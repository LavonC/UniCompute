package storage

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"unicompute/pkg/protocol"
)

const (
	LazyRepairThreshold = 48 // M_repair = 48 shards
	ReconstructionFloor = 32 // k = 32 shards
	AnchorPinningTarget = 20 // At least 20 shards pinned to Campus Lab nodes
)

// RepairEngine coordinates lazy batched repair and shard placement rules.
type RepairEngine struct {
	mu          sync.RWMutex
	codec       *ErasureCodec
	activeJobs  map[string]*RepairJob
	onRepairComplete func(segmentID string, newShards []protocol.ShardMetadata)
}

// RepairJob represents an in-flight segment reconstruction.
type RepairJob struct {
	SegmentID    string
	StartedAt    time.Time
	TriggerCount int
	Status       string
}

// NewRepairEngine creates a new repair engine with the given erasure codec.
func NewRepairEngine(codec *ErasureCodec) *RepairEngine {
	return &RepairEngine{
		codec:      codec,
		activeJobs: make(map[string]*RepairJob),
	}
}

// CheckSegmentHealth evaluates whether a segment requires lazy batched repair.
// Returns shouldRepair=true if onlineShards <= LazyRepairThreshold (48) but >= ReconstructionFloor (32).
func (re *RepairEngine) CheckSegmentHealth(seg *protocol.SegmentMetadata) (shouldRepair bool, reason string) {
	if seg == nil {
		return false, "FATAL: Segment metadata is nil"
	}
	re.mu.RLock()
	defer re.mu.RUnlock()

	onlineCount := 0
	for _, s := range seg.Shards {
		if s.Online {
			onlineCount++
		}
	}
	seg.OnlineShards = onlineCount

	if onlineCount < ReconstructionFloor {
		return false, fmt.Sprintf("FATAL: Segment %s is below reconstruction floor (%d < %d)", seg.SegmentID, onlineCount, ReconstructionFloor)
	}

	if onlineCount <= LazyRepairThreshold {
		return true, fmt.Sprintf("TRIGGER: Shards dropped to %d <= %d threshold (16-shard safety buffer)", onlineCount, LazyRepairThreshold)
	}

	return false, fmt.Sprintf("HEALTHY: %d shards online (> %d threshold)", onlineCount, LazyRepairThreshold)
}

// PlanShardPlacement applies Subnet Anti-Affinity and Campus Lab Anchor Pinning to assign 80 shards to nodes (§9.1).
func PlanShardPlacement(nodes []*protocol.Node, segmentID string) ([]protocol.ShardMetadata, error) {
	if len(nodes) == 0 {
		return nil, errors.New("no nodes available for placement")
	}

	totalShards := 80
	dataShards := 32
	shards := make([]protocol.ShardMetadata, totalShards)

	// Partition online nodes by SubnetZone for Subnet Anti-Affinity
	var labNodes []*protocol.Node
	var dormNodes []*protocol.Node
	var resNodes []*protocol.Node
	var otherNodes []*protocol.Node

	for _, n := range nodes {
		if !n.Online {
			continue
		}
		switch n.SubnetZone {
		case protocol.ZoneCampusLab:
			labNodes = append(labNodes, n)
		case protocol.ZoneDormWiFi:
			dormNodes = append(dormNodes, n)
		case protocol.ZoneResidential:
			resNodes = append(resNodes, n)
		default:
			otherNodes = append(otherNodes, n)
		}
	}

	allEligible := append(append(append(labNodes, dormNodes...), resNodes...), otherNodes...)
	if len(allEligible) == 0 {
		return nil, errors.New("no online nodes available for placement")
	}

	// Build zone-interleaved anti-affinity candidate sequence for non-anchor shards
	var nonAnchorPool []*protocol.Node
	var pools [][]*protocol.Node
	if len(dormNodes) > 0 {
		pools = append(pools, dormNodes)
	}
	if len(resNodes) > 0 {
		pools = append(pools, resNodes)
	}
	if len(labNodes) > 0 {
		pools = append(pools, labNodes)
	}
	if len(otherNodes) > 0 {
		pools = append(pools, otherNodes)
	}

	if len(pools) > 0 {
		maxLen := 0
		for _, p := range pools {
			if len(p) > maxLen {
				maxLen = len(p)
			}
		}
		for round := 0; round < maxLen; round++ {
			for _, p := range pools {
				if round < len(p) {
					nonAnchorPool = append(nonAnchorPool, p[round])
				}
			}
		}
	}
	if len(nonAnchorPool) == 0 {
		nonAnchorPool = allEligible
	}

	// 1. Assign Anchor Shards: at least AnchorPinningTarget (20) to lab nodes if available
	anchorCount := 0
	nonAnchorIdx := 0

	for i := 0; i < totalShards; i++ {
		isParity := i >= dataShards
		shardID := fmt.Sprintf("%s-shard-%02d", segmentID, i)

		var assignedNode *protocol.Node
		isAnchor := false

		if len(labNodes) > 0 && anchorCount < AnchorPinningTarget {
			assignedNode = labNodes[anchorCount%len(labNodes)]
			isAnchor = true
			anchorCount++
		} else {
			// Round robin across zone-interleaved anti-affinity pool
			assignedNode = nonAnchorPool[nonAnchorIdx%len(nonAnchorPool)]
			nonAnchorIdx++
		}

		shards[i] = protocol.ShardMetadata{
			ShardID:     shardID,
			SegmentID:   segmentID,
			ShardIndex:  i,
			IsParity:    isParity,
			SizeBytes:   2 * 1024 * 1024,
			NodeID:      assignedNode.ID,
			SubnetZone:  assignedNode.SubnetZone,
			IsAnchor:    isAnchor,
			Online:      true,
			LastAudited: time.Now(),
		}
	}

	return shards, nil
}

// ExecuteBatchedRepair performs single-pass reconstruction of all missing shards.
// Given 32+ surviving shards, it regenerates all 80 shards and returns the regenerated shards.
func (re *RepairEngine) ExecuteBatchedRepair(survivingShards map[int][]byte, originalSize int64) (allShards [][]byte, err error) {
	if len(survivingShards) < re.codec.dataShards {
		return nil, fmt.Errorf("insufficient surviving shards: got %d, need %d", len(survivingShards), re.codec.dataShards)
	}

	// Prepare matrix for reedsolomon reconstruction
	matrix := make([][]byte, re.codec.totalShards)
	var shardLen int
	validCount := 0

	for idx, data := range survivingShards {
		if idx >= 0 && idx < re.codec.totalShards && len(data) > 0 {
			if shardLen > 0 && len(data) != shardLen {
				return nil, fmt.Errorf("inconsistent shard size: shard %d has size %d, expected %d", idx, len(data), shardLen)
			}
			matrix[idx] = make([]byte, len(data))
			copy(matrix[idx], data)
			shardLen = len(data)
			validCount++
		}
	}

	if shardLen == 0 || validCount == 0 {
		return nil, errors.New("surviving shards contain no data")
	}

	if validCount < re.codec.dataShards {
		return nil, fmt.Errorf("insufficient valid surviving shards: got %d, need %d", validCount, re.codec.dataShards)
	}

	// Reconstruct all missing shards
	if err := re.codec.ReconstructMissingShards(matrix); err != nil {
		return nil, fmt.Errorf("failed to reconstruct missing shards: %w", err)
	}

	return matrix, nil
}
