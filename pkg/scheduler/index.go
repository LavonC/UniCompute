package scheduler

import (
	"sync"
	"time"
)

// LocalityTier indicates where the requested dataset is cached on the node.
type LocalityTier string

const (
	LocalityTierR LocalityTier = "Tier_R" // RAM cache (< 0.4s)
	LocalityTierL LocalityTier = "Tier_L" // Local NVMe/SSD cache (13.6s)
	LocalityCold  LocalityTier = "Cold"   // Not present locally (WAN fetch)
)

// LocalityRecord stores node cache presence.
type LocalityRecord struct {
	NodeID      string
	Tier        LocalityTier
	CachedBytes int64
	TotalBytes  int64
	LastUpdated time.Time
}

// ContentLocalityIndex maintains the in-memory mapping from Dataset/Segment CID to node holding locations.
type ContentLocalityIndex struct {
	mu              sync.RWMutex
	datasetNodes    map[string]map[string]*LocalityRecord // DatasetCID -> NodeID -> Record
	segmentHolders  map[string]map[string]LocalityTier   // SegmentID -> NodeID -> Tier
	shardHolders    map[string]map[string]bool           // ShardID -> NodeID -> true
	datasetSegments map[string][]string                 // DatasetCID -> []SegmentID
	segmentShards   map[string][]string                 // SegmentID -> []ShardID
	segmentDataset  map[string]string                   // SegmentID -> DatasetCID
	shardDataset    map[string]string                   // ShardID -> DatasetCID
}

// NewContentLocalityIndex creates a new in-memory locality registry.
func NewContentLocalityIndex() *ContentLocalityIndex {
	return &ContentLocalityIndex{
		datasetNodes:    make(map[string]map[string]*LocalityRecord),
		segmentHolders:  make(map[string]map[string]LocalityTier),
		shardHolders:    make(map[string]map[string]bool),
		datasetSegments: make(map[string][]string),
		segmentShards:   make(map[string][]string),
		segmentDataset:  make(map[string]string),
		shardDataset:    make(map[string]string),
	}
}

// RegisterDatasetCache records that a node has a complete or partial dataset cached.
func (idx *ContentLocalityIndex) RegisterDatasetCache(datasetCID, nodeID string, tier LocalityTier, cachedBytes, totalBytes int64) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	if _, ok := idx.datasetNodes[datasetCID]; !ok {
		idx.datasetNodes[datasetCID] = make(map[string]*LocalityRecord)
	}
	idx.datasetNodes[datasetCID][nodeID] = &LocalityRecord{
		NodeID:      nodeID,
		Tier:        tier,
		CachedBytes: cachedBytes,
		TotalBytes:  totalBytes,
		LastUpdated: time.Now(),
	}
}

// RegisterDatasetSegment maps a dataset CID to one of its constituent segment IDs.
func (idx *ContentLocalityIndex) RegisterDatasetSegment(datasetCID, segmentID string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.segmentDataset[segmentID] = datasetCID
	// Backfill shardDataset for shards already associated with this segment
	if shards, ok := idx.segmentShards[segmentID]; ok {
		for _, sh := range shards {
			idx.shardDataset[sh] = datasetCID
		}
	}
	for _, s := range idx.datasetSegments[datasetCID] {
		if s == segmentID {
			return
		}
	}
	idx.datasetSegments[datasetCID] = append(idx.datasetSegments[datasetCID], segmentID)
}

// RegisterSegmentShard maps a segment ID to one of its constituent shard IDs.
func (idx *ContentLocalityIndex) RegisterSegmentShard(segmentID, shardID string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	if datasetCID, ok := idx.segmentDataset[segmentID]; ok {
		idx.shardDataset[shardID] = datasetCID
	}
	for _, s := range idx.segmentShards[segmentID] {
		if s == shardID {
			return
		}
	}
	idx.segmentShards[segmentID] = append(idx.segmentShards[segmentID], shardID)
}

// RegisterSegmentCache records that a node holds a complete reconstructed segment.
func (idx *ContentLocalityIndex) RegisterSegmentCache(segmentID, nodeID string, tier LocalityTier) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	if _, ok := idx.segmentHolders[segmentID]; !ok {
		idx.segmentHolders[segmentID] = make(map[string]LocalityTier)
	}
	idx.segmentHolders[segmentID][nodeID] = tier
}

// RegisterShardHolder records that a node stores a specific Cauchy RS shard.
func (idx *ContentLocalityIndex) RegisterShardHolder(shardID, nodeID string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	if _, ok := idx.shardHolders[shardID]; !ok {
		idx.shardHolders[shardID] = make(map[string]bool)
	}
	idx.shardHolders[shardID][nodeID] = true
}

// GetLocality returns how much of a dataset/segment/shard the node has cached and which tier it resides in.
func (idx *ContentLocalityIndex) GetLocality(datasetCID, nodeID string) (tier LocalityTier, cachedBytes, totalBytes int64) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	const defaultSegmentBytes = 64 * 1024 * 1024 // 64 MiB
	const defaultShardBytes = 2 * 1024 * 1024    // 2 MiB

	var knownTotal int64 = 0

	// 1. Direct dataset cache hit
	if nodes, ok := idx.datasetNodes[datasetCID]; ok {
		for _, rec := range nodes {
			if rec.TotalBytes > knownTotal {
				knownTotal = rec.TotalBytes
			}
		}
		if rec, exists := nodes[nodeID]; exists {
			return rec.Tier, rec.CachedBytes, rec.TotalBytes
		}
	}

	// 2. Direct segment cache hit (if query ID matches segmentID)
	if holders, ok := idx.segmentHolders[datasetCID]; ok {
		knownTotal = defaultSegmentBytes
		if t, exists := holders[nodeID]; exists {
			return t, defaultSegmentBytes, defaultSegmentBytes
		}
	}

	// 3. Direct shard cache hit (if query ID matches shardID)
	if holders, ok := idx.shardHolders[datasetCID]; ok {
		knownTotal = defaultShardBytes
		if holders[nodeID] {
			return LocalityTierL, defaultShardBytes, defaultShardBytes
		}
	}

	// 4. Direct segment query with shard holders (query ID is segmentID)
	if shards, ok := idx.segmentShards[datasetCID]; ok && len(shards) > 0 {
		knownTotal = defaultSegmentBytes
		var cachedShards int64 = 0
		for _, shID := range shards {
			if holders, found := idx.shardHolders[shID]; found && holders[nodeID] {
				cachedShards += defaultShardBytes
			}
		}
		if cachedShards > defaultSegmentBytes {
			cachedShards = defaultSegmentBytes
		}
		if cachedShards > 0 {
			return LocalityTierL, cachedShards, defaultSegmentBytes
		}
	}

	// 5. Dataset-to-segment mapping resolution
	if segs, ok := idx.datasetSegments[datasetCID]; ok && len(segs) > 0 {
		var total int64 = int64(len(segs)) * defaultSegmentBytes
		var cached int64 = 0
		highestTier := LocalityCold

		for _, segID := range segs {
			if holders, found := idx.segmentHolders[segID]; found {
				if t, holdsSeg := holders[nodeID]; holdsSeg {
					cached += defaultSegmentBytes
					if t == LocalityTierR {
						highestTier = LocalityTierR
					} else if highestTier != LocalityTierR {
						highestTier = LocalityTierL
					}
					continue
				}
			}

			// Partial locality via shards of this segment
			if shards, foundShards := idx.segmentShards[segID]; foundShards {
				var segShardBytes int64 = 0
				for _, shID := range shards {
					if holders, ok := idx.shardHolders[shID]; ok && holders[nodeID] {
						segShardBytes += defaultShardBytes
					}
				}
				if segShardBytes > defaultSegmentBytes {
					segShardBytes = defaultSegmentBytes
				}
				if segShardBytes > 0 {
					cached += segShardBytes
					if highestTier == LocalityCold {
						highestTier = LocalityTierL
					}
				}
			}
		}

		if cached > 0 {
			if cached > total {
				total = cached
			}
			return highestTier, cached, total
		}
		return LocalityCold, 0, total
	}

	if knownTotal > 0 {
		return LocalityCold, 0, knownTotal
	}
	return LocalityCold, 0, 0
}

// RemoveNode clears a node from the index when it disconnects.
func (idx *ContentLocalityIndex) RemoveNode(nodeID string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	for _, nodes := range idx.datasetNodes {
		delete(nodes, nodeID)
	}
	for _, nodes := range idx.segmentHolders {
		delete(nodes, nodeID)
	}
	for _, nodes := range idx.shardHolders {
		delete(nodes, nodeID)
	}
}
