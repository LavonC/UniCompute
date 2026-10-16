package scheduler

import (
	"context"
	"errors"
	"math"
	"sort"
	"time"

	"unicompute/pkg/protocol"
)

var (
	ErrNoEligibleNodes = errors.New("no eligible worker nodes match task capability and resource constraints")
)

// Weights for PACMan convex scoring function (§8.3)
const (
	WeightLocality   = 0.70 // w_loc
	WeightTierRAM    = 0.20 // w_tier (bonus for Tier R memory-warm)
	WeightReliability = 0.10 // w_rel (BitTorrent credit score weight)

	DefaultDelayScheduleTimeout = 3000 * time.Millisecond // Δt = 3.0s
)

// CandidateScore ranks candidate worker nodes for a given task.
type CandidateScore struct {
	NodeID          string
	Score           float64
	CachedRatio     float64
	ConvexScore     float64
	Tier            LocalityTier
	CreditScore     float64
	IsPerfectLocality bool // L == 1.0
}

// PACManScheduler implements PACMan convex locality scheduling paired with Delay Scheduling.
type PACManScheduler struct {
	index               *ContentLocalityIndex
	delayTimeout        time.Duration
	weightLoc           float64
	weightTier          float64
	weightRel           float64
}

// NewPACManScheduler creates a PACMan scheduler instance.
func NewPACManScheduler(index *ContentLocalityIndex) *PACManScheduler {
	return &PACManScheduler{
		index:        index,
		delayTimeout: DefaultDelayScheduleTimeout,
		weightLoc:    WeightLocality,
		weightTier:   WeightTierRAM,
		weightRel:    WeightReliability,
	}
}

// EvaluateNode computes the convex locality score for a specific node and task:
// Score = w_loc * (C_cached / C_total)^4 + w_tier * I(Tier_R) + w_rel * R_credit(node)
func (s *PACManScheduler) EvaluateNode(node *protocol.Node, task *protocol.TaskCapsule) (CandidateScore, bool) {
	// 1. Hard capability & availability filters (§6, §10.1)
	if !node.Online {
		return CandidateScore{}, false
	}
	if node.OnBattery {
		return CandidateScore{}, false // Automated battery guard auto-pauses on DC power
	}
	if node.UserActive {
		return CandidateScore{}, false // Pause on active user/gaming input
	}
	if node.MaxTier < task.MinTier {
		return CandidateScore{}, false // Node does not satisfy required execution tier
	}
	if task.MaxMemoryMB > 0 {
		if node.AllocatedRAMMB < task.MaxMemoryMB {
			return CandidateScore{}, false // Insufficient allocated RAM quota
		}
	}

	// 2. Query Locality from Index
	var totalRequiredBytes int64 = 0
	var totalCachedBytes int64 = 0
	hasTierR := false

	if len(task.RequiredDatasets) == 0 {
		// Pure compute task with no large dataset inputs: ratio = 1.0
		totalRequiredBytes = 1
		totalCachedBytes = 1
	} else {
		for _, cid := range task.RequiredDatasets {
			tier, cached, total := s.index.GetLocality(cid, node.ID)
			if total == 0 {
				total = 100 * 1024 * 1024 // fallback estimate
			}
			totalRequiredBytes += total
			totalCachedBytes += cached
			if tier == LocalityTierR {
				hasTierR = true
			}
		}
	}

	ratio := float64(totalCachedBytes) / float64(totalRequiredBytes)
	if ratio > 1.0 {
		ratio = 1.0
	}

	// PACMan Convex Locality: ratio^4 severely penalizes partial cache matches
	convexLocality := math.Pow(ratio, 4.0)

	var tierBonus float64 = 0.0
	tierName := LocalityCold
	if hasTierR {
		tierBonus = 1.0
		tierName = LocalityTierR
	} else if ratio > 0 {
		tierName = LocalityTierL
	}

	credit := node.CreditScore
	if credit <= 0 {
		credit = 0.5 // Default initial reputation
	}

	finalScore := (s.weightLoc * convexLocality) + (s.weightTier * tierBonus) + (s.weightRel * credit)

	return CandidateScore{
		NodeID:            node.ID,
		Score:             finalScore,
		CachedRatio:       ratio,
		ConvexScore:       convexLocality,
		Tier:              tierName,
		CreditScore:       credit,
		IsPerfectLocality: ratio >= 0.999,
	}, true
}

// ScheduleTask dispatches a task using PACMan scoring and Delay Scheduling (§8.3).
// If a candidate with L = 1.0 exists, dispatches immediately.
// Otherwise, waits up to delayTimeout for an L = 1.0 node before dispatching to best available.
func (s *PACManScheduler) ScheduleTask(ctx context.Context, task *protocol.TaskCapsule, nodes []*protocol.Node) (*protocol.Node, *CandidateScore, error) {
	nodeMap := make(map[string]*protocol.Node)
	for _, n := range nodes {
		nodeMap[n.ID] = n
	}

	scoreCandidates := func() []CandidateScore {
		var candidates []CandidateScore
		for _, n := range nodes {
			if score, eligible := s.EvaluateNode(n, task); eligible {
				candidates = append(candidates, score)
			}
		}
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].Score > candidates[j].Score
		})
		return candidates
	}

	candidates := scoreCandidates()
	if len(candidates) == 0 {
		return nil, nil, ErrNoEligibleNodes
	}

	// Fast path: if top candidate has perfect locality (L == 1.0), dispatch immediately!
	if candidates[0].IsPerfectLocality {
		top := candidates[0]
		return nodeMap[top.NodeID], &top, nil
	}

	// Delay Scheduling path (§8.3): Wait up to Δt = 3.0s for a memory-warm (Tier R) or NVMe-resident (Tier L) node
	// before falling back to partial network staging.
	timer := time.NewTimer(s.delayTimeout)
	defer timer.Stop()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-timer.C:
			// Delay expired: re-evaluate candidates to avoid selecting a node that went offline during delay
			candidates = scoreCandidates()
			if len(candidates) == 0 {
				return nil, nil, ErrNoEligibleNodes
			}
			top := candidates[0]
			return nodeMap[top.NodeID], &top, nil
		case <-ticker.C:
			candidates = scoreCandidates()
			if len(candidates) > 0 && candidates[0].IsPerfectLocality {
				top := candidates[0]
				return nodeMap[top.NodeID], &top, nil
			}
		}
	}
}
