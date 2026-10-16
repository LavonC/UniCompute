package tests

import (
	"context"
	"math"
	"testing"
	"time"

	"unicompute/pkg/protocol"
	"unicompute/pkg/scheduler"
)

func TestPACManConvexLocalityScoring(t *testing.T) {
	idx := scheduler.NewContentLocalityIndex()
	pac := scheduler.NewPACManScheduler(idx)

	datasetCID := "bafybeih5a6q37_genome"
	totalBytes := int64(40 * 1024 * 1024 * 1024) // 40 GiB

	// Node 1: Memory-Warm Tier R (100% in RAM)
	nodeRAM := &protocol.Node{
		ID:             "node-ram",
		Online:         true,
		MaxTier:        protocol.Tier1Wasm,
		CreditScore:    0.95,
		TotalRAMMB:     32768,
		AllocatedRAMMB: 8192,
	}
	idx.RegisterDatasetCache(datasetCID, "node-ram", scheduler.LocalityTierR, totalBytes, totalBytes)

	// Node 2: Local NVMe Tier L (100% on SSD)
	nodeNVMe := &protocol.Node{
		ID:             "node-nvme",
		Online:         true,
		MaxTier:        protocol.Tier1Wasm,
		CreditScore:    0.95,
		TotalRAMMB:     16384,
		AllocatedRAMMB: 4096,
	}
	idx.RegisterDatasetCache(datasetCID, "node-nvme", scheduler.LocalityTierL, totalBytes, totalBytes)

	// Node 3: Partial Cache (50% cached on SSD)
	nodePartial := &protocol.Node{
		ID:             "node-partial",
		Online:         true,
		MaxTier:        protocol.Tier1Wasm,
		CreditScore:    0.95,
		TotalRAMMB:     16384,
		AllocatedRAMMB: 4096,
	}
	idx.RegisterDatasetCache(datasetCID, "node-partial", scheduler.LocalityTierL, totalBytes/2, totalBytes)

	// Node 4: Cold WAN (0% cached)
	nodeCold := &protocol.Node{
		ID:             "node-cold",
		Online:         true,
		MaxTier:        protocol.Tier1Wasm,
		CreditScore:    0.95,
		TotalRAMMB:     16384,
		AllocatedRAMMB: 4096,
	}

	task := &protocol.TaskCapsule{
		TaskID:           "task-genomic-align",
		MinTier:          protocol.Tier1Wasm,
		RequiredDatasets: []string{datasetCID},
		MaxMemoryMB:      2048,
	}

	// 1. Check PACMan 4th-power convexity on Partial Node: (0.5)^4 = 0.0625
	scorePartial, ok := pac.EvaluateNode(nodePartial, task)
	if !ok {
		t.Fatalf("Partial node was not eligible")
	}
	if math.Abs(scorePartial.ConvexScore-0.0625) > 0.001 {
		t.Errorf("Expected convex score 0.0625 (0.5^4), got %f", scorePartial.ConvexScore)
	}

	// 2. Compare RAM node vs NVMe node: RAM node should win due to Tier R bonus
	scoreRAM, _ := pac.EvaluateNode(nodeRAM, task)
	scoreNVMe, _ := pac.EvaluateNode(nodeNVMe, task)

	if scoreRAM.Score <= scoreNVMe.Score {
		t.Errorf("Tier R RAM node (%f) did not score higher than Tier L NVMe node (%f)", scoreRAM.Score, scoreNVMe.Score)
	}

	// 3. NVMe node (100% cached) must dramatically outscore Partial node (50% cached)
	if scoreNVMe.Score <= scorePartial.Score*5.0 {
		t.Errorf("Convex locality failed to severely penalize 50%% partial cache: NVMe=%f, Partial=%f", scoreNVMe.Score, scorePartial.Score)
	}

	// 4. Cold node should score lowest
	scoreCold, _ := pac.EvaluateNode(nodeCold, task)
	if scoreCold.Score >= scorePartial.Score {
		t.Errorf("Cold node (%f) scored higher than partial node (%f)", scoreCold.Score, scorePartial.Score)
	}
}

func TestSchedulerHardFilters(t *testing.T) {
	idx := scheduler.NewContentLocalityIndex()
	pac := scheduler.NewPACManScheduler(idx)

	task := &protocol.TaskCapsule{
		TaskID:      "task-filter-test",
		MinTier:     protocol.Tier2Container,
		MaxMemoryMB: 4096,
	}

	// 1. Offline node
	nOffline := &protocol.Node{ID: "n1", Online: false, MaxTier: protocol.Tier2Container}
	if _, ok := pac.EvaluateNode(nOffline, task); ok {
		t.Errorf("Offline node was not filtered")
	}

	// 2. Battery node (auto-pause on DC power)
	nBattery := &protocol.Node{ID: "n2", Online: true, OnBattery: true, MaxTier: protocol.Tier2Container}
	if _, ok := pac.EvaluateNode(nBattery, task); ok {
		t.Errorf("Battery-powered node was not filtered")
	}

	// 3. Active gaming user
	nUserActive := &protocol.Node{ID: "n3", Online: true, UserActive: true, MaxTier: protocol.Tier2Container}
	if _, ok := pac.EvaluateNode(nUserActive, task); ok {
		t.Errorf("Node with active user was not filtered")
	}

	// 4. Insufficient Tier (Tier 1 trying to run Tier 2 task)
	nTier1 := &protocol.Node{ID: "n4", Online: true, MaxTier: protocol.Tier1Wasm}
	if _, ok := pac.EvaluateNode(nTier1, task); ok {
		t.Errorf("Node with insufficient tier was not filtered")
	}

	// 5. Insufficient RAM (donor allocated only 2048 MB quota, task needs 4096 MB)
	nLowRAM := &protocol.Node{
		ID:             "n5",
		Online:         true,
		MaxTier:        protocol.Tier2Container,
		TotalRAMMB:     16384,
		AllocatedRAMMB: 2048,
	}
	if _, ok := pac.EvaluateNode(nLowRAM, task); ok {
		t.Errorf("Node with insufficient allocated RAM was not filtered")
	}

	// 5b. Sufficient RAM (donor allocated 8192 MB quota, task needs 4096 MB)
	nSufficientRAM := &protocol.Node{
		ID:             "n5b",
		Online:         true,
		MaxTier:        protocol.Tier2Container,
		TotalRAMMB:     16384,
		AllocatedRAMMB: 8192,
	}
	if _, ok := pac.EvaluateNode(nSufficientRAM, task); !ok {
		t.Errorf("Node with sufficient allocated RAM was unexpectedly filtered")
	}
}

func TestDelaySchedulingImmediateDispatch(t *testing.T) {
	idx := scheduler.NewContentLocalityIndex()
	pac := scheduler.NewPACManScheduler(idx)

	datasetCID := "cid-perfect"
	idx.RegisterDatasetCache(datasetCID, "perfect-node", scheduler.LocalityTierR, 1000, 1000)

	nodePerfect := &protocol.Node{
		ID:             "perfect-node",
		Online:         true,
		MaxTier:        protocol.Tier1Wasm,
		CreditScore:    1.0,
		TotalRAMMB:     16384,
		AllocatedRAMMB: 2048,
	}

	task := &protocol.TaskCapsule{
		TaskID:           "task-immediate",
		MinTier:          protocol.Tier1Wasm,
		RequiredDatasets: []string{datasetCID},
	}

	start := time.Now()
	matched, score, err := pac.ScheduleTask(context.Background(), task, []*protocol.Node{nodePerfect})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("ScheduleTask failed: %v", err)
	}
	if matched.ID != "perfect-node" {
		t.Errorf("Expected perfect-node to be matched, got %s", matched.ID)
	}
	if !score.IsPerfectLocality {
		t.Errorf("Expected IsPerfectLocality=true")
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("Expected immediate dispatch for L=1.0 node (< 100ms), took %v", elapsed)
	}
}
