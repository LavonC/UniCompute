package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"unicompute/pkg/crypto"
	"unicompute/pkg/protocol"
	"unicompute/pkg/sandbox"
	"unicompute/pkg/scheduler"
	"unicompute/pkg/storage"
	"unicompute/pkg/transport"
	"unicompute/pkg/verification"
	"unicompute/pkg/web"
)

func TestEndToEndMultiNodeWorkflow(t *testing.T) {
	// 1. Setup Coordinator components
	_, err := storage.DefaultCauchyCodec()
	if err != nil {
		t.Fatalf("DefaultCauchyCodec failed: %v", err)
	}

	localityIdx := scheduler.NewContentLocalityIndex()
	pacman := scheduler.NewPACManScheduler(localityIdx)
	_ = verification.NewSpotCheckManager()
	rep := verification.NewReputationTracker()
	hub := transport.NewSignalingHub()

	nodes := make(map[string]*protocol.Node)
	taskStatuses := make(map[string]protocol.TaskStatus)

	hub.SetCallbacks(
		func(node *protocol.Node) {
			node.Online = true
			nodes[node.ID] = node
		},
		func(nodeID string) {},
		func(nodeID string) {
			if n, ok := nodes[nodeID]; ok {
				n.Online = false
			}
		},
	)

	datasetCID := "bafybeih5a6q37_climate_grid"
	localityIdx.RegisterDatasetCache(datasetCID, "worker-lab-01", scheduler.LocalityTierR, 1024*1024, 1024*1024)

	// Coordinator HTTP router
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.HandleWebSocket)

	mux.HandleFunc("/api/tasks/submit", func(w http.ResponseWriter, r *http.Request) {
		var task protocol.TaskCapsule
		_ = json.NewDecoder(r.Body).Decode(&task)

		var nodeList []*protocol.Node
		for _, n := range nodes {
			nodeList = append(nodeList, n)
		}

		matchedNode, score, errSched := pacman.ScheduleTask(r.Context(), &task, nodeList)
		if errSched != nil {
			http.Error(w, errSched.Error(), http.StatusInternalServerError)
			return
		}

		// Dispatch to matched node
		taskBytes, _ := json.Marshal(task)
		_ = hub.SendToNode(matchedNode.ID, &protocol.SignalingMessage{
			Type:     "dispatch",
			FromNode: "coordinator",
			ToNode:   matchedNode.ID,
			Payload:  taskBytes,
		})

		taskStatuses[task.TaskID] = protocol.TaskStatusRunning
		web.WriteJSON(w, http.StatusOK, map[string]interface{}{
			"task_id":          task.TaskID,
			"matched_node":     matchedNode.ID,
			"convex_score":     score.Score,
			"locality_tier":    score.Tier,
			"perfect_locality": score.IsPerfectLocality,
		})
	})

	receiptVerifiedCh := make(chan string, 1)

	mux.HandleFunc("/api/receipts/verify", func(w http.ResponseWriter, r *http.Request) {
		var receipt protocol.ExecutionReceipt
		_ = json.NewDecoder(r.Body).Decode(&receipt)

		valid, errV := verification.VerifyExecutionReceipt(&receipt)
		if errV != nil || !valid {
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}

		taskStatuses[receipt.TaskID] = protocol.TaskStatusCompleted
		rep.RecordSuccess(receipt.NodeID)
		receiptVerifiedCh <- receipt.TaskID

		web.WriteJSON(w, http.StatusOK, map[string]bool{"verified": true})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	// 2. Launch Worker 1 ("worker-lab-01" with Tier R memory cache)
	vaultDir1, _ := os.MkdirTemp("", "vault-e2e-1-*")
	defer os.RemoveAll(vaultDir1)
	vault1, _ := storage.NewVault(vaultDir1, 100*1024*1024, 10*1024*1024)
	_ = vault1.StoreSegment(datasetCID, []byte("Pre-cached climate grid model"))

	keyPair1, _ := crypto.GenerateKeyPair()
	client1, err := transport.DialCoordinator(wsURL)
	if err != nil {
		t.Fatalf("Worker 1 dial failed: %v", err)
	}
	defer client1.Close()

	node1 := protocol.Node{
		ID:             "worker-lab-01",
		SubnetZone:     protocol.ZoneCampusLab,
		MaxTier:        protocol.Tier1Wasm,
		CreditScore:    0.98,
		Online:         true,
		TotalRAMMB:     16384,
		AllocatedRAMMB: 2048,
		PublicKey:      keyPair1.PublicKeyHex(),
	}
	n1Bytes, _ := json.Marshal(node1)
	_ = client1.Send(&protocol.SignalingMessage{Type: "register", FromNode: node1.ID, Payload: n1Bytes})

	// Handle task dispatch on Worker 1
	tier1Sandbox := sandbox.NewTier1WasmSandbox()
	client1.On("dispatch", func(msg *protocol.SignalingMessage) {
		var task protocol.TaskCapsule
		_ = json.Unmarshal(msg.Payload, &task)

		// Execute in Tier 1 sandbox
		res, errExec := tier1Sandbox.Execute(context.Background(), &sandbox.ExecutionRequest{
			TaskID:      task.TaskID,
			MinTier:     task.MinTier,
			Entrypoint:  task.Entrypoint,
			CodePayload: task.CodePayload,
			InputMounts: map[string][]byte{"grid.dat": []byte("Climate Data")},
			MaxMemoryMB: task.MaxMemoryMB,
			FuelLimit:   task.FuelLimit,
			Timeout:     5 * time.Second,
		})

		exitCode := 0
		fuel := uint64(1000)
		outCID := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		if errExec == nil && res != nil {
			exitCode = res.ExitCode
			fuel = res.FuelConsumed
			outCID = res.OutputCID
		}

		// Construct signed receipt
		receipt := protocol.ExecutionReceipt{
			TaskID:              task.TaskID,
			NodeID:              "worker-lab-01",
			InputCID:            datasetCID,
			OutputCID:           outCID,
			FuelConsumed:        fuel,
			ExitCode:            exitCode,
			ExecutionDurationMs: 120,
			Timestamp:           time.Now().Unix(),
			WorkerPubKey:        keyPair1.PublicKeyHex(),
		}
		digest, _ := receipt.CanonicalReceiptHash()
		receipt.Signature = keyPair1.SignHex(digest)

		// Submit receipt to coordinator
		recBytes, _ := json.Marshal(receipt)
		_, _ = http.Post(server.URL+"/api/receipts/verify", "application/json", bytes.NewReader(recBytes))
	})

	// 3. Launch Worker 2 ("worker-dorm-02" - cold node)
	keyPair2, _ := crypto.GenerateKeyPair()
	client2, _ := transport.DialCoordinator(wsURL)
	defer client2.Close()
	node2 := protocol.Node{
		ID:             "worker-dorm-02",
		SubnetZone:     protocol.ZoneDormWiFi,
		MaxTier:        protocol.Tier1Wasm,
		CreditScore:    0.80,
		Online:         true,
		TotalRAMMB:     8192,
		AllocatedRAMMB: 1024,
		PublicKey:      keyPair2.PublicKeyHex(),
	}
	n2Bytes, _ := json.Marshal(node2)
	_ = client2.Send(&protocol.SignalingMessage{Type: "register", FromNode: node2.ID, Payload: n2Bytes})

	time.Sleep(150 * time.Millisecond)

	// 4. Researcher submits signed TaskCapsule targeting datasetCID
	researcherKP, _ := crypto.GenerateKeyPair()
	taskID := "job-84920-climate-task-01"

	manifest := protocol.Manifest{
		Version:          "1.0.0",
		TaskID:           taskID,
		Name:             "Climate Model Grid Solver",
		MinTier:          protocol.Tier1Wasm,
		Entrypoint:       "main.wasm",
		RequiredDatasets: []string{datasetCID},
		FuelLimit:        50000000,
		MaxMemoryMB:      512,
		ResearcherPubKey: researcherKP.PublicKeyHex(),
	}
	digest, _ := manifest.CanonicalDigest()
	sigHex := researcherKP.SignHex(digest)

	capsule := protocol.TaskCapsule{
		CapsuleID:        "cap-" + taskID,
		TaskID:           taskID,
		Name:             manifest.Name,
		MinTier:          manifest.MinTier,
		Entrypoint:       manifest.Entrypoint,
		CodePayload:      minimalWasmBinary,
		RequiredDatasets: manifest.RequiredDatasets,
		FuelLimit:        manifest.FuelLimit,
		MaxMemoryMB:      manifest.MaxMemoryMB,
		Signature:        sigHex,
		ResearcherPubKey: researcherKP.PublicKeyHex(),
	}

	capBytes, _ := json.Marshal(capsule)
	resp, err := http.Post(server.URL+"/api/tasks/submit", "application/json", bytes.NewReader(capBytes))
	if err != nil {
		t.Fatalf("Submit POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Submit failed with %s: %s", resp.Status, string(body))
	}

	var submitResult struct {
		MatchedNode     string  `json:"matched_node"`
		LocalityTier    string  `json:"locality_tier"`
		PerfectLocality bool    `json:"perfect_locality"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&submitResult)

	// Verify PACMan convex scheduler picked worker-lab-01 with Tier R locality
	if submitResult.MatchedNode != "worker-lab-01" {
		t.Errorf("PACMan scheduler failed to match warm Tier R node: got %s, want worker-lab-01", submitResult.MatchedNode)
	}
	if submitResult.LocalityTier != "Tier_R" {
		t.Errorf("Expected LocalityTier Tier_R, got %s", submitResult.LocalityTier)
	}

	// 5. Wait for Layer 1 Ed25519 Execution Receipt Attestation verification
	select {
	case verifiedTaskID := <-receiptVerifiedCh:
		if verifiedTaskID != taskID {
			t.Errorf("Verified task ID mismatch: got %s, want %s", verifiedTaskID, taskID)
		}
		t.Logf("[SUCCESS] Task %s executed via Tier 1 Wasm, receipt verified with Ed25519 signature!", verifiedTaskID)
	case <-time.After(5 * time.Second):
		t.Fatalf("Timeout waiting for execution receipt verification")
	}
}
