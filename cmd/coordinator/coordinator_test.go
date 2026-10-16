package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"unicompute/pkg/crypto"
	"unicompute/pkg/protocol"
	"unicompute/pkg/web"
)

func TestCoordinatorTaskSubmissionAuthentication(t *testing.T) {
	coord, err := NewCoordinatorServer()
	if err != nil {
		t.Fatalf("Failed to initialize coordinator: %v", err)
	}

	researcherKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate researcher keypair: %v", err)
	}

	// 1. Unauthenticated task submission (missing signature & pubkey) MUST FAIL with 401
	unsignedTask := protocol.TaskCapsule{
		TaskID:      "task-unsigned-01",
		Name:        "Unsigned Task",
		MinTier:     protocol.Tier1Wasm,
		Entrypoint:  "main.wasm",
		CodePayload: []byte("sample payload"),
	}
	bodyUnsigned, _ := json.Marshal(unsignedTask)
	reqUnsigned := httptest.NewRequest(http.MethodPost, "/api/tasks/submit", bytes.NewReader(bodyUnsigned))
	recUnsigned := httptest.NewRecorder()
	coord.handleTaskSubmit(recUnsigned, reqUnsigned)

	if recUnsigned.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized for unsigned task, got %d: %s", recUnsigned.Code, recUnsigned.Body.String())
	}

	// 2. Task with invalid/forged signature MUST FAIL with 401
	forgedTask := unsignedTask
	forgedTask.TaskID = "task-forged-02"
	forgedTask.ResearcherPubKey = researcherKP.PublicKeyHex()
	forgedTask.Signature = "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
	bodyForged, _ := json.Marshal(forgedTask)
	reqForged := httptest.NewRequest(http.MethodPost, "/api/tasks/submit", bytes.NewReader(bodyForged))
	recForged := httptest.NewRecorder()
	coord.handleTaskSubmit(recForged, reqForged)

	if recForged.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized for forged signature, got %d: %s", recForged.Code, recForged.Body.String())
	}

	// 3. Authenticated task with valid Ed25519 signature MUST SUCCEED (200 or 202)
	validTask := unsignedTask
	validTask.TaskID = "task-valid-03"
	validTask.ResearcherPubKey = researcherKP.PublicKeyHex()
	manifest := protocol.Manifest{
		TaskID:           validTask.TaskID,
		Name:             validTask.Name,
		MinTier:          validTask.MinTier,
		Entrypoint:       validTask.Entrypoint,
		RequiredDatasets: validTask.RequiredDatasets,
		FuelLimit:        validTask.FuelLimit,
		MaxMemoryMB:      validTask.MaxMemoryMB,
		Args:             validTask.Args,
		Env:              validTask.Env,
		ResearcherPubKey: validTask.ResearcherPubKey,
	}
	digest, _ := manifest.CanonicalDigest()
	validTask.Signature = researcherKP.SignHex(digest)

	bodyValid, _ := json.Marshal(validTask)
	reqValid := httptest.NewRequest(http.MethodPost, "/api/tasks/submit", bytes.NewReader(bodyValid))
	recValid := httptest.NewRecorder()
	coord.handleTaskSubmit(recValid, reqValid)

	// Since no nodes are registered yet, it should return 202 Accepted (scheduled/queued)
	if recValid.Code != http.StatusAccepted && recValid.Code != http.StatusOK {
		t.Errorf("Expected 200 or 202 for valid task, got %d: %s", recValid.Code, recValid.Body.String())
	}
}

func TestCoordinatorReceiptWorkerIdentityValidation(t *testing.T) {
	coord, err := NewCoordinatorServer()
	if err != nil {
		t.Fatalf("Failed to initialize coordinator: %v", err)
	}

	workerKP, _ := crypto.GenerateKeyPair()
	registeredNode := &protocol.Node{
		ID:             "node-worker-legit",
		Online:         true,
		PublicKey:      workerKP.PublicKeyHex(),
		AllocatedRAMMB: 8192,
		MaxTier:        protocol.Tier1Wasm,
	}
	coord.onNodeRegister(registeredNode)

	// Create and schedule a task manually assigned to node-worker-legit
	taskID := "task-assigned-10"
	task := &protocol.TaskCapsule{
		TaskID:  taskID,
		MinTier: protocol.Tier1Wasm,
	}
	coord.mu.Lock()
	coord.tasks[taskID] = task
	coord.taskAssignments[taskID] = "node-worker-legit"
	coord.taskStatuses[taskID] = protocol.TaskStatusRunning
	coord.mu.Unlock()

	// 1. Unknown task ID must fail (400)
	fakeReceipt := protocol.ExecutionReceipt{
		TaskID:       "task-nonexistent",
		NodeID:       "node-worker-legit",
		WorkerPubKey: workerKP.PublicKeyHex(),
	}
	bFake, _ := json.Marshal(fakeReceipt)
	rFake := httptest.NewRequest(http.MethodPost, "/api/receipts/verify", bytes.NewReader(bFake))
	wFake := httptest.NewRecorder()
	coord.handleReceiptVerify(wFake, rFake)
	if wFake.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for unknown task, got %d: %s", wFake.Code, wFake.Body.String())
	}

	// 2. Unregistered worker node must fail (401)
	unregReceipt := protocol.ExecutionReceipt{
		TaskID:       taskID,
		NodeID:       "node-unregistered-intruder",
		WorkerPubKey: workerKP.PublicKeyHex(),
	}
	bUnreg, _ := json.Marshal(unregReceipt)
	rUnreg := httptest.NewRequest(http.MethodPost, "/api/receipts/verify", bytes.NewReader(bUnreg))
	wUnreg := httptest.NewRecorder()
	coord.handleReceiptVerify(wUnreg, rUnreg)
	if wUnreg.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for unregistered node, got %d: %s", wUnreg.Code, wUnreg.Body.String())
	}

	// 3. Worker trying to claim a task assigned to someone else must fail (403 Forbidden)
	otherWorkerKP, _ := crypto.GenerateKeyPair()
	otherNode := &protocol.Node{
		ID:        "node-worker-bystander",
		Online:    true,
		PublicKey: otherWorkerKP.PublicKeyHex(),
	}
	coord.onNodeRegister(otherNode)

	bystanderReceipt := protocol.ExecutionReceipt{
		TaskID:       taskID,
		NodeID:       "node-worker-bystander",
		WorkerPubKey: otherWorkerKP.PublicKeyHex(),
	}
	bBystander, _ := json.Marshal(bystanderReceipt)
	rBystander := httptest.NewRequest(http.MethodPost, "/api/receipts/verify", bytes.NewReader(bBystander))
	wBystander := httptest.NewRecorder()
	coord.handleReceiptVerify(wBystander, rBystander)
	if wBystander.Code != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for unassigned node, got %d: %s", wBystander.Code, wBystander.Body.String())
	}

	// 4. Worker claiming legitimate NodeID but signing with wrong public key must fail (401 Unauthorized)
	spoofedKeyReceipt := protocol.ExecutionReceipt{
		TaskID:       taskID,
		NodeID:       "node-worker-legit",
		WorkerPubKey: otherWorkerKP.PublicKeyHex(), // Mismatched key!
	}
	bSpoofed, _ := json.Marshal(spoofedKeyReceipt)
	rSpoofed := httptest.NewRequest(http.MethodPost, "/api/receipts/verify", bytes.NewReader(bSpoofed))
	wSpoofed := httptest.NewRecorder()
	coord.handleReceiptVerify(wSpoofed, rSpoofed)
	if wSpoofed.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized for mismatched worker key, got %d: %s", wSpoofed.Code, wSpoofed.Body.String())
	}

	// 5. Valid assigned worker with valid signature MUST SUCCEED (200 OK)
	validReceipt := protocol.ExecutionReceipt{
		TaskID:              taskID,
		NodeID:              "node-worker-legit",
		InputCID:            "[]",
		OutputCID:           "valid_output_cid_1234",
		FuelConsumed:        50000,
		ExitCode:            0,
		ExecutionDurationMs: 120,
		Timestamp:           time.Now().Unix(),
		WorkerPubKey:        workerKP.PublicKeyHex(),
	}
	digest, _ := validReceipt.CanonicalReceiptHash()
	validReceipt.Signature = workerKP.SignHex(digest)

	bValid, _ := json.Marshal(validReceipt)
	rValid := httptest.NewRequest(http.MethodPost, "/api/receipts/verify", bytes.NewReader(bValid))
	wValid := httptest.NewRecorder()
	coord.handleReceiptVerify(wValid, rValid)

	if wValid.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for valid assigned receipt, got %d: %s", wValid.Code, wValid.Body.String())
	}
}

func TestCoordinatorStorageShardsAPI(t *testing.T) {
	coord, err := NewCoordinatorServer()
	if err != nil {
		t.Fatalf("Failed to initialize coordinator: %v", err)
	}

	// 1. Initial state with no registered datasets returns clean empty state
	req := httptest.NewRequest(http.MethodGet, "/api/storage/shards", nil)
	w := httptest.NewRecorder()
	coord.handleStorageShards(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from /api/storage/shards, got %d", w.Code)
	}

	var resp struct {
		SegmentID    string                   `json:"segment_id"`
		TotalShards  int                      `json:"total_shards"`
		DataShards   int                      `json:"data_shards"`
		ParityShards int                      `json:"parity_shards"`
		OnlineShards int                      `json:"online_shards"`
		Shards       []protocol.ShardMetadata `json:"shards"`
		Status       string                   `json:"status"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode shards response: %v", err)
	}
	if resp.TotalShards != 0 || len(resp.Shards) != 0 {
		t.Errorf("Expected 0 shards for empty cluster, got %d (list len: %d)", resp.TotalShards, len(resp.Shards))
	}
	if resp.Status != "NO_DATASETS_REGISTERED" {
		t.Errorf("Expected status NO_DATASETS_REGISTERED, got %s", resp.Status)
	}

	// 2. Register actual dataset manifest
	shards := make([]protocol.ShardMetadata, 80)
	for i := 0; i < 80; i++ {
		shards[i] = protocol.ShardMetadata{
			ShardID:    "shard-registered-" + string(rune('a'+i%26)),
			SegmentID:  "seg_test_real",
			ShardIndex: i,
			IsParity:   i >= 32,
			NodeID:     "node-holder",
			Online:     i < 70, // 70 online, 10 offline
		}
	}

	manifest := protocol.DatasetManifest{
		DatasetCID: "dataset-cid-real",
		Name:       "Test Ingested Dataset",
		Segments: []protocol.SegmentMetadata{
			{
				SegmentID:    "seg_test_real",
				DatasetCID:   "dataset-cid-real",
				SegmentIndex: 0,
				Shards:       shards,
			},
		},
	}

	bMan, _ := json.Marshal(manifest)
	rMan := httptest.NewRequest(http.MethodPost, "/api/storage/manifest", bytes.NewReader(bMan))
	wMan := httptest.NewRecorder()
	coord.handleDatasetManifest(wMan, rMan)

	if wMan.Code != http.StatusOK {
		t.Fatalf("Failed to register manifest: %v", wMan.Body.String())
	}

	// 3. Query /api/storage/shards?segment_id=seg_test_real
	reqReal := httptest.NewRequest(http.MethodGet, "/api/storage/shards?segment_id=seg_test_real", nil)
	wReal := httptest.NewRecorder()
	coord.handleStorageShards(wReal, reqReal)

	if wReal.Code != http.StatusOK {
		t.Fatalf("Expected 200 for real segment query, got %d", wReal.Code)
	}

	var respReal struct {
		SegmentID    string                   `json:"segment_id"`
		OnlineShards int                      `json:"online_shards"`
		Shards       []protocol.ShardMetadata `json:"shards"`
	}
	_ = json.NewDecoder(wReal.Body).Decode(&respReal)
	if respReal.SegmentID != "seg_test_real" {
		t.Errorf("Expected seg_test_real, got %s", respReal.SegmentID)
	}
	if respReal.OnlineShards != 70 {
		t.Errorf("Expected 70 online shards, got %d", respReal.OnlineShards)
	}

	// 4. Verify ContentLocalityIndex registered dataset mappings properly (Issue 1)
	tier, cached, total := coord.localityIndex.GetLocality("dataset-cid-real", "node-holder")
	if cached <= 0 {
		t.Errorf("Locality index did not register dataset-to-shard mapping, cached: %d", cached)
	}
	if tier != "Tier_L" {
		t.Errorf("Expected Tier_L for shard holders, got %s", tier)
	}
	if total <= 0 {
		t.Errorf("Expected positive total bytes, got %d", total)
	}
}

func TestCoordinatorClusterStatusAPI(t *testing.T) {
	coord, err := NewCoordinatorServer()
	if err != nil {
		t.Fatalf("Failed to initialize coordinator: %v", err)
	}

	// 1. Initial idle state
	req := httptest.NewRequest(http.MethodGet, "/api/cluster/status", nil)
	w := httptest.NewRecorder()
	coord.handleClusterStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from /api/cluster/status, got %d", w.Code)
	}

	var resp web.ClusterStatusResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode cluster status response: %v", err)
	}

	if resp.NodesOnline != 0 {
		t.Errorf("Expected 0 nodes online, got %d", resp.NodesOnline)
	}
	if resp.TasksRunning != 0 {
		t.Errorf("Expected 0 tasks running, got %d", resp.TasksRunning)
	}
	if resp.ActiveJobTitle != "No active jobs submitted" {
		t.Errorf("Expected 'No active jobs submitted', got '%s'", resp.ActiveJobTitle)
	}
	if len(resp.JobStages) != 0 {
		t.Errorf("Expected 0 job stages in idle state, got %d", len(resp.JobStages))
	}
	if resp.ActiveJob != nil {
		t.Errorf("Expected ActiveJob to be nil in idle state, got %+v", resp.ActiveJob)
	}
	if len(resp.Fleet) != 0 {
		t.Errorf("Expected empty fleet in idle state, got %d nodes", len(resp.Fleet))
	}

	// 2. Register a node and submit a task, verify dynamic status
	nodeKP, _ := crypto.GenerateKeyPair()
	testNode := &protocol.Node{
		ID:             "node-status-01",
		SubnetZone:     protocol.ZoneCampusLab,
		Online:         true,
		PublicKey:      nodeKP.PublicKeyHex(),
		AllocatedCores: 8,
		AllocatedRAMMB: 16384,
		MaxTier:        protocol.Tier1Wasm,
	}
	coord.onNodeRegister(testNode)

	coord.mu.Lock()
	coord.tasks["task-job-1"] = &protocol.TaskCapsule{
		TaskID:  "task-job-1",
		Name:    "Genomics Test",
		MinTier: protocol.Tier1Wasm,
	}
	coord.taskStatuses["task-job-1"] = protocol.TaskStatusRunning
	coord.taskAssignments["task-job-1"] = "node-status-01"
	coord.mu.Unlock()

	req2 := httptest.NewRequest(http.MethodGet, "/api/cluster/status", nil)
	w2 := httptest.NewRecorder()
	coord.handleClusterStatus(w2, req2)

	var resp2 web.ClusterStatusResponse
	_ = json.NewDecoder(w2.Body).Decode(&resp2)

	if resp2.NodesOnline != 1 || resp2.LabNodes != 1 {
		t.Errorf("Expected 1 lab node online, got %d (lab: %d)", resp2.NodesOnline, resp2.LabNodes)
	}
	if resp2.TasksRunning != 1 {
		t.Errorf("Expected 1 running task, got %d", resp2.TasksRunning)
	}
	if len(resp2.JobStages) != 4 {
		t.Errorf("Expected 4 DAG stages, got %d", len(resp2.JobStages))
	}
	if resp2.ActiveJob == nil || resp2.ActiveJob.Status != string(protocol.TaskStatusRunning) {
		t.Errorf("Expected active running job, got %+v", resp2.ActiveJob)
	}
	if len(resp2.Fleet) != 1 || resp2.Fleet[0].ID != "node-status-01" {
		t.Errorf("Expected node-status-01 in fleet, got %+v", resp2.Fleet)
	}
}

