package gui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"unicompute/pkg/crypto"
	"unicompute/pkg/protocol"
	"unicompute/pkg/transport"
	"unicompute/pkg/web"
)

func createTestApp(t *testing.T) (*StudioApp, string) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "unicompute-gui-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	app, err := NewStudioApp(filepath.Join(tempDir, "vault"))
	if err != nil {
		_ = os.RemoveAll(tempDir)
		t.Fatalf("failed to create StudioApp: %v", err)
	}

	return app, tempDir
}

func cleanupTestApp(app *StudioApp, tempDir string) {
	if app != nil {
		app.Close()
	}
	if tempDir != "" {
		_ = os.RemoveAll(tempDir)
	}
}

func TestStudioApp_Initialization(t *testing.T) {
	app, tempDir := createTestApp(t)
	defer cleanupTestApp(app, tempDir)

	stats, err := app.GetSystemStats()
	if err != nil {
		t.Fatalf("GetSystemStats failed: %v", err)
	}

	if stats.NodeID == "" {
		t.Errorf("expected non-empty NodeID")
	}
	if stats.AllocatedCores <= 0 {
		t.Errorf("expected AllocatedCores > 0, got %d", stats.AllocatedCores)
	}
	if stats.AllocatedRAMMB <= 0 {
		t.Errorf("expected AllocatedRAMMB > 0, got %d", stats.AllocatedRAMMB)
	}
	if stats.Paused {
		t.Errorf("expected app to start unpaused")
	}

	dag, err := app.GetDAGStatus()
	if err != nil {
		t.Fatalf("GetDAGStatus failed: %v", err)
	}
	if len(dag.Stages) != 4 {
		t.Fatalf("expected 4 DAG stages, got %d", len(dag.Stages))
	}
}

func TestStudioApp_ResourceSliders(t *testing.T) {
	app, tempDir := createTestApp(t)
	defer cleanupTestApp(app, tempDir)

	err := app.UpdateResourceSliders(2, 4096, 200)
	if err != nil {
		t.Fatalf("UpdateResourceSliders failed: %v", err)
	}

	stats, err := app.GetSystemStats()
	if err != nil {
		t.Fatalf("GetSystemStats failed: %v", err)
	}

	if stats.AllocatedCores != 2 {
		t.Errorf("expected 2 cores, got %d", stats.AllocatedCores)
	}
	if stats.AllocatedRAMMB != 4096 {
		t.Errorf("expected 4096 MB RAM, got %d", stats.AllocatedRAMMB)
	}
	if stats.StorageQuotaGB != 200 {
		t.Errorf("expected 200 GB quota, got %d", stats.StorageQuotaGB)
	}
}

func TestStudioApp_PowerAndRules(t *testing.T) {
	app, tempDir := createTestApp(t)
	defer cleanupTestApp(app, tempDir)

	err := app.UpdateRules(false, false, true)
	if err != nil {
		t.Fatalf("UpdateRules failed: %v", err)
	}

	stats, err := app.GetSystemStats()
	if err != nil {
		t.Fatalf("GetSystemStats failed: %v", err)
	}
	if stats.AutoPauseBattery != false || stats.PauseGaming != false || stats.CampusHours != true {
		t.Errorf("rules not updated correctly: %+v", stats)
	}

	// Toggle pause
	paused, err := app.TogglePause()
	if err != nil || !paused {
		t.Errorf("expected paused=true, got %v, err: %v", paused, err)
	}

	stats, _ = app.GetSystemStats()
	if !stats.Paused || stats.PauseReason == "" {
		t.Errorf("expected paused with reason, got: %+v", stats)
	}

	// Toggle resume
	paused, err = app.TogglePause()
	if err != nil || paused {
		t.Errorf("expected paused=false, got %v, err: %v", paused, err)
	}

	// Check power query
	_, _, powerSource, errPower := QuerySystemPower()
	if errPower != nil {
		t.Logf("QuerySystemPower returned note: %v", errPower)
	} else if powerSource == "" {
		t.Errorf("expected non-empty powerSource")
	}
}

func TestStudioApp_IngestFile(t *testing.T) {
	app, tempDir := createTestApp(t)
	defer cleanupTestApp(app, tempDir)

	sampleData := bytes.Repeat([]byte(">Seq1\nATGCGATCGATCGATCGATC\n"), 500) // ~15 KB
	res, err := app.IngestFile("sample.fa", sampleData)
	if err != nil {
		t.Fatalf("IngestFile failed: %v", err)
	}

	if res.DatasetCID == "" {
		t.Errorf("expected non-empty DatasetCID")
	}
	if res.ChunkCount <= 0 {
		t.Errorf("expected at least 1 chunk, got %d", res.ChunkCount)
	}
	if res.TotalShards != 80 {
		t.Errorf("expected 80 RS shards, got %d", res.TotalShards)
	}
	if res.DataShards != 32 {
		t.Errorf("expected 32 data shards, got %d", res.DataShards)
	}
	if res.ParityShards != 48 {
		t.Errorf("expected 48 parity shards, got %d", res.ParityShards)
	}

	// Verify segment status in Vault explorer
	vaultStatus, err := app.GetVaultStatus()
	if err != nil {
		t.Fatalf("GetVaultStatus failed: %v", err)
	}
	if vaultStatus.DatasetCID != res.DatasetCID {
		t.Errorf("expected Vault CID %s, got %s", res.DatasetCID, vaultStatus.DatasetCID)
	}
	if len(vaultStatus.Shards) != 80 {
		t.Errorf("expected 80 shards in vault status, got %d", len(vaultStatus.Shards))
	}
}

func TestStudioApp_SubmitTask_And_DAG(t *testing.T) {
	app, tempDir := createTestApp(t)
	defer cleanupTestApp(app, tempDir)

	// Ingest sample data first
	sampleData := []byte(">Sample_FASTA_Seq\nATGCATGCATGCATGCATGCATGC")
	ingestRes, err := app.IngestFile("genomic_sample.fa", sampleData)
	if err != nil {
		t.Fatalf("IngestFile failed: %v", err)
	}

	// Submit task capsule
	submitReq := TaskSubmitRequest{
		Name:             "Genomic Analysis Pipeline",
		MinTier:          1,
		Entrypoint:       "task.wasm",
		RequiredDatasets: []string{ingestRes.DatasetCID},
		FuelLimit:        500000000,
		MaxMemoryMB:      512,
	}

	subResp, err := app.SubmitTask(submitReq, nil)
	if err != nil {
		t.Fatalf("SubmitTask failed: %v", err)
	}

	if subResp.TaskID == "" || subResp.Signature == "" {
		t.Fatalf("invalid submit response: %+v", subResp)
	}

	// Verify researcher Ed25519 signature
	manifest := protocol.Manifest{
		TaskID:           subResp.TaskID,
		Name:             submitReq.Name,
		MinTier:          protocol.Tier1Wasm,
		Entrypoint:       submitReq.Entrypoint,
		RequiredDatasets: submitReq.RequiredDatasets,
		FuelLimit:        submitReq.FuelLimit,
		MaxMemoryMB:      submitReq.MaxMemoryMB,
		Args:             []string{},
		Env:              map[string]string{"MODE": "production"},
		ResearcherPubKey: subResp.ResearcherPubKey,
	}
	digest, err := manifest.CanonicalDigest()
	if err != nil {
		t.Fatalf("failed to compute manifest digest: %v", err)
	}
	valid, err := crypto.VerifySignatureHex(subResp.ResearcherPubKey, digest, subResp.Signature)
	if err != nil || !valid {
		t.Fatalf("researcher signature verification failed: %v", err)
	}

	// Wait for DAG execution to complete
	var finalDAG DAGPipelineStatus
	for i := 0; i < 60; i++ {
		time.Sleep(100 * time.Millisecond)
		finalDAG, err = app.GetDAGStatus()
		if err == nil && finalDAG.HasOutput && finalDAG.Stages[3].Status == "completed" {
			break
		}
	}

	if !finalDAG.HasOutput {
		t.Fatalf("DAG did not complete in time: %+v", finalDAG)
	}

	// Verify all 4 stages completed
	for i, st := range finalDAG.Stages {
		if st.Status != "completed" {
			t.Errorf("Stage %d (%s) expected completed, got %s", i+1, st.Name, st.Status)
		}
	}

	// Verify output payload retrieval
	out, err := app.GetOutputPayload(subResp.TaskID)
	if err != nil {
		t.Fatalf("GetOutputPayload failed: %v", err)
	}
	if out.OutputText == "" || out.OutputCID == "" {
		t.Errorf("invalid output payload: %+v", out)
	}
	if out.FuelConsumed == 0 {
		t.Errorf("expected FuelConsumed > 0")
	}
	if !bytes.Contains([]byte(out.OutputText), []byte("SUCCESS")) && !bytes.Contains([]byte(out.OutputText), []byte("VERIFIED")) {
		t.Errorf("output payload does not contain verified status: %s", out.OutputText)
	}
}

func TestServer_Endpoints(t *testing.T) {
	app, tempDir := createTestApp(t)
	defer cleanupTestApp(app, tempDir)

	srv, err := StartServer(app, 0) // random free port
	if err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	// 1. GET /
	resp, err := client.Get(srv.URL + "/")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / failed: %v, status: %v", err, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(body, []byte("UniCompute Desktop Studio")) {
		t.Errorf("HTML root missing expected title")
	}

	// 2. GET /api/stats
	resp, err = client.Get(srv.URL + "/api/stats")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/stats failed: %v, status: %v", err, resp.StatusCode)
	}
	var stats SystemStats
	_ = json.NewDecoder(resp.Body).Decode(&stats)
	resp.Body.Close()
	if stats.NodeID == "" {
		t.Errorf("empty NodeID from /api/stats")
	}

	// 3. POST /api/sliders
	sliderReq := map[string]interface{}{
		"cores":      6,
		"ram_mb":     12288,
		"storage_gb": 150,
	}
	sliderBytes, _ := json.Marshal(sliderReq)
	resp, err = client.Post(srv.URL+"/api/sliders", "application/json", bytes.NewReader(sliderBytes))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/sliders failed: %v", err)
	}
	resp.Body.Close()

	// 4. POST /api/pause
	resp, err = client.Post(srv.URL+"/api/pause", "application/json", nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/pause failed: %v", err)
	}
	resp.Body.Close()

	// 5. POST /api/ingest
	testData := []byte(">TestData\nACGTACGTACGTACGT")
	resp, err = client.Post(srv.URL+"/api/ingest?filename=test.fa", "application/octet-stream", bytes.NewReader(testData))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/ingest failed: %v", err)
	}
	var ingestRes IngestResult
	_ = json.NewDecoder(resp.Body).Decode(&ingestRes)
	resp.Body.Close()
	if ingestRes.DatasetCID == "" {
		t.Errorf("expected DatasetCID from /api/ingest")
	}

	// 6. GET /api/vault
	resp, err = client.Get(srv.URL + "/api/vault")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/vault failed: %v", err)
	}
	var vaultStatus VaultMatrixStatus
	_ = json.NewDecoder(resp.Body).Decode(&vaultStatus)
	resp.Body.Close()
	if vaultStatus.TotalShards != 80 {
		t.Errorf("expected 80 total shards, got %d", vaultStatus.TotalShards)
	}

	// 7. POST /api/tray/minimize
	resp, err = client.Post(srv.URL+"/api/tray/minimize", "application/json", nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/tray/minimize failed: %v", err)
	}
	resp.Body.Close()

	// 8. POST /api/tray/restore
	resp, err = client.Post(srv.URL+"/api/tray/restore", "application/json", nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/tray/restore failed: %v", err)
	}
	resp.Body.Close()
}

func TestJobObjectManager(t *testing.T) {
	mgr := NewJobObjectManager(4, 8, 8192)
	defer mgr.Close()

	if err := mgr.ApplyLimits(2, 8, 4096); err != nil {
		t.Errorf("ApplyLimits failed: %v", err)
	}
}

func TestStudioApp_TrayAndPubKeys(t *testing.T) {
	app, tempDir := createTestApp(t)
	defer cleanupTestApp(app, tempDir)

	stats, err := app.GetSystemStats()
	if err != nil {
		t.Fatalf("GetSystemStats failed: %v", err)
	}

	if stats.WorkerPubKey == "" {
		t.Errorf("expected non-empty WorkerPubKey")
	}
	if stats.ResearcherPubKey == "" {
		t.Errorf("expected non-empty ResearcherPubKey")
	}

	// Test MinimizeToTray and RestoreWindow
	app.MinimizeToTray()
	app.RestoreWindow()

	// Test TrayManager directly
	tm := NewTrayManager(0)
	if tm == nil {
		t.Fatalf("expected non-nil TrayManager")
	}
	_ = tm.UpdateTooltip("Test Tooltip")
	_ = tm.ShowBalloon("Title", "Message")
	tm.MinimizeToTray()
	_ = tm.Remove()
}

func TestStudioApp_Tier2_And_Tier3(t *testing.T) {
	app, tempDir := createTestApp(t)
	defer cleanupTestApp(app, tempDir)

	// 1. Test Tier 2 Task Submission
	t2Req := TaskSubmitRequest{
		Name:        "Test Tier 2 Container Task",
		MinTier:     2,
		Entrypoint:  "tier2_task.py",
		FuelLimit:   100000000,
		MaxMemoryMB: 256,
	}
	resp2, err := app.SubmitTask(t2Req, nil)
	if err != nil {
		t.Fatalf("SubmitTask Tier 2 failed: %v", err)
	}
	if resp2.TaskID == "" || resp2.Status != "DISPATCHED" {
		t.Errorf("unexpected Tier 2 submit response: %+v", resp2)
	}

	// Poll for DAG completion
	for i := 0; i < 40; i++ {
		time.Sleep(100 * time.Millisecond)
		dag, err := app.GetDAGStatus()
		if err == nil && dag.ActiveJobID == resp2.TaskID && dag.HasOutput && dag.Stages[3].Status == "completed" {
			break
		}
	}
	dag2, err := app.GetDAGStatus()
	if err != nil {
		t.Fatalf("GetDAGStatus failed: %v", err)
	}
	if dag2.Stages[2].Status != "completed" {
		t.Errorf("expected Stage 3 to complete for Tier 2, got %s", dag2.Stages[2].Status)
	}

	// 2. Test Tier 3 Native Task Submission
	t3Req := TaskSubmitRequest{
		Name:        "Test Tier 3 Native Task",
		MinTier:     3,
		Entrypoint:  "tier3_task.exe",
		FuelLimit:   200000000,
		MaxMemoryMB: 512,
	}
	resp3, err := app.SubmitTask(t3Req, nil)
	if err != nil {
		t.Fatalf("SubmitTask Tier 3 failed: %v", err)
	}
	if resp3.TaskID == "" || resp3.Status != "DISPATCHED" {
		t.Errorf("unexpected Tier 3 submit response: %+v", resp3)
	}

	// Poll for DAG completion
	for i := 0; i < 40; i++ {
		time.Sleep(100 * time.Millisecond)
		dag, err := app.GetDAGStatus()
		if err == nil && dag.ActiveJobID == resp3.TaskID && dag.HasOutput && dag.Stages[3].Status == "completed" {
			break
		}
	}
	dag3, err := app.GetDAGStatus()
	if err != nil {
		t.Fatalf("GetDAGStatus failed: %v", err)
	}
	if dag3.Stages[2].Status != "completed" {
		t.Errorf("expected Stage 3 to complete for Tier 3, got %s", dag3.Stages[2].Status)
	}
}

func TestStudioApp_WorkerOperations(t *testing.T) {
	app, tempDir := createTestApp(t)
	defer cleanupTestApp(app, tempDir)

	// Mock Coordinator WebSocket server
	hub := transport.NewSignalingHub()
	mockCoord := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			hub.HandleWebSocket(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer mockCoord.Close()

	wsURL := "ws" + strings.TrimPrefix(mockCoord.URL, "http") + "/ws"

	cfg := WorkerConnectionConfig{
		CoordinatorURL: wsURL,
		NodeID:         "test-worker-node-1",
		SubnetZone:     "Lab-Alpha",
		AllocatedCores: 4,
		AllocatedRAMMB: 8192,
		StorageQuotaGB: 100,
	}

	// 1. Start worker
	err := app.StartWorker(cfg)
	if err != nil {
		t.Fatalf("StartWorker failed: %v", err)
	}

	// Wait for worker to connect
	var st WorkerConnectionStatus
	for i := 0; i < 50; i++ {
		time.Sleep(50 * time.Millisecond)
		st = app.GetWorkerStatus()
		if st.Connected {
			break
		}
	}

	if !st.Connected {
		t.Fatalf("expected worker to connect, status: %+v", st)
	}
	if st.NodeID != "test-worker-node-1" {
		t.Errorf("expected NodeID test-worker-node-1, got %s", st.NodeID)
	}
	if st.SubnetZone != "Lab-Alpha" {
		t.Errorf("expected SubnetZone Lab-Alpha, got %s", st.SubnetZone)
	}
	sysStats, _ := app.GetSystemStats()
	if sysStats.AllocatedCores != 4 {
		t.Errorf("expected 4 cores, got %d", sysStats.AllocatedCores)
	}

	// 2. Update config
	cfg.AllocatedCores = 8
	cfg.SubnetZone = "Lab-Beta"
	err = app.UpdateWorkerConfig(cfg)
	if err != nil {
		t.Fatalf("UpdateWorkerConfig failed: %v", err)
	}
	st = app.GetWorkerStatus()
	sysStats, _ = app.GetSystemStats()
	if sysStats.AllocatedCores != 8 || st.SubnetZone != "Lab-Beta" {
		t.Errorf("config not updated: status=%+v, stats=%+v", st, sysStats)
	}

	// 3. Reconnect worker
	err = app.ReconnectWorker()
	if err != nil {
		t.Fatalf("ReconnectWorker failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// 4. Receipts
	receipts := app.GetWorkerReceipts()
	if receipts == nil {
		t.Errorf("expected non-nil receipts slice")
	}

	// 5. Stop worker
	err = app.StopWorker()
	if err != nil {
		t.Fatalf("StopWorker failed: %v", err)
	}
	st = app.GetWorkerStatus()
	if st.Connected {
		t.Errorf("expected worker to be disconnected after StopWorker")
	}
}

func TestServer_WorkerAndClusterEndpoints(t *testing.T) {
	app, tempDir := createTestApp(t)
	defer cleanupTestApp(app, tempDir)

	hub := transport.NewSignalingHub()
	mockCoord := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ws":
			hub.HandleWebSocket(w, r)
		case "/api/cluster/status":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(web.ClusterStatusResponse{
				NodesOnline:    3,
				TasksRunning:   1,
				TotalCores:     24,
				TotalRAMMB:     65536,
				LocalityRate:   0.92,
				ActiveJobTitle: "Test Cluster Job",
				Fleet: []web.FleetNodeStatus{
					{ID: "node-1", Zone: "Subnet-A", Tier: 2, Locality: "LAN Hot", Credit: 50.0, Online: true},
					{ID: "node-2", Zone: "Subnet-B", Tier: 3, Locality: "Campus", Credit: 120.0, Online: true},
				},
				Logs: []string{"Cluster operational"},
			})
		case "/api/cluster/fleet":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"fleet": []web.FleetNodeStatus{
					{ID: "node-1", Zone: "Subnet-A", Tier: 2, Locality: "LAN Hot", Credit: 50.0, Online: true},
					{ID: "node-2", Zone: "Subnet-B", Tier: 3, Locality: "Campus", Credit: 120.0, Online: true},
				},
				"nodes_online": 2,
				"count":        2,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockCoord.Close()

	srv, err := StartServer(app, 0)
	if err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	wsURL := "ws" + strings.TrimPrefix(mockCoord.URL, "http") + "/ws"

	// 1. POST /api/worker/connect
	connectPayload, _ := json.Marshal(WorkerConnectionConfig{
		CoordinatorURL: wsURL,
		NodeID:         "donor-node-test-1",
		SubnetZone:     "Campus-North",
		AllocatedCores: 6,
		AllocatedRAMMB: 16384,
		StorageQuotaGB: 200,
	})
	resp, err := client.Post(srv.URL+"/api/worker/connect", "application/json", bytes.NewReader(connectPayload))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/worker/connect failed: %v, code: %v", err, resp.StatusCode)
	}
	resp.Body.Close()

	// Wait for connection
	for i := 0; i < 40; i++ {
		time.Sleep(50 * time.Millisecond)
		st := app.GetWorkerStatus()
		if st.Connected {
			break
		}
	}

	// 2. GET /api/worker/status
	resp, err = client.Get(srv.URL + "/api/worker/status")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/worker/status failed: %v", err)
	}
	var wStatus WorkerConnectionStatus
	_ = json.NewDecoder(resp.Body).Decode(&wStatus)
	resp.Body.Close()
	if !wStatus.Connected {
		t.Errorf("expected worker to report connected from /api/worker/status")
	}

	// 3. POST /api/worker/config
	configPayload, _ := json.Marshal(WorkerConnectionConfig{
		AllocatedCores: 8,
		AllocatedRAMMB: 32768,
		StorageQuotaGB: 250,
		SubnetZone:     "Campus-South",
	})
	resp, err = client.Post(srv.URL+"/api/worker/config", "application/json", bytes.NewReader(configPayload))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/worker/config failed: %v", err)
	}
	resp.Body.Close()

	// 4. GET /api/worker/receipts
	resp, err = client.Get(srv.URL + "/api/worker/receipts")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/worker/receipts failed: %v", err)
	}
	resp.Body.Close()

	// 5. POST /api/worker/reconnect
	resp, err = client.Post(srv.URL+"/api/worker/reconnect", "application/json", nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/worker/reconnect failed: %v", err)
	}
	resp.Body.Close()

	// 6. POST /api/worker/disconnect
	resp, err = client.Post(srv.URL+"/api/worker/disconnect", "application/json", nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/worker/disconnect failed: %v", err)
	}
	_ = json.NewDecoder(resp.Body).Decode(&wStatus)
	resp.Body.Close()
	if wStatus.Connected {
		t.Errorf("expected worker to be disconnected")
	}

	// 7. GET /api/cluster/status with valid coordinator
	resp, err = client.Get(srv.URL + "/api/cluster/status?coordinator=" + mockCoord.URL)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/cluster/status failed: %v", err)
	}
	var cStatus web.ClusterStatusResponse
	_ = json.NewDecoder(resp.Body).Decode(&cStatus)
	resp.Body.Close()
	if cStatus.NodesOnline != 3 {
		t.Errorf("expected 3 nodes online, got %d", cStatus.NodesOnline)
	}
	if len(cStatus.Fleet) != 2 {
		t.Errorf("expected 2 fleet nodes, got %d", len(cStatus.Fleet))
	}

	// 8. GET /api/cluster/fleet with valid coordinator
	resp, err = client.Get(srv.URL + "/api/cluster/fleet?coordinator=" + mockCoord.URL)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/cluster/fleet failed: %v", err)
	}
	var fleetResp struct {
		Fleet []web.FleetNodeStatus `json:"fleet"`
		Count int                   `json:"count"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&fleetResp)
	resp.Body.Close()
	if fleetResp.Count != 2 {
		t.Errorf("expected fleet count 2, got %d", fleetResp.Count)
	}

	// 9. GET /api/cluster/status with unreachable coordinator
	resp, err = client.Get(srv.URL + "/api/cluster/status?coordinator=http://127.0.0.1:59999")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 graceful fallback from unreachable coordinator, got: %v", err)
	}
	resp.Body.Close()

	// 10. GET /api/cluster/fleet with unreachable coordinator
	resp, err = client.Get(srv.URL + "/api/cluster/fleet?coordinator=http://127.0.0.1:59999")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 graceful fallback from unreachable coordinator, got: %v", err)
	}
	resp.Body.Close()
}

func TestServer_SampleAndManifest(t *testing.T) {
	app, tempDir := createTestApp(t)
	defer cleanupTestApp(app, tempDir)

	var receivedManifest map[string]interface{}
	mockCoord := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/storage/manifest" && r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&receivedManifest)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"dataset_cid":"` + fmt.Sprint(receivedManifest["dataset_cid"]) + `","segments":1,"status":"REGISTERED"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer mockCoord.Close()

	srv, err := StartServer(app, 0)
	if err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	// 1. GET /api/load-sample (default)
	resp, err := client.Get(srv.URL + "/api/load-sample")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/load-sample failed: %v, status: %v", err, resp.StatusCode)
	}
	sampleData, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(sampleData) == 0 {
		t.Errorf("empty sample data from /api/load-sample")
	}

	// 2. GET /api/load-sample?file=genomic_sample.fa
	resp, err = client.Get(srv.URL + "/api/load-sample?file=genomic_sample.fa")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/load-sample with filename failed: %v", err)
	}
	resp.Body.Close()

	// 3. GET /api/load-sample?file=missing_file.xyz -> 404
	resp, err = client.Get(srv.URL + "/api/load-sample?file=missing_file.xyz")
	if err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for missing sample file, got: %v, status: %v", err, resp.StatusCode)
	}
	resp.Body.Close()

	// 4. Ingest sample data to create a real dataset in vault
	ingestRes, err := app.IngestFile("genomic_sample.fa", sampleData)
	if err != nil {
		t.Fatalf("IngestFile failed: %v", err)
	}

	// 5. POST /api/publish-manifest with valid dataset
	pubReq := PublishManifestRequest{
		DatasetCID:     ingestRes.DatasetCID,
		CoordinatorURL: mockCoord.URL,
	}
	pubJSON, _ := json.Marshal(pubReq)
	resp, err = client.Post(srv.URL+"/api/publish-manifest", "application/json", bytes.NewReader(pubJSON))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/publish-manifest failed: %v, status: %v", err, resp.StatusCode)
	}
	var pubResp PublishManifestResponse
	_ = json.NewDecoder(resp.Body).Decode(&pubResp)
	resp.Body.Close()

	if pubResp.DatasetCID != ingestRes.DatasetCID {
		t.Errorf("expected published DatasetCID %s, got %s", ingestRes.DatasetCID, pubResp.DatasetCID)
	}
	if pubResp.Status != "REGISTERED" {
		t.Errorf("expected REGISTERED status, got %s", pubResp.Status)
	}

	// 6. POST /api/publish-manifest with unknown CID -> error (400)
	badPubReq := PublishManifestRequest{
		DatasetCID:     "nonexistent_dataset_cid",
		CoordinatorURL: mockCoord.URL,
	}
	badPubJSON, _ := json.Marshal(badPubReq)
	resp, err = client.Post(srv.URL+"/api/publish-manifest", "application/json", bytes.NewReader(badPubJSON))
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown DatasetCID, got %v, status: %v", err, resp.StatusCode)
	}
	resp.Body.Close()
}

func TestStudioApp_RemoteTaskDispatch(t *testing.T) {
	app, tempDir := createTestApp(t)
	defer cleanupTestApp(app, tempDir)

	var submittedTask protocol.TaskCapsule

	mockCoord := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tasks/submit":
			_ = json.NewDecoder(r.Body).Decode(&submittedTask)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"task_id":          submittedTask.TaskID,
				"matched_node":     "node-remote-gpu-01",
				"convex_score":     0.975,
				"locality_tier":    "LAN Hot",
				"perfect_locality": true,
				"status":           "SCHEDULED",
				"message":          "Task accepted and scheduled by PACMan",
			})
		case "/api/cluster/status":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(web.ClusterStatusResponse{
				NodesOnline:    5,
				TasksRunning:   1,
				ActiveJobTitle: "Remote Task Pipeline",
				ActiveJob: &web.ActiveJobInfo{
					JobID:               submittedTask.TaskID,
					Title:               submittedTask.Name,
					Status:              string(protocol.TaskStatusCompleted),
					OutputCID:           "c0ffee123456789abcdef",
					OutputData:          "VERIFIED_REMOTE_COMPUTATION_SUCCESS",
					FuelConsumed:        185000000,
					ExecutionDurationMs: 420,
					WorkerNodeID:        "node-remote-gpu-01",
				},
				Fleet: []web.FleetNodeStatus{
					{ID: "node-remote-gpu-01", Zone: "Subnet-A", Tier: 3, Locality: "LAN Hot", Credit: 250, Online: true},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockCoord.Close()

	// Submit task with Target: "remote"
	req := TaskSubmitRequest{
		Name:           "Remote Genomic Alignment",
		MinTier:        1,
		Entrypoint:     "task.wasm",
		Target:         "remote",
		CoordinatorURL: mockCoord.URL,
		FuelLimit:      500000000,
		MaxMemoryMB:    512,
	}

	resp, err := app.SubmitTask(req, nil)
	if err != nil {
		t.Fatalf("SubmitTask remote failed: %v", err)
	}

	if resp.Status != "DISPATCHED_TO_CLUSTER" {
		t.Errorf("expected DISPATCHED_TO_CLUSTER status, got %s", resp.Status)
	}
	if resp.TaskID == "" || resp.Signature == "" {
		t.Errorf("invalid submit response: %+v", resp)
	}

	// Wait for remote DAG execution to poll and complete
	var finalDAG DAGPipelineStatus
	for i := 0; i < 60; i++ {
		time.Sleep(100 * time.Millisecond)
		finalDAG, err = app.GetDAGStatus()
		if err == nil && finalDAG.HasOutput && finalDAG.Stages[3].Status == "completed" {
			break
		}
	}

	if !finalDAG.HasOutput {
		t.Fatalf("remote DAG did not complete with output in time: %+v", finalDAG)
	}

	// Verify all 4 stages completed
	for i, st := range finalDAG.Stages {
		if st.Status != "completed" {
			t.Errorf("stage %d (%s) expected completed, got %s", i+1, st.Name, st.Status)
		}
	}

	// Verify output payload retrieval
	out, err := app.GetOutputPayload(resp.TaskID)
	if err != nil {
		t.Fatalf("GetOutputPayload failed: %v", err)
	}
	if out.OutputText != "VERIFIED_REMOTE_COMPUTATION_SUCCESS" {
		t.Errorf("expected remote output text, got: %s", out.OutputText)
	}
	if out.OutputCID != "c0ffee123456789abcdef" {
		t.Errorf("expected OutputCID c0ffee123456789abcdef, got %s", out.OutputCID)
	}
}

func TestStudioApp_WorkerEndToEndDispatchAndReceipt(t *testing.T) {
	app, tempDir := createTestApp(t)
	defer cleanupTestApp(app, tempDir)

	hub := transport.NewSignalingHub()
	var registeredNodeID string
	var regMu sync.Mutex

	hub.SetCallbacks(func(node *protocol.Node) {
		regMu.Lock()
		registeredNodeID = node.ID
		regMu.Unlock()
	}, nil, nil)

	var receiptMu sync.Mutex
	var receivedReceipt protocol.ExecutionReceipt
	receiptReceived := false

	mockCoord := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ws":
			hub.HandleWebSocket(w, r)
		case "/api/receipts/verify":
			var rcpt protocol.ExecutionReceipt
			if err := json.NewDecoder(r.Body).Decode(&rcpt); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			receiptMu.Lock()
			receivedReceipt = rcpt
			receiptReceived = true
			receiptMu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":   "ACCEPTED",
				"verified": true,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockCoord.Close()

	wsURL := "ws" + strings.TrimPrefix(mockCoord.URL, "http") + "/ws"
	testNodeID := "e2e-donor-worker-01"

	cfg := WorkerConnectionConfig{
		CoordinatorURL: wsURL,
		NodeID:         testNodeID,
		SubnetZone:     "Campus-Alpha",
		AllocatedCores: 4,
		AllocatedRAMMB: 8192,
		StorageQuotaGB: 50,
	}

	if err := app.StartWorker(cfg); err != nil {
		t.Fatalf("StartWorker failed: %v", err)
	}

	// 1. Wait for registration on mock coordinator
	registered := false
	for i := 0; i < 60; i++ {
		regMu.Lock()
		if registeredNodeID == testNodeID {
			registered = true
		}
		regMu.Unlock()
		if registered {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !registered {
		t.Fatalf("worker failed to register with coordinator in time")
	}

	// Wait for app status to report connected
	for i := 0; i < 40; i++ {
		st := app.GetWorkerStatus()
		if st.Connected {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 2. Dispatch a task capsule to this worker over WebSocket
	testTaskID := "task-dispatch-e2e-999"
	task := protocol.TaskCapsule{
		TaskID:           testTaskID,
		Name:             "E2E Genomic Verification",
		MinTier:          protocol.Tier1Wasm,
		Entrypoint:       "task.wasm",
		MaxMemoryMB:      512,
		FuelLimit:        500000000,
		CodePayload:      DefaultTaskWasm,
		RequiredDatasets: []string{},
	}
	taskBytes, err := json.Marshal(task)
	if err != nil {
		t.Fatalf("failed to marshal task: %v", err)
	}

	sigMsg := &protocol.SignalingMessage{
		Type:    "dispatch",
		ToNode:  testNodeID,
		Payload: taskBytes,
	}
	if err := hub.SendToNode(testNodeID, sigMsg); err != nil {
		t.Fatalf("failed to dispatch task to worker: %v", err)
	}

	// 3. Wait for receipt submission to /api/receipts/verify
	var rcpt protocol.ExecutionReceipt
	gotReceipt := false
	for i := 0; i < 100; i++ {
		receiptMu.Lock()
		if receiptReceived {
			gotReceipt = true
			rcpt = receivedReceipt
		}
		receiptMu.Unlock()
		if gotReceipt {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !gotReceipt {
		t.Fatalf("timed out waiting for execution receipt at coordinator endpoint")
	}

	if rcpt.TaskID != testTaskID {
		t.Errorf("expected receipt task ID %s, got %s", testTaskID, rcpt.TaskID)
	}
	if rcpt.NodeID != testNodeID {
		t.Errorf("expected receipt node ID %s, got %s", testNodeID, rcpt.NodeID)
	}
	if rcpt.Signature == "" {
		t.Errorf("expected non-empty Ed25519 signature on receipt")
	}

	// Verify cryptographic signature on receipt
	digest, err := rcpt.CanonicalReceiptHash()
	if err != nil {
		t.Fatalf("failed to compute canonical receipt hash: %v", err)
	}
	valid, err := crypto.VerifySignatureHex(rcpt.WorkerPubKey, digest, rcpt.Signature)
	if err != nil || !valid {
		t.Fatalf("Ed25519 signature on execution receipt is invalid: %v", err)
	}

	// 4. Verify StudioApp local state
	receipts := app.GetWorkerReceipts()
	if len(receipts) == 0 {
		t.Fatalf("expected at least 1 stored receipt in StudioApp, got %d", len(receipts))
	}
	found := false
	for _, r := range receipts {
		if r.TaskID == testTaskID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("task receipt not found in StudioApp.GetWorkerReceipts()")
	}

	stats, _ := app.GetSystemStats()
	if stats.WorkerStatus == nil {
		t.Fatalf("expected non-nil WorkerStatus in GetSystemStats")
	}
	if stats.WorkerStatus.TasksAssigned < 1 {
		t.Errorf("expected TasksAssigned >= 1, got %d", stats.WorkerStatus.TasksAssigned)
	}
	if stats.WorkerStatus.ReceiptsSigned < 1 {
		t.Errorf("expected ReceiptsSigned >= 1, got %d", stats.WorkerStatus.ReceiptsSigned)
	}

	// 5. Cleanly stop worker
	if err := app.StopWorker(); err != nil {
		t.Fatalf("StopWorker failed: %v", err)
	}
	st := app.GetWorkerStatus()
	if st.Connected {
		t.Errorf("expected worker disconnected after StopWorker")
	}
}

