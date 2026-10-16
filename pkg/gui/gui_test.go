package gui

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"unicompute/pkg/crypto"
	"unicompute/pkg/protocol"
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
	tm.RestoreWindow()
	_ = tm.Remove()
}
