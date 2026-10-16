package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"unicompute/pkg/crypto"
	"unicompute/pkg/protocol"
)

func TestWorkerAgentTrustedKeysAndOutputPersistence(t *testing.T) {
	tempVaultDir, err := os.MkdirTemp("", "worker-test-vault-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tempVaultDir)

	instKP, _ := crypto.GenerateKeyPair()
	trustedKey := instKP.PublicKeyHex()

	// 1. Initialize worker with configured institutional trusted key (Issue 2)
	agent, err := NewWorkerAgent("node-test-01", "ws://localhost:8443/ws", protocol.ZoneCampusLab, tempVaultDir, trustedKey)
	if err != nil {
		t.Fatalf("NewWorkerAgent failed: %v", err)
	}
	if agent.maxTier != protocol.Tier3NativeGPU {
		t.Errorf("Expected Tier3NativeGPU, got %v", agent.maxTier)
	}

	// 2. Test output persistence into agent's vault (Issue 3)
	taskID := "task-persist-output-99"
	filename := "metrics/summary.json"
	payload := []byte(`{"accuracy": 0.9984, "loss": 0.0016, "status": "CONVERGED"}`)

	chunkCID, errStore := agent.vault.StoreOutput(taskID, filename, payload)
	if errStore != nil {
		t.Fatalf("StoreOutput failed: %v", errStore)
	}
	if chunkCID == "" {
		t.Errorf("Expected non-empty chunk CID from StoreOutput")
	}

	// 3. Verify chunk is accessible via ReadChunk
	chunkData, errChunk := agent.vault.ReadChunk(chunkCID)
	if errChunk != nil {
		t.Fatalf("ReadChunk failed: %v", errChunk)
	}
	if !bytes.Equal(chunkData, payload) {
		t.Errorf("ReadChunk data mismatch")
	}

	// 4. Verify output is accessible via ReadOutput
	outData, errOut := agent.vault.ReadOutput(taskID, filename)
	if errOut != nil {
		t.Fatalf("ReadOutput failed: %v", errOut)
	}
	if !bytes.Equal(outData, payload) {
		t.Errorf("ReadOutput data mismatch")
	}

	// 5. Test GUI /api/worker/output endpoint by ?cid=...
	reqCID := httptest.NewRequest(http.MethodGet, "/api/worker/output?cid="+chunkCID, nil)
	recCID := httptest.NewRecorder()
	agent.handleGUIOutput(recCID, reqCID)
	if recCID.Code != http.StatusOK {
		t.Errorf("Expected 200 OK from /api/worker/output?cid=, got %d", recCID.Code)
	}
	if !bytes.Equal(recCID.Body.Bytes(), payload) {
		t.Errorf("Output served via HTTP does not match stored payload")
	}

	// 6. Test GUI /api/worker/output endpoint by ?task_id=...&file=...
	reqFile := httptest.NewRequest(http.MethodGet, "/api/worker/output?task_id="+taskID+"&file="+filename, nil)
	recFile := httptest.NewRecorder()
	agent.handleGUIOutput(recFile, reqFile)
	if recFile.Code != http.StatusOK {
		t.Errorf("Expected 200 OK from /api/worker/output?task_id=&file=, got %d", recFile.Code)
	}
	if !bytes.Equal(recFile.Body.Bytes(), payload) {
		t.Errorf("File served via HTTP does not match stored payload")
	}

	// 7. Test GUI /api/worker/output endpoint by ?task_id=... (lists files)
	reqList := httptest.NewRequest(http.MethodGet, "/api/worker/output?task_id="+taskID, nil)
	recList := httptest.NewRecorder()
	agent.handleGUIOutput(recList, reqList)
	if recList.Code != http.StatusOK {
		t.Errorf("Expected 200 OK listing task outputs, got %d", recList.Code)
	}
	var listResp struct {
		TaskID string   `json:"task_id"`
		Files  []string `json:"files"`
	}
	_ = json.NewDecoder(recList.Body).Decode(&listResp)
	if len(listResp.Files) != 1 || filepath.ToSlash(listResp.Files[0]) != filename {
		t.Errorf("Expected listed files to contain %s, got: %v", filename, listResp.Files)
	}
}
