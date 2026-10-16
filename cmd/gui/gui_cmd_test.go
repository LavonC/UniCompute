package main

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"unicompute/pkg/gui"
)

func TestGUICmd_Launch(t *testing.T) {
	tempVault, err := os.MkdirTemp("", "unicompute-gui-cmd-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempVault)

	app, err := gui.NewStudioApp(tempVault)
	if err != nil {
		t.Fatalf("failed to init app: %v", err)
	}
	defer app.Close()

	srv, err := gui.StartServer(app, 0)
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Close()

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(srv.URL + "/api/vault")
	if err != nil {
		t.Fatalf("GET /api/vault failed: %v", err)
	}
	defer resp.Body.Close()

	var v gui.VaultMatrixStatus
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("failed to decode vault status: %v", err)
	}
	if v.TotalShards != 80 {
		t.Errorf("expected 80 total shards, got %d", v.TotalShards)
	}
}
