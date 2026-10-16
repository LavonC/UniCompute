package main

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"unicompute/pkg/gui"
)

func TestStudio_HeadlessLaunch(t *testing.T) {
	tempVault, err := os.MkdirTemp("", "unicompute-studio-test-*")
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

	// Check status over HTTP
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(srv.URL + "/api/stats")
	if err != nil {
		t.Fatalf("GET /api/stats failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}

	var stats gui.SystemStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("failed to decode stats: %v", err)
	}

	if stats.NodeID == "" {
		t.Errorf("expected non-empty NodeID")
	}
}
