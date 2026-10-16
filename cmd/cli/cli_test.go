package main

import (
	"os"
	"testing"
)

func TestResolveCoordinatorURL(t *testing.T) {
	// 1. Default fallback to localhost:8443
	os.Unsetenv("UNICOMPUTE_COORDINATOR")
	url1 := resolveCoordinatorURL("api/cluster/status", []string{})
	if url1 != "http://localhost:8443/api/cluster/status" {
		t.Errorf("Expected default localhost URL, got: %s", url1)
	}

	// 2. Respect --coordinator flag
	args2 := []string{"--coordinator", "http://192.168.1.50:9000"}
	url2 := resolveCoordinatorURL("api/tasks/submit", args2)
	if url2 != "http://192.168.1.50:9000/api/tasks/submit" {
		t.Errorf("Expected flag URL, got: %s", url2)
	}

	// 3. Respect --coordinator= format
	args3 := []string{"--coordinator=https://cluster.campus.edu:8443"}
	url3 := resolveCoordinatorURL("api/storage/manifest", args3)
	if url3 != "https://cluster.campus.edu:8443/api/storage/manifest" {
		t.Errorf("Expected flag with equals URL, got: %s", url3)
	}

	// 4. Strip trailing slash on coordinator URL
	args4 := []string{"--coordinator", "http://remote-node:8443/"}
	url4 := resolveCoordinatorURL("/api/cluster/status", args4)
	if url4 != "http://remote-node:8443/api/cluster/status" {
		t.Errorf("Expected trailing slash stripped, got: %s", url4)
	}

	// 5. Auto-prepend http:// if scheme omitted
	args5 := []string{"--coordinator", "10.0.0.5:8443"}
	url5 := resolveCoordinatorURL("api/tasks/submit", args5)
	if url5 != "http://10.0.0.5:8443/api/tasks/submit" {
		t.Errorf("Expected http:// auto-prepended, got: %s", url5)
	}

	// 6. Respect UNICOMPUTE_COORDINATOR environment variable
	os.Setenv("UNICOMPUTE_COORDINATOR", "http://env-coord:8443")
	defer os.Unsetenv("UNICOMPUTE_COORDINATOR")
	url6 := resolveCoordinatorURL("api/cluster/status", []string{})
	if url6 != "http://env-coord:8443/api/cluster/status" {
		t.Errorf("Expected env var URL, got: %s", url6)
	}

	// 7. CLI flag overrides environment variable
	args7 := []string{"--coordinator", "http://flag-overrides:8443"}
	url7 := resolveCoordinatorURL("api/cluster/status", args7)
	if url7 != "http://flag-overrides:8443/api/cluster/status" {
		t.Errorf("Expected flag to override env var, got: %s", url7)
	}
}
