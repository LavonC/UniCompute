package gui

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"unicompute/pkg/web"
)

//go:embed assets/studio.html
var StudioHTML []byte

//go:embed assets/task.wasm
var DefaultTaskWasm []byte

// ServerInstance wraps the running loopback HTTP server.
type ServerInstance struct {
	listener net.Listener
	server   *http.Server
	URL      string
	mu       sync.Mutex
	closed   bool
}

// StartServer starts the embedded local web server for the Studio UI.
func StartServer(app *StudioApp, preferredPort int) (*ServerInstance, error) {
	mux := http.NewServeMux()

	// UI Root
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(StudioHTML)
	})

	// REST APIs
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		stats, err := app.GetSystemStats()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, stats)
	})

	mux.HandleFunc("/api/sliders", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Cores     int   `json:"cores"`
			RAMMB     int64 `json:"ram_mb"`
			StorageGB int64 `json:"storage_gb"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := app.UpdateResourceSliders(req.Cores, req.RAMMB, req.StorageGB); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "OK"})
	})

	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			AutoPauseBattery bool `json:"auto_pause_battery"`
			PauseGaming      bool `json:"pause_gaming"`
			CampusHours      bool `json:"campus_hours"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := app.UpdateRules(req.AutoPauseBattery, req.PauseGaming, req.CampusHours); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "OK"})
	})

	mux.HandleFunc("/api/pause", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		paused, err := app.TogglePause()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"paused": paused})
	})

	mux.HandleFunc("/api/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		filename := r.URL.Query().Get("filename")
		if filename == "" {
			filename = "dataset.bin"
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read upload body", http.StatusBadRequest)
			return
		}
		res, err := app.IngestFile(filename, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})

	mux.HandleFunc("/api/load-sample", func(w http.ResponseWriter, r *http.Request) {
		filename := r.URL.Query().Get("file")
		if filename == "" {
			filename = "genomic_sample.fa"
		}
		targetFile := filepath.Base(filename)
		data, err := readOptionalTestData(filepath.Join("test_data", targetFile))
		if err != nil {
			http.Error(w, fmt.Sprintf("sample file not found: %v", err), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", targetFile))
		_, _ = w.Write(data)
	})

	mux.HandleFunc("/api/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req TaskSubmitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid submit payload", http.StatusBadRequest)
			return
		}
		var code []byte
		if req.CodeBase64 != "" {
			if decoded, err := base64.StdEncoding.DecodeString(req.CodeBase64); err == nil {
				code = decoded
			}
		}
		res, err := app.SubmitTask(req, code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, res)
	})

	mux.HandleFunc("/api/tray/minimize", func(w http.ResponseWriter, r *http.Request) {
		app.MinimizeToTray()
		writeJSON(w, http.StatusOK, map[string]string{"status": "MINIMIZED_TO_TRAY"})
	})

	mux.HandleFunc("/api/tray/restore", func(w http.ResponseWriter, r *http.Request) {
		app.RestoreWindow()
		writeJSON(w, http.StatusOK, map[string]string{"status": "RESTORED"})
	})

	mux.HandleFunc("/api/dag", func(w http.ResponseWriter, r *http.Request) {
		dag, err := app.GetDAGStatus()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, dag)
	})

	mux.HandleFunc("/api/vault", func(w http.ResponseWriter, r *http.Request) {
		v, err := app.GetVaultStatus()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, v)
	})

	mux.HandleFunc("/api/output", func(w http.ResponseWriter, r *http.Request) {
		taskID := r.URL.Query().Get("task_id")
		out, err := app.GetOutputPayload(taskID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, out)
	})

	// Worker Agent Connection & Configuration APIs
	mux.HandleFunc("/api/worker/connect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var cfg WorkerConnectionConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := app.StartWorker(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, app.GetWorkerStatus())
	})

	mux.HandleFunc("/api/worker/disconnect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := app.StopWorker(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, app.GetWorkerStatus())
	})

	mux.HandleFunc("/api/worker/reconnect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := app.ReconnectWorker(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, app.GetWorkerStatus())
	})

	mux.HandleFunc("/api/worker/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, app.GetWorkerStatus())
	})

	mux.HandleFunc("/api/worker/receipts", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, app.GetWorkerReceipts())
	})

	mux.HandleFunc("/api/worker/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var cfg WorkerConnectionConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if err := app.UpdateWorkerConfig(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, app.GetWorkerStatus())
	})

	// Dataset Manifest Publishing to Coordinator
	mux.HandleFunc("/api/publish-manifest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req PublishManifestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		resp, err := app.PublishManifest(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})

	// Coordinator & Cluster Fleet Monitoring Proxies
	mux.HandleFunc("/api/cluster/status", func(w http.ResponseWriter, r *http.Request) {
		coordURL := r.URL.Query().Get("coordinator")
		st, err := app.GetClusterStatus(coordURL)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"nodes_online":     0,
				"tasks_running":    0,
				"active_job_title": fmt.Sprintf("Coordinator unreachable: %v", err),
				"fleet":            []web.FleetNodeStatus{},
				"logs":             []string{fmt.Sprintf("[%s] Cannot reach coordinator: %v", time.Now().Format("15:04:05"), err)},
				"audit_logs":       []string{},
				"error":            err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, st)
	})

	mux.HandleFunc("/api/cluster/fleet", func(w http.ResponseWriter, r *http.Request) {
		coordURL := r.URL.Query().Get("coordinator")
		fleet, err := app.GetClusterFleet(coordURL)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"fleet":        []web.FleetNodeStatus{},
				"nodes_online": 0,
				"count":        0,
				"error":        err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"fleet":        fleet,
			"nodes_online": len(fleet),
			"count":        len(fleet),
		})
	})

	addr := fmt.Sprintf("127.0.0.1:%d", preferredPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		// If preferred port is busy, fallback to any available port
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, fmt.Errorf("failed to bind loopback HTTP listener: %w", err)
		}
	}

	actualPort := listener.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("http://127.0.0.1:%d", actualPort)

	server := &http.Server{
		Handler: mux,
	}

	inst := &ServerInstance{
		listener: listener,
		server:   server,
		URL:      url,
	}

	go func() {
		_ = server.Serve(listener)
	}()

	return inst, nil
}

// Close terminates the embedded HTTP server.
func (s *ServerInstance) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.server.Close()
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
