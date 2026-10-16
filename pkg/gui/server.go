package gui

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
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
