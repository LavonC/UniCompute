package web

import (
	_ "embed"
	"encoding/json"
	"net/http"
)

//go:embed coordinator_ui.html
var CoordinatorUIHTML []byte

//go:embed worker_ui.html
var WorkerUIHTML []byte

// ClusterStatusResponse models cluster telemetry sent to the coordinator UI.
type ClusterStatusResponse struct {
	NodesOnline     int               `json:"nodes_online"`
	LabNodes        int               `json:"lab_nodes"`
	LaptopNodes     int               `json:"laptop_nodes"`
	TasksRunning    int               `json:"tasks_running"`
	LocalityRate    float64           `json:"locality_rate"`
	ActiveJobTitle  string            `json:"active_job_title"`
	Fleet           []FleetNodeStatus `json:"fleet"`
}

type FleetNodeStatus struct {
	ID       string  `json:"id"`
	Zone     string  `json:"zone"`
	Tier     int     `json:"tier"`
	Locality string  `json:"locality"`
	Credit   float64 `json:"credit"`
	Online   bool    `json:"online"`
}

// WorkerStatusResponse models live donor desktop status.
type WorkerStatusResponse struct {
	NodeID       string            `json:"node_id"`
	CreditScore  float64           `json:"credit_score"`
	StoredShards int               `json:"stored_shards"`
	Zone         string            `json:"zone"`
	ActiveTask   *WorkerActiveTask `json:"active_task,omitempty"`
}

type WorkerActiveTask struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Progress float64 `json:"progress"`
	Stdout   string  `json:"stdout"`
}

// ServeCoordinatorUI writes the Coordinator web dashboard.
func ServeCoordinatorUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(CoordinatorUIHTML)
}

// ServeWorkerUI writes the Donor Node Desktop Agent web GUI.
func ServeWorkerUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(WorkerUIHTML)
}

// WriteJSON sends a JSON response with proper headers.
func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
