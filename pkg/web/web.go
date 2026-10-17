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

// JobStage models a single stage in the DAG pipeline.
type JobStage struct {
	Name        string `json:"name"`
	Status      string `json:"status"` // "pending", "running", "completed", "idle"
	Description string `json:"description"`
	Duration    string `json:"duration,omitempty"`
}

// ActiveJobInfo models the active running or recently submitted job.
type ActiveJobInfo struct {
	JobID               string     `json:"job_id"`
	Title               string     `json:"title"`
	Status              string     `json:"status"`
	Stages              []JobStage `json:"stages"`
	OutputCID           string     `json:"output_cid,omitempty"`
	OutputData          string     `json:"output_data,omitempty"`
	FuelConsumed        uint64     `json:"fuel_consumed,omitempty"`
	ExecutionDurationMs int64      `json:"execution_duration_ms,omitempty"`
	WorkerNodeID        string     `json:"worker_node_id,omitempty"`
}

// ClusterStatusResponse models cluster telemetry sent to the coordinator UI.
type ClusterStatusResponse struct {
	NodesOnline    int               `json:"nodes_online"`
	LabNodes       int               `json:"lab_nodes"`
	LaptopNodes    int               `json:"laptop_nodes"`
	TasksRunning   int               `json:"tasks_running"`
	LocalityRate   float64           `json:"locality_rate"`
	ActiveJobTitle string            `json:"active_job_title"`
	TotalCores     int               `json:"total_cores"`
	TotalRAMMB     int64             `json:"total_ram_mb"`
	StorageBytes   int64             `json:"storage_bytes"`
	TotalSegments  int               `json:"total_segments"`
	OnlineShards   int               `json:"online_shards"`
	TotalShards    int               `json:"total_shards"`
	Fleet          []FleetNodeStatus `json:"fleet"`
	ActiveJob      *ActiveJobInfo    `json:"active_job,omitempty"`
	JobStages      []JobStage        `json:"job_stages,omitempty"`
	Logs           []string          `json:"logs,omitempty"`
	AuditLogs      []string          `json:"audit_logs,omitempty"`
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
