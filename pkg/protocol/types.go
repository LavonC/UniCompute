package protocol

import (
	"encoding/json"
	"time"
)

// ExecutionTier represents the sandboxing tiers described in Objective 2 & 3.
type ExecutionTier int

const (
	Tier1Wasm      ExecutionTier = 1 // Zero-admin in-process WebAssembly/WASI
	Tier2Container ExecutionTier = 2 // Hardened WSL2 / gVisor container sandbox
	Tier3NativeGPU ExecutionTier = 3 // Native Win32 JobObject GPU execution (first-party signed)
)

func (t ExecutionTier) String() string {
	switch t {
	case Tier1Wasm:
		return "Tier 1 (Wasm/WASI)"
	case Tier2Container:
		return "Tier 2 (Hardened Container)"
	case Tier3NativeGPU:
		return "Tier 3 (Native GPU)"
	default:
		return "Unknown"
	}
}

// SubnetZone represents the network location of a node.
type SubnetZone string

const (
	ZoneCampusLab   SubnetZone = "Campus Lab"
	ZoneDormWiFi    SubnetZone = "Dorm Wi-Fi"
	ZoneResidential SubnetZone = "Residential CGNAT"
)

// Node represents a donor worker node in the UniCompute cluster.
type Node struct {
	ID                string        `json:"id"`
	Hostname          string        `json:"hostname"`
	OS                string        `json:"os"`
	Arch              string        `json:"arch"`
	IP                string        `json:"ip"`
	SubnetZone        SubnetZone    `json:"subnet_zone"`
	MaxTier           ExecutionTier `json:"max_tier"`
	AllocatedCores    int           `json:"allocated_cores"`
	TotalCores        int           `json:"total_cores"`
	AllocatedRAMMB    int64         `json:"allocated_ram_mb"`
	TotalRAMMB        int64         `json:"total_ram_mb"`
	StorageQuotaBytes int64         `json:"storage_quota_bytes"`
	StorageUsedBytes  int64         `json:"storage_used_bytes"`
	HasGPU            bool          `json:"has_gpu"`
	GPUModel          string        `json:"gpu_model"`
	VRAMBytes         int64         `json:"vram_bytes"`
	OnBattery         bool          `json:"on_battery"`
	UserActive        bool          `json:"user_active"`
	CreditScore       float64       `json:"credit_score"`      // BitTorrent credit decay score (0.0 - 1.0)
	DiurnalStability  float64       `json:"diurnal_stability"` // 0.0 - 1.0 historical stability
	Online            bool          `json:"online"`
	LastHeartbeat     time.Time     `json:"last_heartbeat"`
	StoredShards      int           `json:"stored_shards"`
	CachedSegments    []string      `json:"cached_segments"` // Whole segments cached in Tier L or Tier R
	RAMCachedSegments []string      `json:"ram_cached_segments"`
	PublicKey         string        `json:"public_key"` // Ed25519 public key hex
	P2PAddress        string        `json:"p2p_address"`
}

// TaskStatus defines the state of a dispatched task.
type TaskStatus string

const (
	TaskStatusPending    TaskStatus = "PENDING"
	TaskStatusScheduled  TaskStatus = "SCHEDULED"
	TaskStatusRunning    TaskStatus = "RUNNING"
	TaskStatusCompleted  TaskStatus = "COMPLETED"
	TaskStatusFailed     TaskStatus = "FAILED"
	TaskStatusSpotCheck  TaskStatus = "SPOT_CHECKING"
	TaskStatusDisputed   TaskStatus = "DISPUTED"
	TaskStatusBlacklist  TaskStatus = "BLACKLISTED"
)

// TaskCapsule represents the lightweight (< 5 MB) execution package submitted by researchers.
type TaskCapsule struct {
	CapsuleID        string            `json:"capsule_id"`
	TaskID           string            `json:"task_id"`
	Name             string            `json:"name"`
	MinTier          ExecutionTier     `json:"min_tier"`
	Entrypoint       string            `json:"entrypoint"` // wasm binary filename or executable inside capsule
	CodePayload      []byte            `json:"code_payload"`
	RequiredDatasets []string          `json:"required_datasets"` // CIDs of required datasets
	FuelLimit        uint64            `json:"fuel_limit"`
	MaxMemoryMB      int64             `json:"max_memory_mb"`
	Args             []string          `json:"args"`
	Env              map[string]string `json:"env"`
	Signature        string            `json:"signature"` // Ed25519 signature over canonical manifest digest
	ResearcherPubKey string            `json:"researcher_pub_key"`
}

// Manifest represents the execution contract stored inside task_capsule.tar.gz.
type Manifest struct {
	Version          string            `json:"version"`
	TaskID           string            `json:"task_id"`
	Name             string            `json:"name"`
	MinTier          ExecutionTier     `json:"min_tier"`
	Entrypoint       string            `json:"entrypoint"`
	RequiredDatasets []string          `json:"required_datasets"`
	FuelLimit        uint64            `json:"fuel_limit"`
	MaxMemoryMB      int64             `json:"max_memory_mb"`
	Args             []string          `json:"args"`
	Env              map[string]string `json:"env"`
	ResearcherPubKey string            `json:"researcher_pub_key"`
}

// ExecutionReceipt represents the Layer 1 cryptographic attestation signed by worker nodes upon completion.
type ExecutionReceipt struct {
	TaskID              string `json:"task_id"`
	NodeID              string `json:"node_id"`
	InputCID            string `json:"input_cid"`
	OutputCID           string `json:"output_cid"`
	FuelConsumed        uint64 `json:"fuel_consumed"`
	ExitCode            int    `json:"exit_code"`
	ExecutionDurationMs int64  `json:"execution_duration_ms"`
	Timestamp           int64  `json:"timestamp"`
	Signature           string `json:"signature"` // Ed25519 signature over SHA-256 canonical receipt tuple
	WorkerPubKey        string `json:"worker_pub_key"`
	OutputData          []byte `json:"output_data,omitempty"` // For compact outputs (< 64 MiB)
}

// ShardMetadata describes an erasure-coded shard in the Cauchy RS(32, 80) vault.
type ShardMetadata struct {
	ShardID     string     `json:"shard_id"`
	SegmentID   string     `json:"segment_id"`
	ShardIndex  int        `json:"shard_index"` // 0..31 data, 32..79 parity
	IsParity    bool       `json:"is_parity"`
	SizeBytes   int64      `json:"size_bytes"`
	NodeID      string     `json:"node_id"`
	SubnetZone  SubnetZone `json:"subnet_zone"`
	IsAnchor    bool       `json:"is_anchor"` // Pinned to campus lab machine
	Checksum    string     `json:"checksum"`  // SHA-256
	Online      bool       `json:"online"`
	LastAudited time.Time  `json:"last_audited"`
}

// SegmentMetadata describes a 64 MiB segment striped across 80 shards.
type SegmentMetadata struct {
	SegmentID       string          `json:"segment_id"`
	DatasetCID      string          `json:"dataset_cid"`
	SegmentIndex    int             `json:"segment_index"`
	RawSizeBytes    int64           `json:"raw_size_bytes"`
	DataShards      int             `json:"data_shards"`   // k = 32
	ParityShards    int             `json:"parity_shards"` // n - k = 48
	TotalShards     int             `json:"total_shards"`  // n = 80
	ShardSizeBytes  int64           `json:"shard_size_bytes"`
	RootMerkleHash  string          `json:"root_merkle_hash"`
	Shards          []ShardMetadata `json:"shards"`
	OnlineShards    int             `json:"online_shards"`
	UnderRepair     bool            `json:"under_repair"`
}

// DatasetManifest represents an ingested dataset index.
type DatasetManifest struct {
	DatasetCID   string            `json:"dataset_cid"`
	Name         string            `json:"name"`
	TotalBytes   int64             `json:"total_bytes"`
	Segments     []SegmentMetadata `json:"segments"`
	ChunkCount   int               `json:"chunk_count"`
	ChunkEntries []ChunkEntry      `json:"chunk_entries"`
	CreatedAt    time.Time         `json:"created_at"`
}

// ChunkEntry maps FastCDC chunks to segments.
type ChunkEntry struct {
	ChunkCID  string `json:"chunk_cid"`
	SegmentID string `json:"segment_id"`
	Offset    int64  `json:"offset"`
	Length    int64  `json:"length"`
}

// AuditChallenge represents a 4.2 KB Compact Proof of Retrievability challenge.
type AuditChallenge struct {
	ChallengeID   string `json:"challenge_id"`
	NodeID        string `json:"node_id"`
	ShardID       string `json:"shard_id"`
	SegmentID     string `json:"segment_id"`
	ShardIndex    int    `json:"shard_index"`
	Seed          int64  `json:"seed"`
	SectorIndices []int  `json:"sector_indices"`
	Nonce         string `json:"nonce"`
	ByteOffset    int64  `json:"byte_offset"` // For Berlekamp-Welch stripe checks
	StripeLength  int    `json:"stripe_length"`
}

// AuditProof represents the worker's response to an audit challenge.
type AuditProof struct {
	ChallengeID    string   `json:"challenge_id"`
	NodeID         string   `json:"node_id"`
	ShardID        string   `json:"shard_id"`
	AggregatedHash string   `json:"aggregated_hash"`
	MerkleBranch   []string `json:"merkle_branch"`
	PathBits       []bool   `json:"path_bits,omitempty"`
	SectorIndex    int      `json:"sector_index,omitempty"`
	SectorData     []byte   `json:"sector_data,omitempty"`
	StripeSample   []byte   `json:"stripe_sample"`
	Timestamp      int64    `json:"timestamp"`
	ProofSize      int      `json:"proof_size"` // ~4.2 KB
}

// SignalingMessage wraps WebSocket and WebRTC signaling exchanges.
type SignalingMessage struct {
	Type      string          `json:"type"` // "offer", "answer", "candidate", "register", "heartbeat", "dispatch", "telemetry", "result"
	FromNode  string          `json:"from_node"`
	ToNode    string          `json:"to_node"`
	SessionID string          `json:"session_id"`
	Payload   json.RawMessage `json:"payload"`
}

// LiveTelemetry contains live stdout/stderr and performance stats streamed over SCTP DataChannel.
type LiveTelemetry struct {
	TaskID       string  `json:"task_id"`
	NodeID       string  `json:"node_id"`
	Progress     float64 `json:"progress"` // 0.0 - 100.0%
	StdoutChunk  string  `json:"stdout_chunk,omitempty"`
	StderrChunk  string  `json:"stderr_chunk,omitempty"`
	FuelUsed     uint64  `json:"fuel_used"`
	MemoryUsedMB int64   `json:"memory_used_mb"`
	GFLOPS       float64 `json:"gflops"`
	Status       string  `json:"status"`
}
