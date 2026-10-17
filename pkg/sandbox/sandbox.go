package sandbox

import (
	"context"
	"io"
	"time"

	"unicompute/pkg/protocol"
)

// ExecutionRequest specifies all parameters needed to execute a task capsule in an isolated sandbox.
type ExecutionRequest struct {
	TaskID              string
	MinTier             protocol.ExecutionTier
	Entrypoint          string
	CodePayload         []byte
	InputMounts         map[string][]byte // Filename -> Data, mapped into /data/inputs
	MaxMemoryMB         int64
	FuelLimit           uint64
	Args                []string
	Env                 map[string]string
	StdoutWriter        io.Writer
	StderrWriter        io.Writer
	TelemetryChan       chan<- protocol.LiveTelemetry
	SignedBinarySig     string // For Tier 3 native admission verification
	InstitutionalPubKey string
	ManifestDigest      []byte
	Timeout             time.Duration
}

// ExecutionResult captures the output and telemetry of an executed task.
type ExecutionResult struct {
	TaskID       string
	ExitCode     int
	FuelConsumed uint64
	OutputFiles  map[string][]byte // Extracted from /data/outputs
	Stdout       []byte
	Stderr       []byte
	DurationMs   int64
	OutputCID    string
	Error        error
}

// Sandbox defines the common interface for Tier 1, Tier 2, and Tier 3 execution engines.
type Sandbox interface {
	Tier() protocol.ExecutionTier
	Execute(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error)
}
