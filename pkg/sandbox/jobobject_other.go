//go:build !windows

package sandbox

import (
	"os/exec"
)

// JobObject fallback stub for non-Windows platforms.
type JobObject struct{}

// CreateBoundedJobObject fallback stub.
func CreateBoundedJobObject(maxMemoryBytes int64, cpuRatePercent int) (*JobObject, error) {
	return &JobObject{}, nil
}

// AssignCmd fallback stub.
func (j *JobObject) AssignCmd(cmd *exec.Cmd) error {
	return nil
}

// Close fallback stub.
func (j *JobObject) Close() error {
	return nil
}
