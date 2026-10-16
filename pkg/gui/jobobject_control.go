package gui

import (
	"fmt"
	"sync"

	"unicompute/pkg/sandbox"
)

// JobObjectManager maintains the Win32 Job Object resource envelope bounds.
type JobObjectManager struct {
	mu            sync.Mutex
	activeJob     *sandbox.JobObject
	allocatedCores int
	totalCores     int
	allocatedRAMMB int64
}

// NewJobObjectManager initializes a resource bounds manager.
func NewJobObjectManager(cores int, totalCores int, ramMB int64) *JobObjectManager {
	mgr := &JobObjectManager{
		allocatedCores: cores,
		totalCores:     totalCores,
		allocatedRAMMB: ramMB,
	}
	_ = mgr.ApplyLimits(cores, totalCores, ramMB)
	return mgr
}

// ApplyLimits dynamically bounds process memory and CPU rate via Win32 Job Object limits.
func (m *JobObjectManager) ApplyLimits(cores int, totalCores int, ramMB int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if totalCores <= 0 {
		totalCores = 4
	}
	if cores <= 0 {
		cores = 1
	}
	if cores > totalCores {
		cores = totalCores
	}

	cpuPercent := (cores * 100) / totalCores
	if cpuPercent > 100 {
		cpuPercent = 100
	}
	if cpuPercent < 10 {
		cpuPercent = 10
	}

	ramBytes := ramMB * 1024 * 1024

	// Close previous job object if exists
	if m.activeJob != nil {
		_ = m.activeJob.Close()
		m.activeJob = nil
	}

	job, err := sandbox.CreateBoundedJobObject(ramBytes, cpuPercent)
	if err != nil {
		return fmt.Errorf("failed to apply Win32 Job Object limits: %w", err)
	}

	m.activeJob = job
	m.allocatedCores = cores
	m.totalCores = totalCores
	m.allocatedRAMMB = ramMB

	return nil
}

// Close releases the underlying Job Object handle.
func (m *JobObjectManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeJob != nil {
		err := m.activeJob.Close()
		m.activeJob = nil
		return err
	}
	return nil
}
