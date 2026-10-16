//go:build windows

package sandbox

import (
	"fmt"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows Job Object structures and constants
const (
	JobObjectBasicLimitInformation            = 2
	JobObjectExtendedLimitInformation         = 9
	JobObjectCpuRateControlInformation        = 15

	JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE        = 0x00002000
	JOB_OBJECT_LIMIT_PROCESS_MEMORY           = 0x00000100
	JOB_OBJECT_LIMIT_JOB_MEMORY               = 0x00000200
	JOB_OBJECT_LIMIT_WORKINGSET               = 0x00000001
	JOB_OBJECT_LIMIT_PRIORITY_CLASS           = 0x00000020

	JOB_OBJECT_CPU_RATE_CONTROL_ENABLE        = 0x00000001
	JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP      = 0x00000004

	IDLE_PRIORITY_CLASS                       = 0x00000040
	BELOW_NORMAL_PRIORITY_CLASS               = 0x00004000
)

type JOBOBJECT_BASIC_LIMIT_INFORMATION struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type IO_COUNTERS struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type JOBOBJECT_EXTENDED_LIMIT_INFORMATION struct {
	BasicLimitInformation JOBOBJECT_BASIC_LIMIT_INFORMATION
	IoInfo                IO_COUNTERS
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

type JOBOBJECT_CPU_RATE_CONTROL_INFORMATION struct {
	ControlFlags uint32
	Value        uint32 // Rate in 100ths of 1% (e.g. 5000 = 50%)
}

// JobObject wraps a Windows Job Object handle.
type JobObject struct {
	handle windows.Handle
}

// CreateBoundedJobObject creates a Job Object configured with memory ceilings, IDLE_PRIORITY_CLASS,
// and kill-on-close to prevent orphan processes.
func CreateBoundedJobObject(maxMemoryBytes int64, cpuRatePercent int) (*JobObject, error) {
	hJob, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create job object: %w", err)
	}

	info := JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags:    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PRIORITY_CLASS,
			PriorityClass: IDLE_PRIORITY_CLASS,
		},
	}

	if maxMemoryBytes > 0 {
		info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY
		info.ProcessMemoryLimit = uintptr(maxMemoryBytes)
		info.JobMemoryLimit = uintptr(maxMemoryBytes)
	}

	_, errSet := windows.SetInformationJobObject(
		hJob,
		JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	if errSet != nil {
		windows.CloseHandle(hJob)
		return nil, fmt.Errorf("failed to set job object limits: %w", errSet)
	}

	// Apply CPU rate limit if specified
	if cpuRatePercent > 0 && cpuRatePercent <= 100 {
		cpuInfo := JOBOBJECT_CPU_RATE_CONTROL_INFORMATION{
			ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
			Value:        uint32(cpuRatePercent * 100),
		}
		_, _ = windows.SetInformationJobObject(
			hJob,
			JobObjectCpuRateControlInformation,
			uintptr(unsafe.Pointer(&cpuInfo)),
			uint32(unsafe.Sizeof(cpuInfo)),
		)
	}

	return &JobObject{handle: hJob}, nil
}

// AssignCmd assigns an exec.Cmd process to the job object.
func (j *JobObject) AssignCmd(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return fmt.Errorf("process has not started")
	}

	hProc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		return fmt.Errorf("failed to open process handle: %w", err)
	}
	defer windows.CloseHandle(hProc)

	err = windows.AssignProcessToJobObject(j.handle, hProc)
	if err != nil {
		return fmt.Errorf("failed to assign process to job object: %w", err)
	}
	return nil
}

// Close closes the job object handle, terminating all child processes if configured with kill-on-close.
func (j *JobObject) Close() error {
	if j.handle != 0 {
		return windows.CloseHandle(j.handle)
	}
	return nil
}
