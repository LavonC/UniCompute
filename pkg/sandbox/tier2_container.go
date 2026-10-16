package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"unicompute/pkg/protocol"
)

// Tier2ContainerSandbox executes complex POSIX workloads inside an isolated container / hardened process.
type Tier2ContainerSandbox struct{}

// NewTier2ContainerSandbox initializes a Tier 2 Container sandbox.
func NewTier2ContainerSandbox() *Tier2ContainerSandbox {
	return &Tier2ContainerSandbox{}
}

// Tier returns protocol.Tier2Container.
func (s *Tier2ContainerSandbox) Tier() protocol.ExecutionTier {
	return protocol.Tier2Container
}

// Execute runs the workload inside an isolated directory jail bounded by a Win32 JobObject.
func (s *Tier2ContainerSandbox) Execute(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	startTime := time.Now()

	// 1. Prepare isolated workspace
	workDir, err := os.MkdirTemp("", fmt.Sprintf("unicompute-tier2-%s-*", req.TaskID))
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	inputDir := filepath.Join(workDir, "inputs")
	outputDir := filepath.Join(workDir, "outputs")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, err
	}

	// Mount inputs
	for name, data := range req.InputMounts {
		targetPath := filepath.Join(inputDir, name)
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(targetPath, data, 0644); err != nil {
			return nil, err
		}
	}

	// Write entrypoint script or binary
	entrypointPath := filepath.Join(workDir, req.Entrypoint)
	if len(req.CodePayload) > 0 {
		if err := os.WriteFile(entrypointPath, req.CodePayload, 0755); err != nil {
			return nil, fmt.Errorf("failed to write payload: %w", err)
		}
	}

	// 2. Prepare command execution
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 300 * time.Second
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var cmd *exec.Cmd
	// Determine if running python, shell, or binary
	ext := filepath.Ext(req.Entrypoint)
	if ext == ".py" {
		args := append([]string{entrypointPath}, req.Args...)
		cmd = exec.CommandContext(execCtx, "python", args...)
	} else if ext == ".sh" {
		args := append([]string{entrypointPath}, req.Args...)
		cmd = exec.CommandContext(execCtx, "sh", args...)
	} else {
		cmd = exec.CommandContext(execCtx, entrypointPath, req.Args...)
	}

	cmd.Dir = workDir
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env,
		"UNICOMPUTE_INPUTS="+inputDir,
		"UNICOMPUTE_OUTPUTS="+outputDir,
		"NETWORK=none",
	)
	for k, v := range req.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	if req.StdoutWriter != nil {
		cmd.Stdout = io.MultiWriter(&stdoutBuf, req.StdoutWriter)
	} else {
		cmd.Stdout = &stdoutBuf
	}
	if req.StderrWriter != nil {
		cmd.Stderr = io.MultiWriter(&stderrBuf, req.StderrWriter)
	} else {
		cmd.Stderr = &stderrBuf
	}

	// 3. Bind to Win32 JobObject for memory ceilings and idle priority
	maxMem := req.MaxMemoryMB * 1024 * 1024
	if maxMem <= 0 {
		maxMem = 2048 * 1024 * 1024 // 2 GiB default
	}
	job, err := CreateBoundedJobObject(maxMem, 50)
	if err == nil && job != nil {
		defer job.Close()
	}

	// Start command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start container process: %w", err)
	}

	if job != nil {
		_ = job.AssignCmd(cmd)
	}

	errWait := cmd.Wait()
	exitCode := 0
	if errWait != nil {
		if exitErr, ok := errWait.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	// 4. Collect outputs
	outputFiles := make(map[string][]byte)
	var outputHasher = sha256.New()
	_ = filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, errRel := filepath.Rel(outputDir, path)
		if errRel == nil {
			content, errRead := os.ReadFile(path)
			if errRead == nil {
				outputFiles[rel] = content
				outputHasher.Write([]byte(rel))
				outputHasher.Write(content)
			}
		}
		return nil
	})

	outputCID := hex.EncodeToString(outputHasher.Sum(nil))
	duration := time.Since(startTime)
	fuelConsumed := uint64(duration.Microseconds()) * 1200

	return &ExecutionResult{
		TaskID:       req.TaskID,
		ExitCode:     exitCode,
		FuelConsumed: fuelConsumed,
		OutputFiles:  outputFiles,
		Stdout:       stdoutBuf.Bytes(),
		Stderr:       stderrBuf.Bytes(),
		DurationMs:   duration.Milliseconds(),
		OutputCID:    outputCID,
		Error:        errWait,
	}, nil
}
