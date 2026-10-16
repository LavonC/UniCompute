package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"unicompute/pkg/crypto"
	"unicompute/pkg/protocol"
)

var (
	ErrUnauthorizedBinary = errors.New("tier 3 admission denied: binary lacks valid institutional ed25519 cryptographic signature")
)

// Tier3NativeSandbox executes native Win32/GPU processes under strict cryptographic admission and JobObject resource bounding.
type Tier3NativeSandbox struct {
	mu                       sync.RWMutex
	allowedInstitutionalKeys map[string]bool
}

// NewTier3NativeSandbox initializes a Tier 3 native execution sandbox.
func NewTier3NativeSandbox(trustedKeys []string) *Tier3NativeSandbox {
	allowed := make(map[string]bool)
	for _, k := range trustedKeys {
		allowed[k] = true
	}
	return &Tier3NativeSandbox{
		allowedInstitutionalKeys: allowed,
	}
}

// AddTrustedKey registers an institutional Ed25519 public key.
func (s *Tier3NativeSandbox) AddTrustedKey(pubKeyHex string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowedInstitutionalKeys[pubKeyHex] = true
}

// HasTrustedKeys returns true if at least one institutional key is configured.
func (s *Tier3NativeSandbox) HasTrustedKeys() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.allowedInstitutionalKeys) > 0
}

// Tier returns protocol.Tier3NativeGPU.
func (s *Tier3NativeSandbox) Tier() protocol.ExecutionTier {
	return protocol.Tier3NativeGPU
}

// Execute enforces first-party trust admission and launches native process within a Win32 Job Object.
func (s *Tier3NativeSandbox) Execute(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	startTime := time.Now()

	// 1. Enforce First-Party Cryptographic Trust Boundary (§6.3)
	if req.SignedBinarySig == "" || req.InstitutionalPubKey == "" {
		return nil, ErrUnauthorizedBinary
	}

	// Fail-closed: Must have at least one authorized key, and req.InstitutionalPubKey must be authorized.
	s.mu.RLock()
	keysCount := len(s.allowedInstitutionalKeys)
	isAuthorized := s.allowedInstitutionalKeys[req.InstitutionalPubKey]
	s.mu.RUnlock()

	if keysCount == 0 || !isAuthorized {
		return nil, fmt.Errorf("%w: key %s not recognized by institution (fail-closed)", ErrUnauthorizedBinary, req.InstitutionalPubKey)
	}

	// Verify Ed25519 signature over binary hash
	binaryHash := sha256.Sum256(req.CodePayload)
	valid, errSig := crypto.VerifySignatureHex(req.InstitutionalPubKey, binaryHash[:], req.SignedBinarySig)
	if errSig != nil || !valid {
		return nil, fmt.Errorf("%w: signature verification failed", ErrUnauthorizedBinary)
	}

	// 2. Prepare workspace
	workDir, err := os.MkdirTemp("", fmt.Sprintf("unicompute-tier3-%s-*", req.TaskID))
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	inputDir := filepath.Join(workDir, "inputs")
	outputDir := filepath.Join(workDir, "outputs")
	_ = os.MkdirAll(inputDir, 0755)
	_ = os.MkdirAll(outputDir, 0755)

	for name, data := range req.InputMounts {
		_ = os.WriteFile(filepath.Join(inputDir, name), data, 0644)
	}

	binaryPath := filepath.Join(workDir, req.Entrypoint)
	if err := os.WriteFile(binaryPath, req.CodePayload, 0755); err != nil {
		return nil, fmt.Errorf("failed to write verified binary: %w", err)
	}

	// 3. Launch process with Win32 JobObject bounding
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 300 * time.Second
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, binaryPath, req.Args...)
	cmd.Dir = workDir
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env,
		"CUDA_VISIBLE_DEVICES=0",
		"UNICOMPUTE_INPUTS="+inputDir,
		"UNICOMPUTE_OUTPUTS="+outputDir,
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

	maxMem := req.MaxMemoryMB * 1024 * 1024
	job, err := CreateBoundedJobObject(maxMem, 80)
	if err == nil && job != nil {
		defer job.Close()
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start native GPU process: %w", err)
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

	outputFiles := make(map[string][]byte)
	var outputHasher = sha256.New()
	_ = filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(outputDir, path)
		content, _ := os.ReadFile(path)
		outputFiles[rel] = content
		outputHasher.Write([]byte(rel))
		outputHasher.Write(content)
		return nil
	})

	outputCID := hex.EncodeToString(outputHasher.Sum(nil))
	duration := time.Since(startTime)
	fuelConsumed := uint64(duration.Microseconds()) * 2500

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
