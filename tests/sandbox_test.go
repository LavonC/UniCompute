package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"testing"
	"time"

	"unicompute/pkg/crypto"
	"unicompute/pkg/protocol"
	"unicompute/pkg/sandbox"
)

// Minimal valid WebAssembly binary (magic + version 1 + empty type & function section)
var minimalWasmBinary = []byte{
	0x00, 0x61, 0x73, 0x6d, // \0asm
	0x01, 0x00, 0x00, 0x00, // version 1
	0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // Type section: 1 type: func() -> void
	0x03, 0x02, 0x01, 0x00, // Function section: func 0 uses type 0
	0x07, 0x0a, 0x01, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x00, // Export section: export "_start" func 0
	0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b, // Code section: func 0 body (empty, end 0x0b)
}

func TestTier1WasmSandboxExecution(t *testing.T) {
	sb := sandbox.NewTier1WasmSandbox()
	if sb.Tier() != protocol.Tier1Wasm {
		t.Errorf("Expected Tier1Wasm, got %v", sb.Tier())
	}

	req := &sandbox.ExecutionRequest{
		TaskID:      "test-task-wasi-01",
		MinTier:     protocol.Tier1Wasm,
		Entrypoint:  "main.wasm",
		CodePayload: minimalWasmBinary,
		InputMounts: map[string][]byte{
			"reference_genome.fa": []byte(">chr1\nACGTACGTACGT\n"),
		},
		MaxMemoryMB: 128,
		FuelLimit:   10000000,
		Args:        []string{},
		Timeout:     5 * time.Second,
	}

	ctx := context.Background()
	res, err := sb.Execute(ctx, req)
	if err != nil {
		t.Fatalf("Tier 1 Wasm execution failed: %v", err)
	}

	if res.ExitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", res.ExitCode)
	}

	if res.FuelConsumed == 0 {
		t.Errorf("Expected positive fuel consumption, got 0")
	}

	if res.DurationMs < 0 {
		t.Errorf("Invalid execution duration: %d", res.DurationMs)
	}

	// Verify determinism: repeating execution over identical inputs produces identical OutputCID
	res2, err2 := sb.Execute(ctx, req)
	if err2 != nil {
		t.Fatalf("Tier 1 repeat execution failed: %v", err2)
	}

	if res.OutputCID != res2.OutputCID {
		t.Errorf("Nondeterministic execution: OutputCID 1 (%s) != OutputCID 2 (%s)", res.OutputCID, res2.OutputCID)
	}
}

func TestTier1GenomicsWasmSampleExecution(t *testing.T) {
	wasmData, err := os.ReadFile("../test_data/task.wasm")
	if err != nil {
		t.Fatalf("Failed to read test_data/task.wasm: %v", err)
	}
	fastaData, err := os.ReadFile("../test_data/genomic_sample.fa")
	if err != nil {
		t.Fatalf("Failed to read test_data/genomic_sample.fa: %v", err)
	}

	sb := sandbox.NewTier1WasmSandbox()
	req := &sandbox.ExecutionRequest{
		TaskID:      "task-genomics-test-01",
		MinTier:     protocol.Tier1Wasm,
		Entrypoint:  "task.wasm",
		CodePayload: wasmData,
		InputMounts: map[string][]byte{
			"genomic_sample.fa": fastaData,
		},
		MaxMemoryMB: 256,
		FuelLimit:   500000000,
		Timeout:     10 * time.Second,
	}

	res, err := sb.Execute(context.Background(), req)
	if err != nil {
		stderrStr := ""
		if res != nil {
			stderrStr = string(res.Stderr)
		}
		t.Fatalf("Execution of task.wasm failed: %v, stderr: %s", err, stderrStr)
	}
	if res.ExitCode != 0 {
		t.Fatalf("Expected exit code 0, got %d, stderr: %s", res.ExitCode, string(res.Stderr))
	}
	if len(res.OutputFiles) == 0 {
		t.Fatalf("Expected output files, got none")
	}
}

func TestTier2ContainerSandboxExecution(t *testing.T) {
	sb := sandbox.NewTier2ContainerSandbox()
	if sb.Tier() != protocol.Tier2Container {
		t.Errorf("Expected Tier2Container, got %v", sb.Tier())
	}

	// Python script that verifies inputs and writes output to unicompute outputs dir
	script := []byte(`
import os
import sys

inputs_dir = os.environ.get("UNICOMPUTE_INPUTS")
outputs_dir = os.environ.get("UNICOMPUTE_OUTPUTS")

# Verify inputs exist
input_file = os.path.join(inputs_dir, "input.txt")
with open(input_file, "r") as f:
    content = f.read().strip()

# Write output
output_file = os.path.join(outputs_dir, "result.txt")
with open(output_file, "w") as f:
    f.write(f"PROCESSED: {content}")

sys.exit(0)
`)

	req := &sandbox.ExecutionRequest{
		TaskID:      "test-task-tier2-01",
		MinTier:     protocol.Tier2Container,
		Entrypoint:  "worker.py",
		CodePayload: script,
		InputMounts: map[string][]byte{
			"input.txt": []byte("UniCompute Tier 2 Input Data"),
		},
		MaxMemoryMB: 256,
		Timeout:     10 * time.Second,
	}

	res, err := sb.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Tier 2 Container execution failed: %v", err)
	}

	if res.ExitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", res.ExitCode, string(res.Stderr))
	}

	// Verify output was collected
	resultBytes, exists := res.OutputFiles["result.txt"]
	if !exists {
		t.Fatalf("Expected output file 'result.txt' in outputs, got files: %v", res.OutputFiles)
	}

	if !bytes.Contains(resultBytes, []byte("PROCESSED: UniCompute Tier 2 Input Data")) {
		t.Errorf("Unexpected output content: %s", string(resultBytes))
	}
}

func TestTier3FirstPartyAdmissionBoundary(t *testing.T) {
	// 1. Institutional keypair
	instKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate institutional keypair: %v", err)
	}

	sb := sandbox.NewTier3NativeSandbox([]string{instKP.PublicKeyHex()})
	if sb.Tier() != protocol.Tier3NativeGPU {
		t.Errorf("Expected Tier3NativeGPU, got %v", sb.Tier())
	}

	binaryPayload := []byte("echo native GPU tensor calculation")

	// Test A: Unsigned binary MUST BE REJECTED (§6.3)
	unsignedReq := &sandbox.ExecutionRequest{
		TaskID:              "task-tier3-unsigned",
		MinTier:             protocol.Tier3NativeGPU,
		Entrypoint:          "solver.exe",
		CodePayload:         binaryPayload,
		SignedBinarySig:     "",
		InstitutionalPubKey: "",
	}

	_, errUnsigned := sb.Execute(context.Background(), unsignedReq)
	if errUnsigned == nil {
		t.Errorf("Unsigned binary was unexpectedly accepted in Tier 3 (security violation!)")
	}

	// Test B: Binary signed by untrusted foreign key MUST BE REJECTED
	foreignKP, _ := crypto.GenerateKeyPair()
	foreignHash := sha256.Sum256(binaryPayload)
	foreignSig := foreignKP.SignHex(foreignHash[:])

	foreignReq := &sandbox.ExecutionRequest{
		TaskID:              "task-tier3-foreign",
		MinTier:             protocol.Tier3NativeGPU,
		Entrypoint:          "solver.exe",
		CodePayload:         binaryPayload,
		SignedBinarySig:     foreignSig,
		InstitutionalPubKey: foreignKP.PublicKeyHex(),
	}

	_, errForeign := sb.Execute(context.Background(), foreignReq)
	if errForeign == nil {
		t.Errorf("Binary signed by untrusted foreign key was unexpectedly accepted in Tier 3!")
	}

	// Test C: When allowedInstitutionalKeys is empty, any binary MUST BE REJECTED (fail-closed)
	sbEmpty := sandbox.NewTier3NativeSandbox([]string{})
	_, errEmptyKeys := sbEmpty.Execute(context.Background(), foreignReq)
	if errEmptyKeys == nil {
		t.Errorf("Tier 3 unexpectedly accepted binary when trusted institutional keys list was empty (fail-open vulnerability!)")
	}
}

func TestTier1WasmDeterministicFuel(t *testing.T) {
	sb1 := sandbox.NewTier1WasmSandbox()
	sb2 := sandbox.NewTier1WasmSandbox()

	req := &sandbox.ExecutionRequest{
		TaskID:      "test-deterministic-fuel",
		MinTier:     protocol.Tier1Wasm,
		Entrypoint:  "main.wasm",
		CodePayload: minimalWasmBinary,
		InputMounts: map[string][]byte{
			"data1.bin": []byte("Input chunk data payload for deterministic computation"),
			"data2.bin": []byte("Second input partition"),
		},
		MaxMemoryMB: 128,
		FuelLimit:   10000000,
	}

	res1, err1 := sb1.Execute(context.Background(), req)
	if err1 != nil {
		t.Fatalf("Execution 1 failed: %v", err1)
	}

	res2, err2 := sb2.Execute(context.Background(), req)
	if err2 != nil {
		t.Fatalf("Execution 2 failed: %v", err2)
	}

	// In Layer 2 probabilistic spot checking, fuel and output CID must be 100% bit-identical
	if res1.FuelConsumed != res2.FuelConsumed {
		t.Errorf("Nondeterministic fuel consumption: run 1 = %d, run 2 = %d", res1.FuelConsumed, res2.FuelConsumed)
	}
	if res1.OutputCID != res2.OutputCID {
		t.Errorf("Nondeterministic output CID: run 1 = %s, run 2 = %s", res1.OutputCID, res2.OutputCID)
	}
}

func TestTier3AuthorizedBinaryExecution(t *testing.T) {
	instKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	sb := sandbox.NewTier3NativeSandbox([]string{instKP.PublicKeyHex()})

	// Authorized payload
	scriptPayload := []byte("@echo off\r\necho Native GPU Execution Succeeded\r\n")
	scriptHash := sha256.Sum256(scriptPayload)
	sig := instKP.SignHex(scriptHash[:])

	req := &sandbox.ExecutionRequest{
		TaskID:              "task-tier3-authorized",
		MinTier:             protocol.Tier3NativeGPU,
		Entrypoint:          "solver.cmd",
		CodePayload:         scriptPayload,
		SignedBinarySig:     sig,
		InstitutionalPubKey: instKP.PublicKeyHex(),
		MaxMemoryMB:         256,
		Timeout:             5 * time.Second,
	}

	res, err := sb.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("Authorized Tier 3 execution failed: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("Expected exit code 0, got %d. Stderr: %s", res.ExitCode, string(res.Stderr))
	}
	if !bytes.Contains(res.Stdout, []byte("Native GPU Execution Succeeded")) {
		t.Errorf("Expected stdout to contain success message, got: %s", string(res.Stdout))
	}
}
