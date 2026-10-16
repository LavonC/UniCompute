# UniCompute: Comprehensive Engineering Architecture & Implementation Plan

> **Based on**: *UniCompute: Comprehensive System Architecture* (Verified System Architecture Specification).  
> **Target Scope**: Full core production system (Objectives 1–5, Section 4–11, Section 14).  
> **Excluded Scope**: Section 12 Future Scope (Extension 1: Remote Interactive Desktop, Extension 2: Stateless Campus Web Hosting, Extension 3: High-Speed LAN Distributed AI Inference Mesh).

---

## 1. System Requirements & Architecture Decomposition

### Pillar 1: Remote Connection Management & Cross-NAT P2P Networking (Objective 1, §4, §5)
- **Central Coordinator Control Plane**:
  - Operates exclusively as a control-plane orchestrator, metadata registry, and WebRTC signaling exchange (SDP/ICE over persistent TLS/WSS).
  - Enforces zero bulk payload bytes and zero storage shards across the coordinator during normal operation.
  - Node presence heartbeats, capability advertisement (cores, RAM, disk, min_tier, GPU available, battery state, subnet zone, diurnal availability score).
- **P2P Transport**:
  - WebRTC DataChannels (ICE, DTLS 1.3, SCTP) with dual-stack IPv4/IPv6 STUN candidate harvesting.
  - Channel A: Low-latency SCTP DataChannel for control, stdout/stderr streaming logs, compact outputs (< 64 MiB).
  - Channel B: High-throughput DataChannel for bulk chunks, shards, and large outputs (> 64 MiB).
  - 2.0-Second Deterministic Fallback Ladder to authenticated campus TURN/relay if symmetric UDP firewalls prevent direct hole punching.

### Pillar 2: Multi-Tier Deterministic & Containerized Execution Sandboxing (Objectives 2 & 3, §6)
- **Tier 1 (Public Default — WebAssembly WASI)**:
  - Zero-installation Windows Home compatibility (in-process userspace runtime via `wazero`, sub-millisecond cold start, zero admin rights, zero Hyper-V/WSL2 dependency).
  - Canonical-NaN IEEE-754 bit-identical determinism across CPU architectures.
  - Capability-based memory & syscall isolation: virtual filesystem (`sys.FS`) mounting `/data/inputs` (read-only) and `/data/outputs` (isolated staging).
  - Instruction fuel metering: terminates runaway executions immediately when fuel budget is exhausted.
- **Tier 2 (Opt-In Power Contributor — Hardened Containers)**:
  - Isolated POSIX execution environment with dropped capabilities, network namespace jail (`--network=none`), and read-only rootfs.
  - Windows JobObject bounded execution with CPU rate controls and memory caps.
- **Tier 3 (Hardware-Accelerated Native Execution / GPU Pools)**:
  - First-Party Trust Boundary: cryptographic admission policy admitting only institutionally signed binaries (verified via Ed25519).
  - Kernel-enforced Win32 Job Object resource limits (`JOB_OBJECT_LIMIT_PROCESS_MEMORY`, `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, `IDLE_PRIORITY_CLASS`).
- **Lightweight Task Capsule Packaging (§6.4)**:
  - Capped at < 5 MB content-addressed archive (`task_capsule.tar.gz`) containing entrypoint code/wasm and `manifest.json`.
  - Decoupled `required_datasets` array referencing cryptographic Content IDs (CIDs).

### Pillar 3: Content-Defined Chunking, Merkle Indexing & Fault-Tolerant Storage (Objective 4, §8, §9)
- **Layer 1: FastCDC**: Variable-length content-defined chunking (8–64 KiB, avg 16 KiB) with gear-based rolling hash.
- **Layer 2: Message-Locked Encryption (MLE AES-256-GCM)**: Plaintext SHA-256 derived convergent key for secure cross-dataset deduplication.
- **Layer 3: Merkle Chunk-to-Segment Manifest Index**: Hierarchical Merkle tree mapping root dataset CID -> ordered chunk CIDs -> (Segment_ID, byte_offset, byte_length). Generates and validates compact inclusion proofs.
- **Layer 4: Cauchy Reed-Solomon Erasure Coding RS(k=32, n=80)**: Over GF(2^8), dispersing 64 MiB segments into 32 data shards and 48 parity shards (2.5× expansion factor). Any 32 of 80 shards reconstruct the full segment.
- **Two-Tier Locality Cache**:
  - Tier R (Memory-Warm RAM cache): In-memory physical/heap cache for active wave segments.
  - Tier L (Local NVMe Vault cache): Disk-backed directory structure storing whole segments and local shards.
- **Lazy Batched Repair Policy**:
  - Repair delayed until online shards for any segment drop to threshold $M_{repair} = 48$.
  - Single-pass read of 32 surviving shards regenerates all missing shards over campus LAN.
  - Campus Lab Anchor Pinning: ensures at least 20 shards per segment pinned to persistent lab desktops.

### Pillar 4: Cryptographic Attestation, Spot-Check Auditing & Locality Provisioning (Objective 5, §7, §8.3, §9.2)
- **Two-Layer Compute Verification**:
  - Layer 1: Asymmetric Ed25519 Execution Receipt Attestation. Worker signs canonical receipt:
    $$R = (task\_id \parallel input\_cid \parallel output\_cid \parallel fuel\_consumed \parallel exit\_code \parallel timestamp)$$
    with hardware/software Ed25519 private key.
  - Layer 2: Asynchronous 5–10% Probabilistic Spot-Checking. Coordinator dispatches duplicate task capsule to independent peer, compares `output_cid` and `fuel_consumed`. Discrepancies trigger tie-breaking, blacklisting, and credit score slashing.
- **Locality-Aware PACMan Convex Scheduler & Delay Scheduling**:
  - Locality scoring function:
    $$Score(node, task) = w_{loc} \cdot \left(\frac{C_{cached}}{C_{total}}\right)^4 + w_{tier} \cdot I(Tier\_R) + w_{rel} \cdot R_{credit}(node)$$
  - Delay Scheduling waits up to $\Delta t = 3.0$ seconds for $L = 1.0$ memory-warm or NVMe-resident node before falling back to network staging.
- **Dual-Mode Cryptographic Storage Auditing**:
  - Single-Node Compact Proofs of Retrievability (PoR): 4.2 KB challenge-response packet with Merkle branch.
  - Stripe-Wide Algebraic Auditing via Berlekamp-Welch decoding across random byte-offset stripe (256 B – 8 KB) to mathematically catch corrupted/Byzantine shards without downloading full segment. Disqualifies nodes failing 4 consecutive audits.

### Pillar 5: Functional System Interfaces & Operational Dashboards (§10)
- **Donor Node Desktop Agent GUI (§10.1, Figure 8)**:
  - Real-time resource sliders (CPU core allocation, RAM cap, local storage quota).
  - Sandbox tier indicators (Tier 1 Wasm, Tier 2 JobObject, Tier 3 Native).
  - Active execution monitor (task name, memory commit, GFLOPS/fuel rate, progress bar, vault cache hits).
  - Automated power & idle rules (AC/DC battery suspension, mouse/keyboard activity guard, campus hours restriction).
  - Storage shard inventory & live P2P network diagnostics.
- **Cluster Management & DAG Orchestration Web Console (§10.2, Figure 9)**:
  - Fleet Telemetry Cards (Nodes Online, Tasks Running, Aggregate Cores/RAM, Storage Vault capacity, Co-located locality hit rate).
  - Interactive DAG Workflow Visualizer (multi-stage pipeline tracking: Stage 1 Ingestion, Stage 2 Locality Dispatch, Stage 3 Parallel Wasm Grid Solver, Stage 4 Result Reduction).
  - Live Node Fleet Table & P2P Stdout Stream (real-time streaming logs from worker nodes).
  - Interactive job submission & dataset inspector.
- **Distributed Storage Vault & Erasure-Coding Explorer (§10.3, Figure 10)**:
  - 80-Shard Cauchy RS(32, 80) Matrix Visualizer ($D_0\dots D_{31}$ data shards, $P_{32}\dots P_{79}$ parity shards).
  - Reconstruction Safety Margin Gauge (online shards vs 48 lazy repair threshold vs 32 reconstruction floor).
  - Live Algebraic Stripe Audit Stream (PoR and Berlekamp-Welch stripe audits log, Byzantine detection).

---

## 2. Implementation Architecture & Module Directory Structure

```
UniComp/
├── cmd/
│   ├── coordinator/          # Central Coordinator binary
│   ├── worker/               # Worker Agent daemon & local agent server/GUI
│   └── cli/                  # unicompute CLI for dataset & task operations
├── pkg/
│   ├── protocol/             # Common schemas, manifests, receipts, wire messages
│   ├── crypto/               # Ed25519 signing/verification, MLE AES-GCM
│   ├── storage/              # FastCDC, Merkle index, RS(32, 80), Vault, PoR, Berlekamp-Welch
│   ├── sandbox/              # Wazero WASI Tier 1, JobObject Tier 2/3, Win32 JobObject bindings
│   ├── scheduler/            # PACMan convex scoring, Delay scheduling, Locality index
│   ├── verification/         # Ed25519 receipt verifier, 5-10% probabilistic spot-checker
│   ├── transport/            # WebRTC DataChannel, WSS signaling, STUN/TURN fallback
│   └── web/                  # Embedded Web Console & Worker Desktop Agent GUI
├── tests/                    # Production test suites (unit, integration, chaos, e2e)
├── docker-compose.yml        # Multi-node local test cluster
├── Dockerfile.coordinator    # Coordinator dockerfile
└── Dockerfile.worker         # Worker node dockerfile
```

---

## 3. Step-by-Step Implementation Strategy

1. **Protocol & Crypto Primitives**:
   - `pkg/protocol`: Data models (`Node`, `TaskCapsule`, `Manifest`, `ExecutionReceipt`, `ShardMetadata`, `AuditChallenge`, `AuditProof`, `SignalingMessage`).
   - `pkg/crypto`: Asymmetric Ed25519 signing/verification for researchers and workers; Message-Locked Encryption (MLE) with convergent key derivation and AES-256-GCM.
2. **Four-Layer Storage Pipeline**:
   - `pkg/storage/fastcdc.go`: Gear-based FastCDC implementation (8KB min, 16KB avg, 64KB max).
   - `pkg/storage/merkle.go`: Merkle Tree indexing of chunk CIDs and compact inclusion proofs.
   - `pkg/storage/erasure.go`: Cauchy Reed-Solomon RS(32, 80) codec over GF(2^8) with SIMD acceleration via `klauspost/reedsolomon`.
   - `pkg/storage/vault.go`: Two-tier storage hierarchy: Tier R (RAM cache) and Tier L (NVMe/disk vault).
   - `pkg/storage/audit.go`: 4.2 KB Compact Proofs of Retrievability and Berlekamp-Welch stripe checks.
   - `pkg/storage/repair.go`: Lazy batched repair engine with $M_{repair} = 48$ threshold and campus lab anchor pinning.
3. **Execution Sandboxing (Tier 1, Tier 2, Tier 3)**:
   - `pkg/sandbox/tier1_wasm.go`: In-process WebAssembly/WASI engine via `wazero` with fuel metering, capability filesystem jailing (`/data/inputs` read-only, `/data/outputs`), and bit-identical output.
   - `pkg/sandbox/tier2_container.go`: Opt-in container / process isolation with dropped privileges and network jailing.
   - `pkg/sandbox/tier3_native.go`: Native process execution with institutional Ed25519 key verification and resource bounds.
   - `pkg/sandbox/jobobject_windows.go` & `jobobject_other.go`: Win32 Job Object management on Windows (memory caps, IDLE_PRIORITY_CLASS, kill on close) with cross-platform fallback for non-Windows hosts.
4. **Locality-Aware PACMan Scheduling & Two-Layer Verification**:
   - `pkg/scheduler`: Content-to-Node Locality Index, PACMan convex scoring ($(\frac{C_{cached}}{C_{total}})^4$), Delay Scheduling ($\Delta t = 3.0s$).
   - `pkg/verification`: Ed25519 Receipt verification, 5–10% probabilistic asynchronous spot-checking, credit decay & reputation tracking, Byzantine slasher.
5. **P2P Transport & Signaling**:
   - `pkg/transport`: WebSocket signaling exchange, Pion WebRTC DataChannel (Channel A for telemetry/compact results, Channel B for bulk shards), STUN/TURN candidate gathering and 2.0s fallback ladder.
6. **Web Interfaces & Operational Dashboards**:
   - `pkg/web`: Embedded single-page applications:
     - Worker Node Desktop Agent GUI (Figure 8).
     - Cluster Management & DAG Orchestration Web Console (Figure 9).
     - Distributed Storage Vault & Erasure-Coding Explorer (Figure 10).
7. **CLI Tool & Executables**:
   - `cmd/coordinator`: Full coordinator server with REST/WSS APIs, embedded Web Console, STUN/TURN, and scheduling.
   - `cmd/worker`: Full worker agent with daemon loop, local GUI, sandbox runner, and storage vault.
   - `cmd/cli`: Developer/Researcher CLI tool for dataset ingestion, task capsule creation, Ed25519 signing, and job monitoring.
8. **Comprehensive Verification & Testing**:
   - Unit tests for all packages.
   - Integration tests: End-to-end Wasm job execution, dataset sharding, RS(32, 80) loss and reconstruction, PACMan locality hit verification, Byzantine detection during spot-checks.
   - Production readiness: Docker Compose multi-node cluster, deployment scripts, and test suite execution.
