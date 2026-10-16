# UniCompute: Comprehensive System Architecture & Production Implementation

A verified, research-grounded distributed computing and content-addressed storage platform for heterogeneous consumer Windows PCs and campus laboratory workstations.

Based on the research specification: **UniCompute: Comprehensive System Architecture (Verified System Architecture Specification)**.

---

## Architecture Overview

UniCompute transforms idle student laptops and campus laboratory computers into a private, high-throughput academic supercomputer without central bandwidth bottlenecks, cloud egress costs, or security compromises.

```
                              +---------------------------------------+
                              |          CENTRAL COORDINATOR          |
                              |  - Control-Plane WebRTC Signaling     |
                              |  - In-Memory Content Locality Index   |
                              |  - PACMan Convex Scheduler            |
                              |  - Storage Scrub & PoR Auditing       |
                              +---------------------------------------+
                                        /                   \
                        Persistent WSS /                     \ Persistent WSS
                         Signaling    /                       \ Signaling
                                     v                         v
       +------------------------------------+           +------------------------------------+
       |       DONOR WORKER NODE A          |           |       DONOR WORKER NODE B          |
       |  - Win32 Desktop Agent GUI         |<=========>|  - Win32 Desktop Agent GUI         |
       |  - Tier 1: Wazero WASI Sandbox     |  WebRTC   |  - Tier 1: Wazero WASI Sandbox     |
       |  - Tier 2: Hardened Containers     |  Channel  |  - Tier 2: Hardened Containers     |
       |  - Tier 3: Native Win32 JobObject  |   A & B   |  - Tier 3: Native Win32 JobObject  |
       |  - Tier R (RAM) & Tier L (NVMe)    |   (P2P)   |  - Tier R (RAM) & Tier L (NVMe)    |
       |  - Cauchy RS(32, 80) Storage Vault |           |  - Cauchy RS(32, 80) Storage Vault |
       +------------------------------------+           +------------------------------------+
```

---

## The Five Functional Pillars Implemented

### 1. Remote Connection Management & Cross-NAT P2P Networking (Objective 1, §4, §5)
- **Central Coordinator**: Control plane only (zero bulk payload data traverses the coordinator).
- **Persistent Signaling**: SDP Offer/Answer, ICE candidates, and node presence heartbeats over WebSocket (`/ws`).
- **WebRTC DataChannels**:
  - **Channel A**: Low-latency SCTP channel for control, live stdout/stderr telemetry, and compact outputs (< 64 MiB).
  - **Channel B**: High-throughput data channel for bulk chunks, Cauchy RS shards, and large outputs (> 64 MiB).
- **Dual-Stack STUN/TURN Discovery**: Embedded STUN/TURN service on UDP port 3478 with a **2.0-second deterministic fallback ladder** when direct UDP hole-punching does not converge.

### 2. Multi-Tier Deterministic & Containerized Execution Sandboxing (Objectives 2 & 3, §6)
- **Tier 1 (Public Default — WebAssembly / WASI)**:
  - In-process userspace execution via `wazero` (zero admin privileges, zero Hyper-V/WSL2 dependency).
  - Sub-millisecond (0.4 ms) cold-start latency.
  - Capability-jailed virtual filesystem (`sys.FS`) mounting `/data/inputs` (read-only) and `/data/outputs` (isolated staging).
  - Deterministic instruction counting (**fuel metering**) terminating runaway loops immediately upon budget exhaustion.
  - IEEE-754 bit-identical determinism with canonical NaNs.
- **Tier 2 (Opt-In Power Contributor — Hardened Containers)**:
  - POSIX scientific workflows (Python, NumPy, SciPy, C++).
  - Network isolation (`--network=none`), non-root UID 65534, dropped capabilities.
  - Bounded by parent Win32 JobObject on Windows.
- **Tier 3 (Hardware-Accelerated Native Execution & GPU Pools)**:
  - Direct CUDA / DirectCompute process access.
  - **First-Party Trust Boundary**: Strict cryptographic admission policy admitting only institutionally signed binaries (verified via Ed25519). Unsigned code is immediately rejected.
  - Enforced via Win32 JobObject (`JOB_OBJECT_LIMIT_PROCESS_MEMORY`, `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, `IDLE_PRIORITY_CLASS`).

### 3. Content-Defined Chunking, Merkle Indexing & Fault-Tolerant Storage (Objective 4, §8, §9)
- **Layer 1: FastCDC**: Variable-length content-defined chunking (8 KiB min, 16 KiB avg, 64 KiB max) with gear-based rolling hash.
- **Layer 2: Message-Locked Encryption (MLE AES-256-GCM)**: Plaintext SHA-256 derived convergent key for secure cross-dataset deduplication.
- **Layer 3: Merkle Chunk-to-Segment Manifest Tree**: Maps root file CID -> ordered chunk CIDs -> (Segment_ID, byte_offset, byte_length) with compact inclusion proofs.
- **Layer 4: Cauchy Reed-Solomon RS(k=32, n=80) Erasure Coding**: Over GF(2^8), dispersing 64 MiB segments into 32 data shards and 48 parity shards (2.5× expansion factor). Any 32 of 80 shards reconstruct the full segment.
- **Two-Tier Locality Cache**:
  - **Tier R (RAM Cache)**: In-memory segment cache for hot dataset partitions (0.4s fast path).
  - **Tier L (NVMe/SSD Cache)**: Local disk vault storing whole segments and shards (13.6s path for 40 GiB vs 4.5+ hours WAN download).
- **Lazy Batched Repair Policy**:
  - Delays repair until online shards for any segment drop to threshold $M_{repair} = 48$.
  - Single-pass read of 32 surviving shards regenerates all missing shards over campus LAN.
  - **Campus Lab Anchor Pinning**: Pins $\ge 20$ shards per segment to persistent departmental laboratory desktops.

### 4. Cryptographic Attestation, Spot-Check Auditing & Locality Provisioning (Objective 5, §7, §8.3, §9.2)
- **Two-Layer Compute Verification**:
  - **Layer 1**: Asymmetric Ed25519 Execution Receipt Attestation ($R = task\_id \parallel input\_cid \parallel output\_cid \parallel fuel\_consumed \parallel exit\_code \parallel timestamp$).
  - **Layer 2**: Asynchronous 5–10% Probabilistic Spot-Checking. Coordinator randomly dispatches duplicate task capsule to independent peer, compares `output_cid` and `fuel_consumed`. Discrepancies trigger immediate blacklisting and credit score slashing.
- **Locality-Aware PACMan Convex Scheduler & Delay Scheduling**:
  - Scoring: $Score(node, task) = w_{loc} \cdot (C_{cached} / C_{total})^4 + w_{tier} \cdot I(Tier\_R) + w_{rel} \cdot R_{credit}(node)$.
  - $(C_{cached}/C_{total})^4$ penalizes partial matches ($0.5^4 = 0.0625$), prioritizing nodes holding complete working segments.
  - Delay Scheduling waits up to $\Delta t = 3.0$ seconds for $L = 1.0$ warm node before falling back.
- **Dual-Mode Cryptographic Storage Auditing**:
  - **4.2 KB Compact Proofs of Retrievability (PoR)**: Challenge-response with Merkle branch.
  - **Stripe-Wide Algebraic Auditing**: Berlekamp-Welch decoding across random byte-offset stripe (256 B – 8 KB). Disqualifies nodes failing 4 consecutive audits.

### 5. Functional System Interfaces & Operational Dashboards (Section 10)
- **Donor Node Desktop Agent (Windows 11 GUI, §10.1, Figure 8)**:
  - Interactive resource sliders: CPU core allocation, RAM working-set cap, storage vault reservation.
  - Execution isolation engine controls (Tier 1 Wasm, Tier 2 JobObject, Tier 3 Native).
  - Active execution monitor with live progress, memory commit, GFLOPS rate, and local vault cache hits ("Zero network fetch").
  - Automated power rules: instant auto-pause on DC battery power, pause on mouse/keyboard gaming input, campus hours restriction.
- **Cluster Management & Requester DAG Job Submission Web Console (§10.2, Figure 9)**:
  - Fleet Telemetry Cards: Nodes Online (Campus Labs vs Windows Laptops), Tasks Running, Aggregate Cores | RAM, Storage Vault capacity, Co-located locality hit rate.
  - Interactive DAG Workflow Visualizer: multi-stage pipeline tracking (Ingestion & Sharding -> Locality Dispatch -> Parallel Solver -> Result Reduction).
  - Live Node Fleet Table & P2P Stdout Stream.
- **Distributed Storage Vault & Erasure-Coding Explorer (§10.3, Figure 10)**:
  - 80-Shard Cauchy Matrix Visualizer ($D_0\dots D_{31}$ data shards, $P_{32}\dots P_{79}$ parity shards, anchor pinned badges).
  - Reconstruction Safety Margin Gauge (online shards vs 48 lazy repair threshold vs 32 reconstruction floor).
  - Live Algebraic Stripe Audit Stream (PoR and Berlekamp-Welch audits/sec).

---

## Building and Running

### Prerequisites
- Go 1.22+ installed
- Windows 10/11 or Linux host

### 1. Build Binaries
```powershell
go build -o unicompute-coordinator.exe ./cmd/coordinator
go build -o unicompute-worker.exe ./cmd/worker
go build -o unicompute-cli.exe ./cmd/cli
```

### 2. Run the Central Coordinator
```powershell
./unicompute-coordinator.exe -port 8443 -stun-port 3478
```
- Web Console: Open browser at `http://localhost:8443`

### 3. Run a Donor Worker Node
```powershell
./unicompute-worker.exe -coordinator ws://localhost:8443/ws -id node-win11-8f2a -zone "Campus Lab" -gui-port 9090
```
- Desktop Agent GUI: Open browser at `http://localhost:9090`

### 4. Researcher CLI Usage
```powershell
# Generate signing keys
./unicompute-cli.exe keygen

# Ingest a dataset (FastCDC + MLE + Cauchy RS(32, 80))
./unicompute-cli.exe ingest dataset.dat

# Check cluster telemetry
./unicompute-cli.exe status

# Submit a task capsule
./unicompute-cli.exe submit main.wasm --dataset <CID> --tier 1
```

---

## Running Automated Verification Test Suite

Run the full automated test suite covering all 5 pillars:
```powershell
go test -v ./tests/...
```

All 21 comprehensive test cases verify:
- Cryptographic Ed25519 signing and verification.
- Message-Locked Encryption (MLE AES-256-GCM) convergent keys and deduplication.
- FastCDC normalized rolling hash chunking.
- Merkle chunk manifest trees and inclusion proofs.
- Cauchy Reed-Solomon RS(32, 80) encoding and 48-shard loss reconstruction.
- Reconstruction failure on boundary underflow (< 32 surviving shards).
- Two-tier storage vault (Tier R RAM cache and Tier L NVMe disk storage).
- 4.2 KB Compact Proof of Retrievability (PoR) challenges.
- Lazy batched repair engine ($M=48$ threshold) and campus lab anchor pinning ($\ge 20$ shards).
- Tier 1 Wazero WASI in-process sandbox (capability filesystem jailing and fuel metering).
- Tier 2 Container sandbox with JobObject bounding.
- Tier 3 Native GPU First-Party cryptographic admission boundary.
- PACMan convex locality scoring ($(C/Total)^4$) and Delay Scheduling ($\Delta t = 3.0s$).
- Two-layer compute verification: Ed25519 execution receipts and Byzantine spot-check detection.
- Bayesian reputation decay and 4-failure disqualification.
- Full end-to-end multi-node workflow execution.
