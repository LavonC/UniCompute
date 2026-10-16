package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"unicompute/pkg/crypto"
	"unicompute/pkg/protocol"
	"unicompute/pkg/storage"
	"unicompute/pkg/web"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	cmd := os.Args[1]
	switch cmd {
	case "keygen":
		handleKeygen()
	case "ingest":
		handleIngest()
	case "submit":
		handleSubmit()
	case "status":
		handleStatus()
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println("UniCompute CLI & Researcher SDK")
	fmt.Println("Usage:")
	fmt.Println("  unicompute keygen                             Generate researcher Ed25519 signing keypair")
	fmt.Println("  unicompute ingest <file>                      Ingest dataset with FastCDC, MLE & Cauchy RS(32, 80)")
	fmt.Println("  unicompute submit [options] <wasm/script>     Submit task capsule with Ed25519 signed manifest")
	fmt.Println("  unicompute status [--coordinator <url>]       Show cluster fleet and storage vault status")
}

func handleKeygen() {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error generating keys: %v\n", err)
		return
	}

	keyFile := "researcher.key"
	pubFile := "researcher.pub.hex"

	if err := kp.SavePrivateKeyFile(keyFile); err != nil {
		fmt.Printf("Error saving key: %v\n", err)
		return
	}
	if err := os.WriteFile(pubFile, []byte(kp.PublicKeyHex()), 0644); err != nil {
		fmt.Printf("Error saving pubkey: %v\n", err)
		return
	}

	fmt.Printf("[+] Generated Ed25519 Keypair:\n")
	fmt.Printf("    Private Key: %s\n", keyFile)
	fmt.Printf("    Public Key:  %s (%s)\n", pubFile, kp.PublicKeyHex())
}

func handleIngest() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: unicompute ingest <filepath> [--publish] [--coordinator <url>]")
		return
	}

	var filePath string
	publish := false
	var coordArgs []string

	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--publish" {
			publish = true
		} else if arg == "--coordinator" && i+1 < len(args) {
			publish = true
			coordArgs = append(coordArgs, arg, args[i+1])
			i++
		} else if strings.HasPrefix(arg, "--coordinator=") {
			publish = true
			coordArgs = append(coordArgs, arg)
		} else if !strings.HasPrefix(arg, "-") && filePath == "" {
			filePath = arg
		} else {
			coordArgs = append(coordArgs, arg)
		}
	}

	if filePath == "" {
		fmt.Println("Usage: unicompute ingest <filepath> [--publish] [--coordinator <url>]")
		return
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}
	if len(data) == 0 {
		fmt.Printf("Error: file %s is empty (0 bytes). UniCompute requires at least 1 byte to ingest.\n", filePath)
		return
	}

	fmt.Printf("[*] Slicing %s (%d bytes) with FastCDC variable content-defined chunking...\n", filePath, len(data))
	cdc := storage.NewFastCDC()
	chunks := cdc.ChunkBytes(data)
	fmt.Printf("[+] Generated %d chunks (avg: %d bytes)\n", len(chunks), len(data)/max(1, len(chunks)))

	fmt.Println("[*] Applying Message-Locked Encryption (MLE AES-256-GCM)...")
	var chunkHashes [][]byte
	var chunkEntries []protocol.ChunkEntry

	for i, ch := range chunks {
		packed, key, cid, err := crypto.EncryptMLEPacked(ch.Data)
		if err != nil {
			fmt.Printf("MLE error on chunk %d: %v\n", i, err)
			return
		}
		_ = key
		_ = packed

		h, _ := hex.DecodeString(cid)
		chunkHashes = append(chunkHashes, h)

		chunkEntries = append(chunkEntries, protocol.ChunkEntry{
			ChunkCID:  cid,
			SegmentID: "seg_00",
			Offset:    ch.Offset,
			Length:    ch.Length,
		})
	}

	fmt.Println("[*] Constructing Merkle Chunk-to-Segment Manifest Tree...")
	tree, err := storage.NewMerkleTree(chunkHashes)
	if err != nil {
		fmt.Printf("Merkle tree error: %v\n", err)
		return
	}
	datasetCID := tree.RootHex()
	fmt.Printf("[+] Merkle Manifest Root CID: %s\n", datasetCID)

	fmt.Println("[*] Encoding into Cauchy Reed-Solomon RS(32, 80) Shards (2.5x expansion)...")
	codec, err := storage.DefaultCauchyCodec()
	if err != nil {
		fmt.Printf("RS codec error: %v\n", err)
		return
	}

	shards, err := codec.EncodeSegment(data)
	if err != nil {
		fmt.Printf("RS encoding error: %v\n", err)
		return
	}

	fmt.Printf("[+] Successfully generated %d erasure shards (32 Data, 48 Parity, 2 MiB each)\n", len(shards))
	fmt.Printf("[✓] Dataset successfully indexed! Content ID (CID): %s\n", datasetCID)

	coordURL := resolveCoordinatorURL("api/storage/manifest", coordArgs)

	if publish {
		fmt.Printf("[*] Registering dataset manifest with Coordinator (%s)...\n", coordURL)
		manifest := protocol.DatasetManifest{
			DatasetCID: datasetCID,
			Name:       filepath.Base(filePath),
			TotalBytes: int64(len(data)),
			Segments: []protocol.SegmentMetadata{
				{
					SegmentID:      "seg_" + datasetCID[:8],
					DatasetCID:     datasetCID,
					SegmentIndex:   0,
					RawSizeBytes:   int64(len(data)),
					DataShards:     32,
					ParityShards:   48,
					TotalShards:    80,
					RootMerkleHash: datasetCID,
				},
			},
			ChunkCount:   len(chunks),
			ChunkEntries: chunkEntries,
			CreatedAt:    time.Now(),
		}

		mBytes, _ := json.Marshal(manifest)
		resp, err := http.Post(coordURL, "application/json", bytes.NewReader(mBytes))
		if err != nil {
			fmt.Printf("[-] Failed to register manifest: %v\n", err)
		} else {
			defer resp.Body.Close()
			fmt.Printf("[+] Manifest registered with coordinator! Status: %s\n", resp.Status)
		}
	}
}

func handleSubmit() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: unicompute submit <wasm_or_script_file> [--dataset <cid>] [--tier <1|2|3>] [--coordinator <url>]")
		return
	}

	var filePath string
	tier := protocol.Tier1Wasm
	var datasetCID string
	var coordArgs []string

	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--tier" && i+1 < len(args) {
			t, _ := strconv.Atoi(args[i+1])
			tier = protocol.ExecutionTier(t)
			i++
		} else if strings.HasPrefix(arg, "--tier=") {
			t, _ := strconv.Atoi(strings.TrimPrefix(arg, "--tier="))
			tier = protocol.ExecutionTier(t)
		} else if arg == "--dataset" && i+1 < len(args) {
			datasetCID = args[i+1]
			i++
		} else if strings.HasPrefix(arg, "--dataset=") {
			datasetCID = strings.TrimPrefix(arg, "--dataset=")
		} else if arg == "--coordinator" && i+1 < len(args) {
			coordArgs = append(coordArgs, arg, args[i+1])
			i++
		} else if strings.HasPrefix(arg, "--coordinator=") {
			coordArgs = append(coordArgs, arg)
		} else if !strings.HasPrefix(arg, "-") && filePath == "" {
			filePath = arg
		} else {
			coordArgs = append(coordArgs, arg)
		}
	}

	if filePath == "" {
		fmt.Println("Usage: unicompute submit <wasm_or_script_file> [--dataset <cid>] [--tier <1|2|3>] [--coordinator <url>]")
		return
	}

	payload, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Error reading file %s: %v\n", filePath, err)
		return
	}

	taskID := fmt.Sprintf("task-%x", time.Now().UnixNano()%0xffffff)
	var datasets []string
	if datasetCID != "" {
		datasets = append(datasets, datasetCID)
	}

	manifest := protocol.Manifest{
		Version:          "1.0.0",
		TaskID:           taskID,
		Name:             filepath.Base(filePath),
		MinTier:          tier,
		Entrypoint:       filepath.Base(filePath),
		RequiredDatasets: datasets,
		FuelLimit:        50000000,
		MaxMemoryMB:      512,
		Args:             []string{},
		Env:              map[string]string{"MODE": "production"},
	}

	// Sign manifest if researcher key exists
	var sigHex, pubHex string
	if kp, err := crypto.LoadPrivateKeyFile("researcher.key"); err == nil {
		digest, _ := manifest.CanonicalDigest()
		sigHex = kp.SignHex(digest)
		pubHex = kp.PublicKeyHex()
		manifest.ResearcherPubKey = pubHex
	} else {
		// Generate ephemeral key for CLI submission
		kp, _ := crypto.GenerateKeyPair()
		digest, _ := manifest.CanonicalDigest()
		sigHex = kp.SignHex(digest)
		pubHex = kp.PublicKeyHex()
		manifest.ResearcherPubKey = pubHex
	}

	capsule := protocol.TaskCapsule{
		CapsuleID:        fmt.Sprintf("cap-%s", taskID),
		TaskID:           taskID,
		Name:             manifest.Name,
		MinTier:          manifest.MinTier,
		Entrypoint:       manifest.Entrypoint,
		CodePayload:      payload,
		RequiredDatasets: manifest.RequiredDatasets,
		FuelLimit:        manifest.FuelLimit,
		MaxMemoryMB:      manifest.MaxMemoryMB,
		Args:             manifest.Args,
		Env:              manifest.Env,
		Signature:        sigHex,
		ResearcherPubKey: pubHex,
	}

	coordURL := resolveCoordinatorURL("api/tasks/submit", coordArgs)
	fmt.Printf("[*] Submitting Task Capsule %s to Coordinator (%s)...\n", taskID, coordURL)

	reqBytes, _ := json.Marshal(capsule)
	resp, err := http.Post(coordURL, "application/json", bytes.NewReader(reqBytes))
	if err != nil {
		fmt.Printf("Submission failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("[+] Response [%s]: %s\n", resp.Status, string(body))
}

func handleStatus() {
	coordURL := resolveCoordinatorURL("api/cluster/status", os.Args[2:])
	resp, err := http.Get(coordURL)
	if err != nil {
		fmt.Printf("Failed to reach coordinator at %s: %v\n", coordURL, err)
		return
	}
	defer resp.Body.Close()

	var status web.ClusterStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		fmt.Printf("Failed to decode response: %v\n", err)
		return
	}

	fmt.Println("================================================================")
	fmt.Println(" UniCompute Cluster Telemetry & Fleet Status")
	fmt.Println("================================================================")
	fmt.Printf(" Nodes Online:         %d (%d Campus Labs, %d Laptops)\n", status.NodesOnline, status.LabNodes, status.LaptopNodes)
	fmt.Printf(" Tasks Running:        %d\n", status.TasksRunning)
	fmt.Printf(" Locality Hit Rate:    %.1f%% (Zero Network Fetch)\n", status.LocalityRate*100)
	fmt.Println("----------------------------------------------------------------")
	fmt.Printf(" %-16s %-16s %-8s %-16s %-8s\n", "NODE ID", "ZONE", "TIER", "LOCALITY", "CREDIT")
	fmt.Println("----------------------------------------------------------------")
	for _, n := range status.Fleet {
		fmt.Printf(" %-16s %-16s Tier %-3d %-16s %.3f\n", n.ID, n.Zone, n.Tier, n.Locality, n.Credit)
	}
	fmt.Println("================================================================")
}

func resolveCoordinatorURL(subpath string, args []string) string {
	base := "http://localhost:8443"
	if env := os.Getenv("UNICOMPUTE_COORDINATOR"); env != "" {
		base = env
	}

	for i := 0; i < len(args); i++ {
		if args[i] == "--coordinator" && i+1 < len(args) {
			base = args[i+1]
			break
		}
		if strings.HasPrefix(args[i], "--coordinator=") {
			base = strings.TrimPrefix(args[i], "--coordinator=")
			break
		}
	}

	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	subpath = strings.TrimLeft(subpath, "/")
	return base + "/" + subpath
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
