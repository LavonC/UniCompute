package tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"unicompute/pkg/crypto"
	"unicompute/pkg/protocol"
	"unicompute/pkg/scheduler"
	"unicompute/pkg/storage"
	"unicompute/pkg/verification"
)

func TestMerkleTreeEdgeCases(t *testing.T) {
	// 1. Empty leaves must fail
	_, errEmpty := storage.NewMerkleTree([][]byte{})
	if errEmpty == nil {
		t.Errorf("Expected error on empty leaves, got nil")
	}

	// 2. Single leaf tree
	singleLeaf := [][]byte{[]byte("Single isolated chunk CID in genomic partition")}
	tree1, err1 := storage.NewMerkleTree(singleLeaf)
	if err1 != nil {
		t.Fatalf("Single leaf tree failed: %v", err1)
	}
	proof1, errP1 := tree1.GenerateProof(0)
	if errP1 != nil {
		t.Fatalf("Single leaf proof failed: %v", errP1)
	}
	if !storage.VerifyMerkleProof(singleLeaf[0], proof1, tree1.Root) {
		t.Errorf("Valid single leaf proof failed verification")
	}
	// Tampered leaf
	if storage.VerifyMerkleProof([]byte("tampered"), proof1, tree1.Root) {
		t.Errorf("Tampered leaf unexpectedly verified in single leaf tree")
	}

	// 3. Out-of-bounds leaf index
	if _, err := tree1.GenerateProof(-1); err == nil {
		t.Errorf("Expected error on negative leaf index, got nil")
	}
	if _, err := tree1.GenerateProof(1); err == nil {
		t.Errorf("Expected error on index 1 with 1 leaf, got nil")
	}

	// 4. Odd and prime leaf counts: 3, 5, 7, 9, 17, 33
	oddCounts := []int{3, 5, 7, 9, 17, 33}
	for _, count := range oddCounts {
		leaves := make([][]byte, count)
		for i := 0; i < count; i++ {
			leaf := make([]byte, 32)
			_, _ = rand.Read(leaf)
			leaves[i] = leaf
		}

		tree, err := storage.NewMerkleTree(leaves)
		if err != nil {
			t.Fatalf("Failed to build Merkle tree with %d leaves: %v", count, err)
		}

		// Verify inclusion proof for EVERY leaf
		for i := 0; i < count; i++ {
			proof, err := tree.GenerateProof(i)
			if err != nil {
				t.Fatalf("Failed to generate proof for leaf %d/%d: %v", i, count, err)
			}
			if !storage.VerifyMerkleProof(leaves[i], proof, tree.Root) {
				t.Errorf("Proof failed for leaf %d in %d-leaf tree", i, count)
			}

			// Tampered leaf must fail
			tampered := append([]byte(nil), leaves[i]...)
			tampered[0] ^= 0xff
			if storage.VerifyMerkleProof(tampered, proof, tree.Root) {
				t.Errorf("Tampered leaf unexpectedly passed for leaf %d in %d-leaf tree", i, count)
			}
		}
	}

	// 5. VerifyMerkleProof nil / malformed proof
	if storage.VerifyMerkleProof([]byte("data"), nil, []byte("root")) {
		t.Errorf("Nil proof unexpectedly returned true")
	}
	malformedProof := &storage.MerkleProof{
		LeafIndex: 0,
		Siblings:  [][]byte{[]byte("sib1")},
		PathBits:  []bool{}, // length mismatch
	}
	if storage.VerifyMerkleProof([]byte("data"), malformedProof, []byte("root")) {
		t.Errorf("Malformed proof with mismatched lengths unexpectedly returned true")
	}
}

func TestFastCDCEdgeCases(t *testing.T) {
	cdc := storage.NewFastCDC()

	// 1. Zero bytes input: empty slice
	emptyChunks := cdc.ChunkBytes([]byte{})
	if len(emptyChunks) != 0 {
		t.Errorf("Expected 0 chunks for empty input, got %d", len(emptyChunks))
	}

	// 2. Small data sizes below MinChunkSize (8 KiB)
	smallSizes := []int{1, 10, 500, 4096, 8191}
	for _, sz := range smallSizes {
		data := make([]byte, sz)
		_, _ = rand.Read(data)
		chunks := cdc.ChunkBytes(data)
		if len(chunks) != 1 {
			t.Errorf("Expected exactly 1 chunk for size %d, got %d", sz, len(chunks))
		}
		if len(chunks[0].Data) != sz {
			t.Errorf("Chunk length %d != original size %d", len(chunks[0].Data), sz)
		}
		if !bytes.Equal(chunks[0].Data, data) {
			t.Errorf("Chunk data mismatch for size %d", sz)
		}
	}

	// 3. ChunkReader matches ChunkBytes
	testData := make([]byte, 65536)
	_, _ = rand.Read(testData)
	chunksDirect := cdc.ChunkBytes(testData)
	chunksReader, errR := cdc.ChunkReader(bytes.NewReader(testData))
	if errR != nil {
		t.Fatalf("ChunkReader failed: %v", errR)
	}
	if len(chunksDirect) != len(chunksReader) {
		t.Fatalf("Chunk count mismatch: direct=%d, reader=%d", len(chunksDirect), len(chunksReader))
	}
	for i := range chunksDirect {
		if !bytes.Equal(chunksDirect[i].Data, chunksReader[i].Data) {
			t.Errorf("Chunk %d data mismatch between direct and reader", i)
		}
	}

	// 4. Custom boundaries with zero or negative args
	customCDC := storage.NewFastCDCCustom(-10, 0, 0)
	cChunks := customCDC.ChunkBytes(testData)
	if len(cChunks) == 0 {
		t.Errorf("Custom CDC returned 0 chunks")
	}
}

func TestCauchyReedSolomonRS3280EdgeCases(t *testing.T) {
	codec, err := storage.DefaultCauchyCodec()
	if err != nil {
		t.Fatalf("DefaultCauchyCodec failed: %v", err)
	}

	// 1. Empty data
	_, errEmpty := codec.EncodeSegment([]byte{})
	if errEmpty == nil {
		t.Errorf("Expected error on empty data encoding, got nil")
	}

	// 2. Small inputs: 1, 10, 31, 32, 100 bytes
	smallSizes := []int64{1, 10, 31, 32, 100}
	for _, sz := range smallSizes {
		data := make([]byte, sz)
		_, _ = rand.Read(data)
		shards, errEnc := codec.EncodeSegment(data)
		if errEnc != nil {
			t.Fatalf("EncodeSegment failed for size %d: %v", sz, errEnc)
		}
		if len(shards) != 80 {
			t.Fatalf("Expected 80 shards, got %d", len(shards))
		}

		// Reconstruct with 32 shards surviving (wipe 48 parity shards)
		matrix := make([][]byte, 80)
		for i := 0; i < 32; i++ {
			matrix[i] = append([]byte(nil), shards[i].Data...)
		}
		reconstructed, errDec := codec.DecodeSegment(matrix, sz)
		if errDec != nil {
			t.Fatalf("DecodeSegment failed for size %d: %v", sz, errDec)
		}
		if !bytes.Equal(reconstructed, data) {
			t.Errorf("Reconstructed data mismatch for size %d", sz)
		}
	}

	// 3. DecodeSegment with wrong shard slice length
	_, errLen := codec.DecodeSegment(make([][]byte, 79), 100)
	if errLen == nil {
		t.Errorf("Expected error on shard slice length 79 != 80, got nil")
	}

	// 4. ReconstructMissingShards with wrong shard slice length
	errRecLen := codec.ReconstructMissingShards(make([][]byte, 50))
	if errRecLen == nil {
		t.Errorf("Expected error on ReconstructMissingShards length 50 != 80, got nil")
	}

	// 5. NewErasureCodec invalid arguments
	if _, err := storage.NewErasureCodec(0, 48); err == nil {
		t.Errorf("Expected error on 0 data shards, got nil")
	}
	if _, err := storage.NewErasureCodec(32, 0); err == nil {
		t.Errorf("Expected error on 0 parity shards, got nil")
	}
	if _, err := storage.NewErasureCodec(150, 150); err == nil {
		t.Errorf("Expected error on 300 total shards (> 256 in GF(2^8)), got nil")
	}
}

func TestTwoTierVaultEdgeCases(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "vault-edge-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Small vault: 1000 bytes quota, 200 bytes RAM cache
	vault, err := storage.NewVault(tempDir, 1000, 200)
	if err != nil {
		t.Fatalf("NewVault failed: %v", err)
	}

	// 1. Read non-existent shard and segment
	if _, err := vault.ReadShard("missing_seg", 0); err != storage.ErrNotFound {
		t.Errorf("Expected ErrNotFound on missing shard, got: %v", err)
	}
	if _, _, err := vault.ReadSegment("missing_seg"); err != storage.ErrNotFound {
		t.Errorf("Expected ErrNotFound on missing segment, got: %v", err)
	}

	// 2. HasSegmentLocality on missing
	if loc := vault.HasSegmentLocality("missing_seg"); loc != "Cold" {
		t.Errorf("Expected Cold locality, got: %s", loc)
	}

	// 3. Store shard exceeding quota
	oversized := make([]byte, 1001)
	if _, err := vault.StoreShard("seg_large", 0, oversized); err != storage.ErrQuotaExceeded {
		t.Errorf("Expected ErrQuotaExceeded on oversized shard, got: %v", err)
	}
	if err := vault.StoreSegment("seg_large", oversized); err != storage.ErrQuotaExceeded {
		t.Errorf("Expected ErrQuotaExceeded on oversized segment, got: %v", err)
	}

	// 4. Overwrite existing shard: ensure usedBytes does NOT double-count
	shardData1 := []byte("Initial shard data 50 bytes......................")
	_, errS1 := vault.StoreShard("seg_1", 0, shardData1)
	if errS1 != nil {
		t.Fatalf("StoreShard failed: %v", errS1)
	}
	used1, quota, shardsCount, _ := vault.GetStats()
	if quota != 1000 || shardsCount != 1 {
		t.Errorf("Unexpected stats: quota=%d, shards=%d", quota, shardsCount)
	}

	// Overwrite same shard with new content of same length
	shardData2 := []byte("Updated shard data 50 bytes......................")
	_, errS2 := vault.StoreShard("seg_1", 0, shardData2)
	if errS2 != nil {
		t.Fatalf("StoreShard overwrite failed: %v", errS2)
	}
	used2, _, shardsCount2, _ := vault.GetStats()
	if used2 != used1 {
		t.Errorf("usedBytes double-counted on shard overwrite: used1=%d, used2=%d", used1, used2)
	}
	if shardsCount2 != 1 {
		t.Errorf("Shard count increased on overwrite: %d", shardsCount2)
	}

	// 5. Overwrite existing segment: ensure usedBytes does NOT double-count
	segData1 := []byte("Segment data 60 bytes.......................................")
	errSeg1 := vault.StoreSegment("seg_1", segData1)
	if errSeg1 != nil {
		t.Fatalf("StoreSegment failed: %v", errSeg1)
	}
	usedSeg1, _, _, segsCount1 := vault.GetStats()
	if segsCount1 != 1 {
		t.Errorf("Expected segment count 1, got %d", segsCount1)
	}

	segData2 := []byte("Updated segment data 60 bytes...............................")
	errSeg2 := vault.StoreSegment("seg_1", segData2)
	if errSeg2 != nil {
		t.Fatalf("StoreSegment overwrite failed: %v", errSeg2)
	}
	usedSeg2, _, _, segsCount2 := vault.GetStats()
	if usedSeg2 != usedSeg1 {
		t.Errorf("usedBytes double-counted on segment overwrite: used1=%d, used2=%d", usedSeg1, usedSeg2)
	}
	if segsCount2 != 1 {
		t.Errorf("Segment count increased on overwrite: %d", segsCount2)
	}

	// 6. TierRCache LRU eviction
	cache := storage.NewTierRCache(100) // 100 byte capacity
	cache.Put("item1", make([]byte, 60))
	cache.Put("item2", make([]byte, 60)) // Evicts item1 (60 + 60 = 120 > 100)

	if cache.Has("item1") {
		t.Errorf("Expected item1 to be evicted from TierRCache")
	}
	if !cache.Has("item2") {
		t.Errorf("Expected item2 to be present in TierRCache")
	}

	// Update existing item with larger value
	cache.Put("item2", make([]byte, 80))
	if !cache.Has("item2") {
		t.Errorf("Expected item2 to be retained after update")
	}
}

func TestRepairEngineEdgeCases(t *testing.T) {
	codec, _ := storage.DefaultCauchyCodec()
	re := storage.NewRepairEngine(codec)

	// 1. ExecuteBatchedRepair with 32 surviving shards
	data := make([]byte, 32*1024)
	_, _ = rand.Read(data)
	shards, err := codec.EncodeSegment(data)
	if err != nil {
		t.Fatalf("EncodeSegment failed: %v", err)
	}

	surviving := make(map[int][]byte)
	for i := 0; i < 32; i++ {
		surviving[i] = shards[i].Data
	}

	allShards, errRepair := re.ExecuteBatchedRepair(surviving, int64(len(data)))
	if errRepair != nil {
		t.Fatalf("ExecuteBatchedRepair failed: %v", errRepair)
	}
	if len(allShards) != 80 {
		t.Fatalf("Expected 80 shards from repair, got %d", len(allShards))
	}
	// Verify missing parity shards (e.g. 32 to 79) were correctly regenerated
	for i := 32; i < 80; i++ {
		if !bytes.Equal(allShards[i], shards[i].Data) {
			t.Errorf("Regenerated parity shard %d mismatch", i)
		}
	}

	// 2. Insufficient shards (< 32)
	underflowSurviving := make(map[int][]byte)
	for i := 0; i < 31; i++ {
		underflowSurviving[i] = shards[i].Data
	}
	_, errUnderflow := re.ExecuteBatchedRepair(underflowSurviving, int64(len(data)))
	if errUnderflow == nil {
		t.Errorf("Expected error with 31 surviving shards, got nil")
	}

	// 3. Out-of-bounds index in surviving map does not panic
	outOfBoundsSurviving := make(map[int][]byte)
	for i := 0; i < 32; i++ {
		outOfBoundsSurviving[i] = shards[i].Data
	}
	outOfBoundsSurviving[999] = []byte("ignored")
	outOfBoundsSurviving[-5] = []byte("ignored")
	if _, err := re.ExecuteBatchedRepair(outOfBoundsSurviving, int64(len(data))); err != nil {
		t.Errorf("ExecuteBatchedRepair failed with out-of-bounds keys: %v", err)
	}

	// 4. CheckSegmentHealth boundary values
	testHealth := func(online int, expectRepair bool) {
		meta := &protocol.SegmentMetadata{
			SegmentID: "seg_test",
			Shards:    make([]protocol.ShardMetadata, 80),
		}
		for i := 0; i < online; i++ {
			meta.Shards[i].Online = true
		}
		should, _ := re.CheckSegmentHealth(meta)
		if should != expectRepair {
			t.Errorf("CheckSegmentHealth(%d online): got repair=%v, want %v", online, should, expectRepair)
		}
	}

	testHealth(80, false) // healthy
	testHealth(49, false) // healthy
	testHealth(48, true)  // repair threshold boundary
	testHealth(40, true)  // repair triggered
	testHealth(32, true)  // reconstruction floor boundary
	testHealth(31, false) // below floor: fatal, cannot repair
	testHealth(0, false)  // fatal

	// 5. PlanShardPlacement with empty node list
	_, errNoNodes := storage.PlanShardPlacement([]*protocol.Node{}, "seg_1")
	if errNoNodes == nil {
		t.Errorf("Expected error on empty node list, got nil")
	}
}

func TestMLEEdgeCases(t *testing.T) {
	// 1. Empty plaintext
	emptyPlaintext := []byte{}
	packed, key, cid, err := crypto.EncryptMLEPacked(emptyPlaintext)
	if err != nil {
		t.Fatalf("EncryptMLEPacked failed on empty plaintext: %v", err)
	}
	if cid == "" {
		t.Errorf("Empty CID on empty plaintext")
	}
	decrypted, errDec := crypto.DecryptMLEPacked(packed, key)
	if errDec != nil {
		t.Fatalf("DecryptMLEPacked failed on empty plaintext: %v", errDec)
	}
	if len(decrypted) != 0 {
		t.Errorf("Expected 0 bytes decrypted, got %d", len(decrypted))
	}

	// 2. Short ciphertext (< 28 bytes)
	_, errShort := crypto.DecryptMLEPacked([]byte("short"), key)
	if errShort == nil {
		t.Errorf("Expected error on short ciphertext, got nil")
	}

	// 3. Wrong key size
	_, errWrongKey := crypto.DecryptMLEPacked(packed, []byte("short-key"))
	if errWrongKey == nil {
		t.Errorf("Expected error on invalid key size, got nil")
	}

	// 4. Corrupted nonce
	corruptedNonce := append([]byte(nil), packed...)
	corruptedNonce[0] ^= 0xff
	_, errCorruptNonce := crypto.DecryptMLEPacked(corruptedNonce, key)
	if errCorruptNonce == nil {
		t.Errorf("Expected decryption error on corrupted nonce, got nil")
	}
}

func TestCryptoKeyFileIO(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "key-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	keyPath := filepath.Join(tempDir, "test.key")
	if err := kp.SavePrivateKeyFile(keyPath); err != nil {
		t.Fatalf("SavePrivateKeyFile failed: %v", err)
	}

	loadedKP, err := crypto.LoadPrivateKeyFile(keyPath)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFile failed: %v", err)
	}

	if kp.PublicKeyHex() != loadedKP.PublicKeyHex() {
		t.Errorf("Loaded public key mismatch")
	}

	// Test signing with loaded key
	msg := []byte("UniCompute signed attestation test")
	sig := loadedKP.Sign(msg)
	if !crypto.VerifySignature(kp.PublicKey, msg, sig) {
		t.Errorf("Signature created by loaded key failed verification")
	}

	// Test loading invalid key file
	invalidPath := filepath.Join(tempDir, "invalid.key")
	_ = os.WriteFile(invalidPath, []byte("too short"), 0600)
	if _, err := crypto.LoadPrivateKeyFile(invalidPath); err == nil {
		t.Errorf("Expected error on truncated key file, got nil")
	}

	// VerifySignatureHex with invalid hex
	if _, err := crypto.VerifySignatureHex("invalid-hex", msg, kp.SignHex(msg)); err == nil {
		t.Errorf("Expected error on invalid pubkey hex, got nil")
	}
	if _, err := crypto.VerifySignatureHex(kp.PublicKeyHex(), msg, "invalid-hex"); err == nil {
		t.Errorf("Expected error on invalid sig hex, got nil")
	}
}

func TestVerificationReceiptEdgeCases(t *testing.T) {
	// 1. Nil receipt
	if _, err := verification.VerifyExecutionReceipt(nil); err == nil {
		t.Errorf("Expected error on nil receipt, got nil")
	}

	// 2. Missing signature
	rNoSig := &protocol.ExecutionReceipt{WorkerPubKey: "pub"}
	if _, err := verification.VerifyExecutionReceipt(rNoSig); err == nil {
		t.Errorf("Expected error on missing signature, got nil")
	}

	// 3. Missing pubkey
	rNoPub := &protocol.ExecutionReceipt{Signature: "sig"}
	if _, err := verification.VerifyExecutionReceipt(rNoPub); err == nil {
		t.Errorf("Expected error on missing pubkey, got nil")
	}

	// 4. Invalid pubkey hex
	rBadHex := &protocol.ExecutionReceipt{Signature: "aabb", WorkerPubKey: "not-hex"}
	if _, err := verification.VerifyExecutionReceipt(rBadHex); err == nil {
		t.Errorf("Expected error on malformed hex, got nil")
	}
}

func TestSchedulerEdgeCases(t *testing.T) {
	idx := scheduler.NewContentLocalityIndex()
	pac := scheduler.NewPACManScheduler(idx)

	task := &protocol.TaskCapsule{
		TaskID:      "task-edge",
		MinTier:     protocol.Tier1Wasm,
		MaxMemoryMB: 512,
	}

	// 1. Empty node list
	if _, _, err := pac.ScheduleTask(context.Background(), task, []*protocol.Node{}); err != scheduler.ErrNoEligibleNodes {
		t.Errorf("Expected ErrNoEligibleNodes on empty node list, got: %v", err)
	}

	// 2. All nodes offline
	offlineNode := &protocol.Node{ID: "node-off", Online: false, MaxTier: protocol.Tier1Wasm}
	if _, _, err := pac.ScheduleTask(context.Background(), task, []*protocol.Node{offlineNode}); err != scheduler.ErrNoEligibleNodes {
		t.Errorf("Expected ErrNoEligibleNodes on all-offline node list, got: %v", err)
	}

	// 3. Context cancelled during delay scheduling (node has L < 1.0)
	coldNode := &protocol.Node{ID: "node-cold", Online: true, MaxTier: protocol.Tier1Wasm, CreditScore: 0.8}
	taskWithDataset := &protocol.TaskCapsule{
		TaskID:           "task-cold",
		MinTier:          protocol.Tier1Wasm,
		RequiredDatasets: []string{"dataset-not-cached"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	_, _, errCtx := pac.ScheduleTask(ctx, taskWithDataset, []*protocol.Node{coldNode})
	if errCtx != context.Canceled {
		t.Errorf("Expected context.Canceled, got: %v", errCtx)
	}

	// 4. ContentLocalityIndex RemoveNode
	idx.RegisterDatasetCache("cid-1", "node-1", scheduler.LocalityTierR, 100, 100)
	tier, cached, _ := idx.GetLocality("cid-1", "node-1")
	if tier != scheduler.LocalityTierR || cached != 100 {
		t.Errorf("Expected Tier_R with 100 cached bytes, got %s, %d", tier, cached)
	}
	idx.RemoveNode("node-1")
	tierAfter, cachedAfter, _ := idx.GetLocality("cid-1", "node-1")
	if tierAfter != scheduler.LocalityCold || cachedAfter != 0 {
		t.Errorf("Expected Cold after RemoveNode, got %s, %d", tierAfter, cachedAfter)
	}
}

func TestBerlekampWelchStripeAuditEdgeCases(t *testing.T) {
	codec, err := storage.DefaultCauchyCodec()
	if err != nil {
		t.Fatalf("DefaultCauchyCodec failed: %v", err)
	}

	data := make([]byte, 32*1024)
	_, _ = rand.Read(data)

	shards, err := codec.EncodeSegment(data)
	if err != nil {
		t.Fatalf("EncodeSegment failed: %v", err)
	}

	sampleLen := len(shards[0].Data)
	stripeSamples := make([][]byte, 80)
	for i := 0; i < 80; i++ {
		stripeSamples[i] = make([]byte, sampleLen)
		copy(stripeSamples[i], shards[i].Data)
	}

	// Attack case: data shard 15 is corrupted
	samplesShard15 := make([][]byte, 80)
	for i := 0; i < 80; i++ {
		samplesShard15[i] = make([]byte, sampleLen)
		copy(samplesShard15[i], stripeSamples[i])
	}
	samplesShard15[15][0] ^= 0xff

	corrupted15, err15 := storage.BerlekampWelchStripeAudit(codec, samplesShard15)
	if err15 != nil {
		t.Fatalf("BerlekampWelchStripeAudit failed with shard 15 corrupt: %v", err15)
	}
	if len(corrupted15) != 1 || corrupted15[0] != 15 {
		t.Errorf("Expected only shard [15] to be flagged as corrupt, got: %v", corrupted15)
	}

	// Attack case 2: Truncated/malformed shard length (shard 20 has 500 bytes instead of sampleLen)
	samplesTruncated := make([][]byte, 80)
	for i := 0; i < 80; i++ {
		samplesTruncated[i] = make([]byte, sampleLen)
		copy(samplesTruncated[i], stripeSamples[i])
	}
	samplesTruncated[20] = make([]byte, sampleLen/2) // malformed length!

	corruptedTrunc, errTrunc := storage.BerlekampWelchStripeAudit(codec, samplesTruncated)
	if errTrunc != nil {
		t.Fatalf("BerlekampWelchStripeAudit failed with truncated shard 20: %v", errTrunc)
	}
	if len(corruptedTrunc) != 1 || corruptedTrunc[0] != 20 {
		t.Errorf("Expected truncated shard [20] to be flagged as corrupt, got: %v", corruptedTrunc)
	}

	// Attack case 3: Scattered corruptions across data and parity (shard 22 and shard 68)
	samplesScattered := make([][]byte, 80)
	for i := 0; i < 80; i++ {
		samplesScattered[i] = make([]byte, sampleLen)
		copy(samplesScattered[i], stripeSamples[i])
	}
	samplesScattered[22][5] ^= 0x77
	samplesScattered[68][5] ^= 0x88

	corruptedScattered, errScattered := storage.BerlekampWelchStripeAudit(codec, samplesScattered)
	if errScattered != nil {
		t.Fatalf("BerlekampWelchStripeAudit failed with scattered corruptions: %v", errScattered)
	}
	if len(corruptedScattered) != 2 || corruptedScattered[0] != 22 || corruptedScattered[1] != 68 {
		t.Errorf("Expected shards [22, 68] to be flagged as corrupt, got: %v", corruptedScattered)
	}
}

func TestTwoTierVaultDeleteAndDefensiveCopy(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "vault-del-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	vault, err := storage.NewVault(tempDir, 10000, 500)
	if err != nil {
		t.Fatalf("NewVault failed: %v", err)
	}

	// 1. Store shard, verify stats, then delete shard
	shardPayload := []byte("Shard 100 bytes data................................................................................")
	if _, err := vault.StoreShard("seg_del", 3, shardPayload); err != nil {
		t.Fatalf("StoreShard failed: %v", err)
	}
	usedBefore, _, shardsBefore, _ := vault.GetStats()
	if shardsBefore != 1 || usedBefore != int64(len(shardPayload)) {
		t.Errorf("Unexpected stats before delete: used=%d, shards=%d", usedBefore, shardsBefore)
	}

	// Delete shard
	if err := vault.DeleteShard("seg_del", 3); err != nil {
		t.Fatalf("DeleteShard failed: %v", err)
	}
	usedAfter, _, shardsAfter, _ := vault.GetStats()
	if shardsAfter != 0 || usedAfter != 0 {
		t.Errorf("Stats not decremented after DeleteShard: used=%d, shards=%d", usedAfter, shardsAfter)
	}
	// Deleting again should return ErrNotFound
	if err := vault.DeleteShard("seg_del", 3); err != storage.ErrNotFound {
		t.Errorf("Expected ErrNotFound on re-delete, got: %v", err)
	}

	// 2. Store segment, verify in Tier R and Tier L, then delete segment
	segPayload := []byte("Segment data 80 bytes...........................................................")
	if err := vault.StoreSegment("seg_full", segPayload); err != nil {
		t.Fatalf("StoreSegment failed: %v", err)
	}
	if loc := vault.HasSegmentLocality("seg_full"); loc != "Tier_R" {
		t.Errorf("Expected Tier_R locality, got: %s", loc)
	}

	// Delete segment
	if err := vault.DeleteSegment("seg_full"); err != nil {
		t.Fatalf("DeleteSegment failed: %v", err)
	}
	usedSegAfter, _, _, segsAfter := vault.GetStats()
	if segsAfter != 0 || usedSegAfter != 0 {
		t.Errorf("Stats not decremented after DeleteSegment: used=%d, segs=%d", usedSegAfter, segsAfter)
	}
	if loc := vault.HasSegmentLocality("seg_full"); loc != "Cold" {
		t.Errorf("Expected Cold after DeleteSegment, got: %s", loc)
	}
	if err := vault.DeleteSegment("seg_full"); err != storage.ErrNotFound {
		t.Errorf("Expected ErrNotFound on re-delete segment, got: %v", err)
	}

	// 3. TierRCache oversized item rejection (should not evict existing items)
	cache := storage.NewTierRCache(200) // 200 bytes max
	cache.Put("itemA", make([]byte, 100))
	cache.Put("itemB", make([]byte, 80)) // total = 180 <= 200

	// Try putting 300 bytes (> 200 maxBytes)
	cache.Put("oversized", make([]byte, 300))
	if cache.Has("oversized") {
		t.Errorf("Oversized item unexpectedly stored in TierRCache")
	}
	if !cache.Has("itemA") || !cache.Has("itemB") {
		t.Errorf("Existing items unexpectedly evicted by rejected oversized item")
	}

	// 4. Defensive copy test: mutating input slice after Put does not corrupt cached data
	mutableData := []byte("pure original data")
	cache.Put("immutable_test", mutableData)
	mutableData[0] = 'X' // mutate source slice
	cachedVal, ok := cache.Get("immutable_test")
	if !ok || cachedVal[0] == 'X' {
		t.Errorf("Cached value was mutated through original slice! Defensive copy failed.")
	}
}

func TestRepairEngineValidationEdgeCases(t *testing.T) {
	codec, _ := storage.DefaultCauchyCodec()
	re := storage.NewRepairEngine(codec)

	data := make([]byte, 32*1024)
	_, _ = rand.Read(data)
	shards, _ := codec.EncodeSegment(data)

	// Case 1: 32 entries total, but 3 entries are out-of-bounds (valid count = 29 < 32)
	survivingOOB := make(map[int][]byte)
	for i := 0; i < 29; i++ {
		survivingOOB[i] = shards[i].Data
	}
	survivingOOB[999] = []byte("oob1")
	survivingOOB[80] = []byte("oob2")
	survivingOOB[-1] = []byte("oob3")

	_, errOOB := re.ExecuteBatchedRepair(survivingOOB, int64(len(data)))
	if errOOB == nil || !strings.Contains(errOOB.Error(), "insufficient valid surviving shards") {
		t.Errorf("Expected 'insufficient valid surviving shards' error, got: %v", errOOB)
	}

	// Case 2: Inconsistent shard sizes
	survivingMismatched := make(map[int][]byte)
	for i := 0; i < 32; i++ {
		survivingMismatched[i] = shards[i].Data
	}
	survivingMismatched[10] = make([]byte, 500) // corrupted length

	_, errMismatch := re.ExecuteBatchedRepair(survivingMismatched, int64(len(data)))
	if errMismatch == nil || !strings.Contains(errMismatch.Error(), "inconsistent shard size") {
		t.Errorf("Expected 'inconsistent shard size' error, got: %v", errMismatch)
	}
}

func TestCheckSegmentHealthNil(t *testing.T) {
	codec, _ := storage.DefaultCauchyCodec()
	re := storage.NewRepairEngine(codec)

	shouldRepair, reason := re.CheckSegmentHealth(nil)
	if shouldRepair || !strings.Contains(reason, "nil") {
		t.Errorf("Expected false and nil reason on nil segment, got %v: %s", shouldRepair, reason)
	}
}

func TestPoRChallengeWithIndex(t *testing.T) {
	chal := storage.GeneratePoRChallengeWithIndex("node-42", "seg-abc-shard-15", "seg-abc", 15)
	if chal.ShardIndex != 15 {
		t.Errorf("Expected ShardIndex 15, got %d", chal.ShardIndex)
	}
	if chal.SegmentID != "seg-abc" || chal.NodeID != "node-42" {
		t.Errorf("Unexpected challenge metadata: %+v", chal)
	}
}
