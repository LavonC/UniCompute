package tests

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"

	"unicompute/pkg/protocol"
	"unicompute/pkg/storage"
)

func TestFastCDCChunking(t *testing.T) {
	// Generate 128 KiB pseudo-random data
	data := make([]byte, 128*1024)
	_, _ = rand.Read(data)

	cdc := storage.NewFastCDC()
	chunks := cdc.ChunkBytes(data)

	if len(chunks) == 0 {
		t.Fatalf("FastCDC returned 0 chunks")
	}

	// Verify all chunks meet min size (except possibly last chunk)
	var reconstructed []byte
	for i, ch := range chunks {
		if i < len(chunks)-1 && len(ch.Data) < storage.DefaultMinChunkSize {
			t.Errorf("Chunk %d size %d < min chunk size %d", i, len(ch.Data), storage.DefaultMinChunkSize)
		}
		if len(ch.Data) > storage.DefaultMaxChunkSize {
			t.Errorf("Chunk %d size %d > max chunk size %d", i, len(ch.Data), storage.DefaultMaxChunkSize)
		}
		reconstructed = append(reconstructed, ch.Data...)
	}

	if !bytes.Equal(reconstructed, data) {
		t.Errorf("Reconstructed data does not match original data")
	}
}

func TestMerkleTreeAndProofs(t *testing.T) {
	numLeaves := 16
	leaves := make([][]byte, numLeaves)
	for i := 0; i < numLeaves; i++ {
		leaf := make([]byte, 32)
		_, _ = rand.Read(leaf)
		leaves[i] = leaf
	}

	tree, err := storage.NewMerkleTree(leaves)
	if err != nil {
		t.Fatalf("Failed to create Merkle tree: %v", err)
	}

	if len(tree.Root) != 32 {
		t.Errorf("Expected 32-byte root hash, got %d", len(tree.Root))
	}

	// Test inclusion proof for all leaves
	for i := 0; i < numLeaves; i++ {
		proof, err := tree.GenerateProof(i)
		if err != nil {
			t.Fatalf("Failed to generate proof for leaf %d: %v", i, err)
		}

		if !storage.VerifyMerkleProof(leaves[i], proof, tree.Root) {
			t.Errorf("Valid Merkle proof failed for leaf %d", i)
		}

		// Tampered leaf
		tampered := make([]byte, 32)
		copy(tampered, leaves[i])
		tampered[0] ^= 0xff
		if storage.VerifyMerkleProof(tampered, proof, tree.Root) {
			t.Errorf("Tampered leaf unexpectedly passed Merkle verification")
		}
	}
}

func TestCauchyReedSolomonRS3280(t *testing.T) {
	codec, err := storage.DefaultCauchyCodec() // RS(k=32, n=80)
	if err != nil {
		t.Fatalf("Failed to create RS(32, 80) codec: %v", err)
	}

	// 1 MiB test data segment
	origSize := int64(1024 * 1024)
	data := make([]byte, origSize)
	_, _ = rand.Read(data)

	shards, err := codec.EncodeSegment(data)
	if err != nil {
		t.Fatalf("RS encode failed: %v", err)
	}

	if len(shards) != 80 {
		t.Fatalf("Expected 80 shards (32 data + 48 parity), got %d", len(shards))
	}

	// 1. Reconstruct with zero loss
	matrix := make([][]byte, 80)
	for i := 0; i < 80; i++ {
		matrix[i] = shards[i].Data
	}

	reconstructed, err := codec.DecodeSegment(matrix, origSize)
	if err != nil {
		t.Fatalf("Reconstruction with zero loss failed: %v", err)
	}
	if !bytes.Equal(reconstructed, data) {
		t.Errorf("Reconstructed data does not match original")
	}

	// 2. Reconstruct with 48 lost shards (simulating massive diurnal laptop churn: 32/80 surviving)
	matrixLoss48 := make([][]byte, 80)
	// Retain only 32 data shards, wipe all 48 parity shards
	for i := 0; i < 32; i++ {
		matrixLoss48[i] = make([]byte, len(shards[i].Data))
		copy(matrixLoss48[i], shards[i].Data)
	}
	for i := 32; i < 80; i++ {
		matrixLoss48[i] = nil // Lost shards
	}

	reconstructed48, err := codec.DecodeSegment(matrixLoss48, origSize)
	if err != nil {
		t.Fatalf("Reconstruction with 48 lost shards failed: %v", err)
	}
	if !bytes.Equal(reconstructed48, data) {
		t.Errorf("Reconstructed data after 48-shard loss does not match original")
	}

	// 3. Reconstruct with 32 random surviving shards across data and parity
	matrixMixed := make([][]byte, 80)
	// Pick 16 data shards and 16 parity shards
	for i := 0; i < 16; i++ {
		matrixMixed[i] = shards[i].Data
	}
	for i := 32; i < 48; i++ {
		matrixMixed[i] = shards[i].Data
	}
	// Total surviving = 32
	reconstructedMixed, err := codec.DecodeSegment(matrixMixed, origSize)
	if err != nil {
		t.Fatalf("Reconstruction with mixed 32 shards failed: %v", err)
	}
	if !bytes.Equal(reconstructedMixed, data) {
		t.Errorf("Reconstructed data after mixed 32-shard loss does not match original")
	}

	// 4. Boundary Failure: 31 surviving shards (below k=32 floor) MUST FAIL
	matrixFail := make([][]byte, 80)
	for i := 0; i < 31; i++ {
		matrixFail[i] = shards[i].Data
	}
	_, errUnderflow := codec.DecodeSegment(matrixFail, origSize)
	if errUnderflow == nil {
		t.Errorf("Reconstruction with 31 shards unexpectedly succeeded (must fail under k=32 floor)")
	}
}

func TestTwoTierStorageVault(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "vault-test-*")
	if err != nil {
		t.Fatalf("TempDir failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 10 MB quota, 2 MB RAM cache
	vault, err := storage.NewVault(tempDir, 10*1024*1024, 2*1024*1024)
	if err != nil {
		t.Fatalf("NewVault failed: %v", err)
	}

	segID := "seg_alpha_01"
	segData := []byte("Full 64 MiB segment working dataset cached in NVMe and RAM")

	// 1. Store segment
	if err := vault.StoreSegment(segID, segData); err != nil {
		t.Fatalf("StoreSegment failed: %v", err)
	}

	// 2. Read segment: should hit Tier R (RAM cache) fast path (< 0.4s)
	loaded, tier, err := vault.ReadSegment(segID)
	if err != nil {
		t.Fatalf("ReadSegment failed: %v", err)
	}
	if tier != "Tier_R" {
		t.Errorf("Expected Tier_R locality hit, got %s", tier)
	}
	if !bytes.Equal(loaded, segData) {
		t.Errorf("Loaded segment does not match stored segment")
	}

	// 3. Store and read shard
	shardData := []byte("2 MiB shard Cauchy Reed Solomon parity slice")
	chk, err := vault.StoreShard(segID, 0, shardData)
	if err != nil {
		t.Fatalf("StoreShard failed: %v", err)
	}
	if chk == "" {
		t.Errorf("StoreShard returned empty checksum")
	}

	loadedShard, err := vault.ReadShard(segID, 0)
	if err != nil {
		t.Fatalf("ReadShard failed: %v", err)
	}
	if !bytes.Equal(loadedShard, shardData) {
		t.Errorf("Loaded shard does not match")
	}
}

func TestPoRChallengeResponse(t *testing.T) {
	shardData := make([]byte, 64*1024)
	_, _ = rand.Read(shardData)

	chal := storage.GeneratePoRChallenge("node-1", "shard-1", "seg-1")
	proof, err := storage.AnswerPoRChallenge(shardData, chal)
	if err != nil {
		t.Fatalf("AnswerPoRChallenge failed: %v", err)
	}

	if !storage.VerifyPoRProof(shardData, chal, proof) {
		t.Errorf("Valid PoR proof failed verification")
	}

	// Tamper with a byte inside one of the challenged sectors
	totalSectors := len(shardData) / 512
	targetSector := chal.SectorIndices[0] % totalSectors
	tamperedOffset := targetSector*512 + 10

	tamperedShard := make([]byte, len(shardData))
	copy(tamperedShard, shardData)
	tamperedShard[tamperedOffset] ^= 0xff

	if storage.VerifyPoRProof(tamperedShard, chal, proof) {
		t.Errorf("Tampered shard unexpectedly passed PoR proof verification")
	}

	// Verify without loading full shard: verifier uses only the 32-byte Merkle root
	shardRoot, errRoot := storage.ComputeShardMerkleRoot(shardData)
	if errRoot != nil {
		t.Fatalf("ComputeShardMerkleRoot failed: %v", errRoot)
	}
	if !storage.VerifyPoRProofWithRoot(shardRoot, chal, proof) {
		t.Errorf("Authentic PoR verification with 32-byte root failed!")
	}

	// Tampered root must fail
	tamperedRoot := "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
	if storage.VerifyPoRProofWithRoot(tamperedRoot, chal, proof) {
		t.Errorf("Tampered root unexpectedly passed verification!")
	}
}

func TestPoRNonPowerOfTwoAndArbitrarySizes(t *testing.T) {
	testSizes := []int{
		512,        // 1 sector
		1000,       // 2 sectors (unaligned trailing bytes)
		1536,       // 3 sectors (non-power-of-2)
		2048,       // 4 sectors
		3500,       // 7 sectors (odd, non-power-of-2)
		5120,       // 10 sectors (non-power-of-2)
		65536 + 13, // 128 sectors + 13 trailing bytes
	}

	for _, size := range testSizes {
		shardData := make([]byte, size)
		_, _ = rand.Read(shardData)

		shardRoot, errRoot := storage.ComputeShardMerkleRoot(shardData)
		if errRoot != nil {
			t.Fatalf("ComputeShardMerkleRoot failed for size %d: %v", size, errRoot)
		}

		chal := storage.GeneratePoRChallenge("node-por-test", "shard-por-test", "seg-por-test")
		proof, errProof := storage.AnswerPoRChallenge(shardData, chal)
		if errProof != nil {
			t.Fatalf("AnswerPoRChallenge failed for size %d: %v", size, errProof)
		}

		// Verify using full shard
		if !storage.VerifyPoRProof(shardData, chal, proof) {
			t.Errorf("VerifyPoRProof failed for size %d", size)
		}

		// Verify using 32-byte Merkle root
		if !storage.VerifyPoRProofWithRoot(shardRoot, chal, proof) {
			t.Errorf("VerifyPoRProofWithRoot failed for size %d", size)
		}

		// Tampered sector data must fail
		tamperedProof := *proof
		tamperedSector := make([]byte, len(proof.SectorData))
		copy(tamperedSector, proof.SectorData)
		tamperedSector[0] ^= 0xff
		tamperedProof.SectorData = tamperedSector
		if storage.VerifyPoRProofWithRoot(shardRoot, chal, &tamperedProof) {
			t.Errorf("Tampered sector data unexpectedly verified for size %d", size)
		}
	}
}

func TestLazyBatchedRepairEngine(t *testing.T) {
	codec, _ := storage.DefaultCauchyCodec()
	re := storage.NewRepairEngine(codec)

	// Segment with 70 shards online: healthy (> 48 threshold)
	shardsHealthy := make([]protocol.ShardMetadata, 80)
	for i := 0; i < 70; i++ {
		shardsHealthy[i] = protocol.ShardMetadata{Online: true}
	}
	segHealthy := &protocol.SegmentMetadata{
		SegmentID: "seg_healthy",
		Shards:    shardsHealthy,
	}

	shouldRepair, _ := re.CheckSegmentHealth(segHealthy)
	if shouldRepair {
		t.Errorf("Segment with 70 online shards should be healthy, but repair was triggered")
	}

	// Segment with 46 shards online: below LazyRepairThreshold (48) but above ReconstructionFloor (32)
	shardsTrigger := make([]protocol.ShardMetadata, 80)
	for i := 0; i < 46; i++ {
		shardsTrigger[i] = protocol.ShardMetadata{Online: true}
	}
	segTrigger := &protocol.SegmentMetadata{
		SegmentID: "seg_trigger",
		Shards:    shardsTrigger,
	}

	shouldRepair, reason := re.CheckSegmentHealth(segTrigger)
	if !shouldRepair {
		t.Errorf("Expected lazy repair to trigger at 46 shards, but got: %s", reason)
	}

	// Segment below floor (30 shards online): fatal loss
	shardsFatal := make([]protocol.ShardMetadata, 80)
	for i := 0; i < 30; i++ {
		shardsFatal[i] = protocol.ShardMetadata{Online: true}
	}
	segFatal := &protocol.SegmentMetadata{
		SegmentID: "seg_fatal",
		Shards:    shardsFatal,
	}

	shouldRepairFatal, _ := re.CheckSegmentHealth(segFatal)
	if shouldRepairFatal {
		t.Errorf("Should not trigger repair when under reconstruction floor (data loss)")
	}
}

func TestShardPlacementAnchorPinning(t *testing.T) {
	nodes := []*protocol.Node{
		{ID: "node-lab-01", SubnetZone: protocol.ZoneCampusLab, Online: true},
		{ID: "node-lab-02", SubnetZone: protocol.ZoneCampusLab, Online: true},
		{ID: "node-dorm-01", SubnetZone: protocol.ZoneDormWiFi, Online: true},
		{ID: "node-res-01", SubnetZone: protocol.ZoneResidential, Online: true},
	}

	shards, err := storage.PlanShardPlacement(nodes, "seg_anchor_test")
	if err != nil {
		t.Fatalf("PlanShardPlacement failed: %v", err)
	}

	if len(shards) != 80 {
		t.Fatalf("Expected 80 shards, got %d", len(shards))
	}

	anchorCount := 0
	for _, s := range shards {
		if s.IsAnchor {
			anchorCount++
			if s.SubnetZone != protocol.ZoneCampusLab {
				t.Errorf("Anchor shard placed on non-lab node: %s", s.SubnetZone)
			}
		}
	}

	if anchorCount < storage.AnchorPinningTarget {
		t.Errorf("Expected at least %d anchor shards, got %d", storage.AnchorPinningTarget, anchorCount)
	}
}

func TestBerlekampWelchStripeAudit(t *testing.T) {
	codec, err := storage.DefaultCauchyCodec()
	if err != nil {
		t.Fatalf("DefaultCauchyCodec failed: %v", err)
	}

	// 1. Generate 64 MiB segment and encode to 80 Cauchy RS shards
	data := make([]byte, 32*1024) // 32 KiB test segment -> 1 KiB per shard
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

	// Case 1: Honest stripe: all 80 shards match -> zero corrupted shards
	corrupted, err := storage.BerlekampWelchStripeAudit(codec, stripeSamples)
	if err != nil {
		t.Fatalf("BerlekampWelchStripeAudit failed on honest stripe: %v", err)
	}
	if len(corrupted) != 0 {
		t.Errorf("Expected 0 corrupted shards on honest stripe, got: %v", corrupted)
	}

	// Case 2: Data shard 5 corrupted (Byzantine node altered data shard)
	samplesDataCorrupt := make([][]byte, 80)
	for i := 0; i < 80; i++ {
		samplesDataCorrupt[i] = make([]byte, sampleLen)
		copy(samplesDataCorrupt[i], stripeSamples[i])
	}
	samplesDataCorrupt[5][0] ^= 0xff // Corrupt data shard 5

	corruptedData, errData := storage.BerlekampWelchStripeAudit(codec, samplesDataCorrupt)
	if errData != nil {
		t.Fatalf("BerlekampWelchStripeAudit failed with corrupted data shard: %v", errData)
	}
	if len(corruptedData) != 1 || corruptedData[0] != 5 {
		t.Errorf("Expected data shard [5] to be flagged as corrupted, got: %v", corruptedData)
	}

	// Case 3: Parity shard 42 corrupted
	samplesParityCorrupt := make([][]byte, 80)
	for i := 0; i < 80; i++ {
		samplesParityCorrupt[i] = make([]byte, sampleLen)
		copy(samplesParityCorrupt[i], stripeSamples[i])
	}
	samplesParityCorrupt[42][10] ^= 0xaa // Corrupt parity shard 42

	corruptedParity, errParity := storage.BerlekampWelchStripeAudit(codec, samplesParityCorrupt)
	if errParity != nil {
		t.Fatalf("BerlekampWelchStripeAudit failed with corrupted parity shard: %v", errParity)
	}
	if len(corruptedParity) != 1 || corruptedParity[0] != 42 {
		t.Errorf("Expected parity shard [42] to be flagged as corrupted, got: %v", corruptedParity)
	}

	// Case 4: Multiple corrupted shards (data shard 3 + parity shard 60)
	samplesMultiCorrupt := make([][]byte, 80)
	for i := 0; i < 80; i++ {
		samplesMultiCorrupt[i] = make([]byte, sampleLen)
		copy(samplesMultiCorrupt[i], stripeSamples[i])
	}
	samplesMultiCorrupt[3][5] ^= 0x55
	samplesMultiCorrupt[60][5] ^= 0x33

	corruptedMulti, errMulti := storage.BerlekampWelchStripeAudit(codec, samplesMultiCorrupt)
	if errMulti != nil {
		t.Fatalf("BerlekampWelchStripeAudit failed on multi-corrupt: %v", errMulti)
	}
	if len(corruptedMulti) != 2 || corruptedMulti[0] != 3 || corruptedMulti[1] != 60 {
		t.Errorf("Expected corrupted shards [3, 60], got: %v", corruptedMulti)
	}

	// Case 5: Missing shards (churn) + corrupted shard (data shard 0 is missing, shard 7 is corrupted, 20 parity shards missing)
	samplesChurn := make([][]byte, 80)
	for i := 0; i < 80; i++ {
		samplesChurn[i] = make([]byte, sampleLen)
		copy(samplesChurn[i], stripeSamples[i])
	}
	samplesChurn[0] = nil // Missing data shard 0
	for i := 50; i < 70; i++ {
		samplesChurn[i] = nil // 20 missing parity shards
	}
	samplesChurn[7][2] ^= 0xcc // Corrupted data shard 7 (among 59 surviving)

	corruptedChurn, errChurn := storage.BerlekampWelchStripeAudit(codec, samplesChurn)
	if errChurn != nil {
		t.Fatalf("BerlekampWelchStripeAudit failed with churn + corruption: %v", errChurn)
	}
	if len(corruptedChurn) != 1 || corruptedChurn[0] != 7 {
		t.Errorf("Expected corrupted shard [7] under churn, got: %v", corruptedChurn)
	}

	// Case 6: Below reconstruction floor (only 30 surviving shards) -> must return error
	samplesUnderflow := make([][]byte, 80)
	for i := 0; i < 30; i++ {
		samplesUnderflow[i] = make([]byte, sampleLen)
		copy(samplesUnderflow[i], stripeSamples[i])
	}
	_, errUnderflow := storage.BerlekampWelchStripeAudit(codec, samplesUnderflow)
	if errUnderflow == nil {
		t.Errorf("Expected error when surviving shards < 32 floor, got nil")
	}
}
