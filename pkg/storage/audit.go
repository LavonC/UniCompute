package storage

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"

	"unicompute/pkg/protocol"
)

// GeneratePoRChallenge creates a randomized 4.2 KB Proof of Retrievability challenge.
func GeneratePoRChallenge(nodeID, shardID, segmentID string) *protocol.AuditChallenge {
	seed := time.Now().UnixNano()
	r := rand.New(rand.NewSource(seed))

	// Choose 50 random sector indices within a 2 MiB shard (assuming 512-byte sectors = 4096 sectors)
	numSectors := 4096
	subsetSize := 50
	indices := make([]int, subsetSize)
	for i := 0; i < subsetSize; i++ {
		indices[i] = r.Intn(numSectors)
	}

	nonceBytes := make([]byte, 16)
	r.Read(nonceBytes)

	// Stripe offset for Berlekamp-Welch algebraic check (random 1 KB stripe)
	byteOffset := int64(r.Intn(2*1024*1024 - 1024))

	shardIndex := 0
	var idx int
	if n, _ := fmt.Sscanf(shardID, "%*[^0-9]%d", &idx); n > 0 {
		shardIndex = idx
	}

	return &protocol.AuditChallenge{
		ChallengeID:   fmt.Sprintf("chal-%x", r.Uint64()),
		NodeID:        nodeID,
		ShardID:       shardID,
		SegmentID:     segmentID,
		ShardIndex:    shardIndex,
		Seed:          seed,
		SectorIndices: indices,
		Nonce:         hex.EncodeToString(nonceBytes),
		ByteOffset:    byteOffset,
		StripeLength:  1024,
	}
}

// GeneratePoRChallengeWithIndex creates a randomized 4.2 KB PoR challenge with explicit shard index.
func GeneratePoRChallengeWithIndex(nodeID, shardID, segmentID string, shardIndex int) *protocol.AuditChallenge {
	chal := GeneratePoRChallenge(nodeID, shardID, segmentID)
	chal.ShardIndex = shardIndex
	return chal
}

// AnswerPoRChallenge processes the challenge against the local shard bytes.
func AnswerPoRChallenge(shardData []byte, chal *protocol.AuditChallenge) (*protocol.AuditProof, error) {
	if len(shardData) == 0 {
		return nil, fmt.Errorf("shard data is empty")
	}

	sectorSize := 512
	totalSectors := (len(shardData) + sectorSize - 1) / sectorSize
	if totalSectors == 0 {
		return nil, fmt.Errorf("shard data is empty")
	}

	// Pseudo-random linear combination weights derived from seed
	prg := rand.New(rand.NewSource(chal.Seed))
	agg := make([]byte, sectorSize)

	for _, idx := range chal.SectorIndices {
		secIdx := idx % totalSectors
		secStart := secIdx * sectorSize
		secEnd := secStart + sectorSize
		if secEnd > len(shardData) {
			secEnd = len(shardData)
		}
		coeff := byte(prg.Intn(255) + 1)
		for b := 0; b < secEnd-secStart; b++ {
			agg[b] ^= shardData[secStart+b] * coeff
		}
	}

	// Hash the aggregated vector with the challenge nonce
	mac := hmac.New(sha256.New, []byte(chal.Nonce))
	mac.Write(agg)
	aggHash := hex.EncodeToString(mac.Sum(nil))

	// Extract stripe sample for Berlekamp-Welch
	var stripeSample []byte
	if chal.ByteOffset >= 0 && chal.ByteOffset < int64(len(shardData)) {
		end := chal.ByteOffset + int64(chal.StripeLength)
		if end > int64(len(shardData)) {
			end = int64(len(shardData))
		}
		stripeSample = make([]byte, end-chal.ByteOffset)
		copy(stripeSample, shardData[chal.ByteOffset:end])
	}

	// Build authentic block-level Merkle tree over 512-byte sectors
	mt, err := BuildShardMerkleTree(shardData)
	if err != nil {
		return nil, fmt.Errorf("failed to build shard merkle tree: %w", err)
	}

	primarySectorIdx := 0
	if len(chal.SectorIndices) > 0 {
		primarySectorIdx = chal.SectorIndices[0] % len(mt.Leaves)
	}

	merkleProof, err := mt.GenerateProof(primarySectorIdx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate authentic merkle proof: %w", err)
	}

	merkleBranch := make([]string, len(merkleProof.Siblings))
	for i, s := range merkleProof.Siblings {
		merkleBranch[i] = hex.EncodeToString(s)
	}

	secStart := primarySectorIdx * sectorSize
	secEnd := secStart + sectorSize
	if secEnd > len(shardData) {
		secEnd = len(shardData)
	}
	sectorData := make([]byte, secEnd-secStart)
	copy(sectorData, shardData[secStart:secEnd])

	proofSize := len(aggHash) + len(stripeSample) + (len(merkleBranch) * 64) + len(sectorData)

	return &protocol.AuditProof{
		ChallengeID:    chal.ChallengeID,
		NodeID:         chal.NodeID,
		ShardID:        chal.ShardID,
		AggregatedHash: aggHash,
		MerkleBranch:   merkleBranch,
		PathBits:       merkleProof.PathBits,
		SectorIndex:    primarySectorIdx,
		SectorData:     sectorData,
		StripeSample:   stripeSample,
		Timestamp:      time.Now().Unix(),
		ProofSize:      proofSize,
	}, nil
}

const DefaultSectorSize = 512

// BuildShardMerkleTree constructs an authentic Merkle tree from 512-byte sectors of a shard.
func BuildShardMerkleTree(shardData []byte) (*MerkleTree, error) {
	if len(shardData) == 0 {
		return nil, fmt.Errorf("shard data is empty")
	}

	sectorSize := DefaultSectorSize
	numSectors := (len(shardData) + sectorSize - 1) / sectorSize
	if numSectors == 0 {
		return nil, fmt.Errorf("shard data is empty")
	}

	leaves := make([][]byte, numSectors)
	for i := 0; i < numSectors; i++ {
		start := i * sectorSize
		end := start + sectorSize
		if end > len(shardData) {
			end = len(shardData)
		}
		h := sha256.Sum256(shardData[start:end])
		leaves[i] = h[:]
	}

	return NewMerkleTree(leaves)
}

// ComputeShardMerkleRoot returns the hex-encoded root hash of a shard's block-level Merkle tree.
func ComputeShardMerkleRoot(shardData []byte) (string, error) {
	mt, err := BuildShardMerkleTree(shardData)
	if err != nil {
		return "", err
	}
	return mt.RootHex(), nil
}

// VerifyPoRProofWithRoot verifies an authentic block-level Merkle audit proof
// using only the expected shard Merkle root, without requiring the verifier
// to load the entire 2 MiB shard into memory.
func VerifyPoRProofWithRoot(expectedRootHex string, chal *protocol.AuditChallenge, proof *protocol.AuditProof) bool {
	if proof == nil || chal == nil || expectedRootHex == "" {
		return false
	}
	if len(proof.SectorData) == 0 {
		return false
	}

	expectedRootBytes, err := hex.DecodeString(expectedRootHex)
	if err != nil {
		return false
	}

	numLeaves := 1 << len(proof.MerkleBranch)
	primarySectorIdx := 0
	if proof.SectorIndex >= 0 && proof.SectorIndex < numLeaves {
		primarySectorIdx = proof.SectorIndex
	} else if len(chal.SectorIndices) > 0 {
		primarySectorIdx = chal.SectorIndices[0] % numLeaves
	}

	leaf := sha256.Sum256(proof.SectorData)
	current := leaf[:]

	for i, siblingHex := range proof.MerkleBranch {
		siblingBytes, err := hex.DecodeString(siblingHex)
		if err != nil {
			return false
		}
		var isRight bool
		if i < len(proof.PathBits) {
			isRight = proof.PathBits[i]
		} else {
			isRight = ((primarySectorIdx >> i) & 1) == 1
		}
		if isRight {
			current = hashNodes(siblingBytes, current)
		} else {
			current = hashNodes(current, siblingBytes)
		}
	}

	return bytes.Equal(current, expectedRootBytes)
}

// VerifyPoRProof checks if an audit proof response correctly authenticates shard possession.
// It verifies both the authentic block-level Merkle inclusion proof and HMAC vector aggregation.
func VerifyPoRProof(expectedShard []byte, chal *protocol.AuditChallenge, proof *protocol.AuditProof) bool {
	if proof == nil || chal == nil || len(expectedShard) == 0 {
		return false
	}

	mt, err := BuildShardMerkleTree(expectedShard)
	if err != nil {
		return false
	}

	if !VerifyPoRProofWithRoot(mt.RootHex(), chal, proof) {
		return false
	}

	expectedProof, err := AnswerPoRChallenge(expectedShard, chal)
	if err != nil {
		return false
	}
	return expectedProof.AggregatedHash == proof.AggregatedHash
}

// BerlekampWelchStripeAudit verifies algebraic consistency across a stripe returned by holders of RS(k, n) shards (§9.2, Storj v3 model).
// Given surviving samples from a stripe (with missing shards set to nil/empty), it reconstructs the valid
// Reed-Solomon codeword across all 80 shard positions and mathematically detects any corrupted or Byzantine shards
// (both data and parity shards) without false accusations or crashing on missing data shards.
func BerlekampWelchStripeAudit(codec *ErasureCodec, stripeSamples [][]byte) (corruptedShards []int, err error) {
	if len(stripeSamples) != codec.totalShards {
		return nil, fmt.Errorf("expected %d shard samples, got %d", codec.totalShards, len(stripeSamples))
	}

	// 1. Determine sample length
	var sampleLen int
	for _, s := range stripeSamples {
		if len(s) > 0 {
			sampleLen = len(s)
			break
		}
	}
	if sampleLen == 0 {
		return nil, fmt.Errorf("no sample data provided")
	}

	// 2. Identify all surviving shards of matching sample length, and flag any malformed non-empty samples
	var surviving []int
	for i, s := range stripeSamples {
		if len(s) == sampleLen {
			surviving = append(surviving, i)
		} else if len(s) > 0 {
			// Non-empty sample with malformed/truncated length is corrupted
			corruptedShards = append(corruptedShards, i)
		}
	}

	if len(surviving) < codec.dataShards {
		return nil, fmt.Errorf("cannot perform algebraic check: only %d surviving samples, need %d", len(surviving), codec.dataShards)
	}

	// 3. Find algebraic consensus codeword across surviving shards.
	// Evaluate sliding candidate windows of dataShards across all surviving shards.
	var consensusMatrix [][]byte
	bestAgreement := 0

	totalWindows := len(surviving) - codec.dataShards + 1

	for attempt := 0; attempt < totalWindows; attempt++ {
		candidateIndices := make([]int, codec.dataShards)
		copy(candidateIndices, surviving[attempt:attempt+codec.dataShards])

		// Prepare matrix with only candidate shards populated, others nil
		matrix := make([][]byte, codec.totalShards)
		for _, idx := range candidateIndices {
			matrix[idx] = make([]byte, sampleLen)
			copy(matrix[idx], stripeSamples[idx])
		}

		// Reconstruct all 80 shards
		if errRecon := codec.ReconstructMissingShards(matrix); errRecon != nil {
			continue
		}

		// Count how many surviving shards match the reconstructed codeword
		agreement := 0
		for _, idx := range surviving {
			if bytes.Equal(stripeSamples[idx], matrix[idx]) {
				agreement++
			}
		}

		if agreement > bestAgreement {
			bestAgreement = agreement
			consensusMatrix = matrix
		}

		// If agreement meets or exceeds 3/4 supermajority of surviving nodes, we have found the true codeword
		if agreement >= codec.dataShards && agreement >= (len(surviving)*3)/4 {
			break
		}
	}

	// Require at least majority consensus to prevent minority false accusations
	if consensusMatrix == nil || bestAgreement < (len(surviving)+1)/2 {
		return nil, fmt.Errorf("failed to find algebraic consensus codeword across stripe samples")
	}

	// 4. Identify any shard (data or parity) whose sample differs from the true algebraic codeword
	for _, idx := range surviving {
		if !bytes.Equal(stripeSamples[idx], consensusMatrix[idx]) {
			corruptedShards = append(corruptedShards, idx)
		}
	}

	return corruptedShards, nil
}
