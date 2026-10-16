package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/klauspost/reedsolomon"
)

const (
	DefaultDataShards   = 32 // k = 32
	DefaultParityShards = 48 // n - k = 48 (total n = 80)
	DefaultSegmentSize  = 64 * 1024 * 1024 // 64 MiB
	DefaultShardSize    = 2 * 1024 * 1024  // 2 MiB
)

// ErasureCodec encapsulates Cauchy Reed-Solomon encoding and decoding.
type ErasureCodec struct {
	dataShards   int
	parityShards int
	totalShards  int
	enc          reedsolomon.Encoder
}

// Shard represents an individual encoded shard.
type Shard struct {
	Index    int    `json:"index"`
	Data     []byte `json:"-"`
	IsParity bool   `json:"is_parity"`
	Checksum string `json:"checksum"` // SHA-256
	Size     int    `json:"size"`
}

// NewErasureCodec creates an RS(k, n-k) codec. Defaults to RS(32, 48) => 80 shards.
func NewErasureCodec(dataShards, parityShards int) (*ErasureCodec, error) {
	if dataShards <= 0 || parityShards <= 0 {
		return nil, errors.New("data and parity shards must be positive")
	}
	if dataShards+parityShards > 256 {
		return nil, errors.New("total shards (k + m) cannot exceed 256 in GF(2^8)")
	}

	enc, err := reedsolomon.New(dataShards, parityShards, reedsolomon.WithCauchyMatrix())
	if err != nil {
		// Fallback to standard if WithCauchyMatrix option differs
		enc, err = reedsolomon.New(dataShards, parityShards)
		if err != nil {
			return nil, fmt.Errorf("failed to create reedsolomon codec: %w", err)
		}
	}

	return &ErasureCodec{
		dataShards:   dataShards,
		parityShards: parityShards,
		totalShards:  dataShards + parityShards,
		enc:          enc,
	}, nil
}

// DefaultCauchyCodec returns the production RS(32, 80) codec specified in the architecture.
func DefaultCauchyCodec() (*ErasureCodec, error) {
	return NewErasureCodec(DefaultDataShards, DefaultParityShards)
}

// EncodeSegment takes raw segment bytes, pads to shard boundaries, and produces n shards.
func (ec *ErasureCodec) EncodeSegment(data []byte) ([]Shard, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot encode empty data")
	}

	// Calculate shard size: padded to multiple of dataShards
	shardSize := (len(data) + ec.dataShards - 1) / ec.dataShards

	// Allocate buffer for all shards
	shards := make([][]byte, ec.totalShards)
	for i := range shards {
		shards[i] = make([]byte, shardSize)
	}

	// Copy data into data shards
	for i := 0; i < ec.dataShards; i++ {
		start := i * shardSize
		if start < len(data) {
			end := start + shardSize
			if end > len(data) {
				end = len(data)
			}
			copy(shards[i], data[start:end])
		}
	}

	// Compute parity shards
	if err := ec.enc.Encode(shards); err != nil {
		return nil, fmt.Errorf("reedsolomon encoding failed: %w", err)
	}

	// Wrap in Shard structs
	result := make([]Shard, ec.totalShards)
	for i := 0; i < ec.totalShards; i++ {
		h := sha256.Sum256(shards[i])
		result[i] = Shard{
			Index:    i,
			Data:     shards[i],
			IsParity: i >= ec.dataShards,
			Checksum: hex.EncodeToString(h[:]),
			Size:     len(shards[i]),
		}
	}

	return result, nil
}

// DecodeSegment reconstructs the original raw bytes given a slice of shards.
// Missing shards are represented by nil in shards slice. At least dataShards must be present.
func (ec *ErasureCodec) DecodeSegment(shards [][]byte, originalSize int64) ([]byte, error) {
	if len(shards) != ec.totalShards {
		return nil, fmt.Errorf("expected %d shards in input array, got %d", ec.totalShards, len(shards))
	}

	// Count surviving shards
	surviving := 0
	for _, s := range shards {
		if len(s) > 0 {
			surviving++
		}
	}

	if surviving < ec.dataShards {
		return nil, fmt.Errorf("insufficient shards for reconstruction: got %d, required at least %d", surviving, ec.dataShards)
	}

	// Reconstruct missing shards
	if err := ec.enc.Reconstruct(shards); err != nil {
		return nil, fmt.Errorf("reedsolomon reconstruction failed: %w", err)
	}

	// Concatenate data shards
	var reconstructed []byte
	for i := 0; i < ec.dataShards; i++ {
		reconstructed = append(reconstructed, shards[i]...)
	}

	if originalSize > 0 && int64(len(reconstructed)) > originalSize {
		reconstructed = reconstructed[:originalSize]
	}

	return reconstructed, nil
}

// ReconstructMissingShards reconstructs all missing shards in-place in the shards slice.
func (ec *ErasureCodec) ReconstructMissingShards(shards [][]byte) error {
	if len(shards) != ec.totalShards {
		return fmt.Errorf("expected %d shards in input array, got %d", ec.totalShards, len(shards))
	}
	return ec.enc.Reconstruct(shards)
}
