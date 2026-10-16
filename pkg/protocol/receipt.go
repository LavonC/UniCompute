package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// CanonicalReceiptHash computes H = SHA-256(task_id || input_cid || output_cid || fuel_consumed || exit_code || timestamp).
func (r *ExecutionReceipt) CanonicalReceiptHash() ([]byte, error) {
	h := sha256.New()

	// Write string lengths and contents to prevent length extension / delimiter collision
	if err := writeLengthPrefixedString(h, r.TaskID); err != nil {
		return nil, err
	}
	if err := writeLengthPrefixedString(h, r.InputCID); err != nil {
		return nil, err
	}
	if err := writeLengthPrefixedString(h, r.OutputCID); err != nil {
		return nil, err
	}

	fuelBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(fuelBuf, r.FuelConsumed)
	h.Write(fuelBuf)

	exitBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(exitBuf, uint32(r.ExitCode))
	h.Write(exitBuf)

	timeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBuf, uint64(r.Timestamp))
	h.Write(timeBuf)

	digest := h.Sum(nil)
	return digest, nil
}

func writeLengthPrefixedString(h interface{ Write([]byte) (int, error) }, s string) error {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(len(s)))
	if _, err := h.Write(buf); err != nil {
		return fmt.Errorf("write error: %w", err)
	}
	if _, err := h.Write([]byte(s)); err != nil {
		return fmt.Errorf("write error: %w", err)
	}
	return nil
}

// CanonicalReceiptHashHex returns the hex-encoded digest of the execution receipt.
func (r *ExecutionReceipt) CanonicalReceiptHashHex() (string, error) {
	d, err := r.CanonicalReceiptHash()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(d), nil
}
