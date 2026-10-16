package verification

import (
	"fmt"

	"unicompute/pkg/crypto"
	"unicompute/pkg/protocol"
)

// VerifyExecutionReceipt verifies the Layer 1 Ed25519 cryptographic signature over the canonical receipt tuple (§7.1).
func VerifyExecutionReceipt(receipt *protocol.ExecutionReceipt) (bool, error) {
	if receipt == nil {
		return false, fmt.Errorf("receipt is nil")
	}
	if receipt.Signature == "" {
		return false, fmt.Errorf("receipt missing signature")
	}
	if receipt.WorkerPubKey == "" {
		return false, fmt.Errorf("receipt missing worker public key")
	}

	digest, err := receipt.CanonicalReceiptHash()
	if err != nil {
		return false, fmt.Errorf("failed to compute canonical receipt hash: %w", err)
	}

	valid, errSig := crypto.VerifySignatureHex(receipt.WorkerPubKey, digest, receipt.Signature)
	if errSig != nil {
		return false, fmt.Errorf("signature verification failed: %w", errSig)
	}

	return valid, nil
}
