package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// KeyPair wraps an Ed25519 public and private key.
type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateKeyPair generates a new cryptographic Ed25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 keypair: %w", err)
	}
	return &KeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// Sign creates an Ed25519 digital signature over the given data.
func (kp *KeyPair) Sign(data []byte) []byte {
	return ed25519.Sign(kp.PrivateKey, data)
}

// SignHex creates an Ed25519 signature and returns it hex-encoded.
func (kp *KeyPair) SignHex(data []byte) string {
	sig := kp.Sign(data)
	return hex.EncodeToString(sig)
}

// PublicKeyHex returns the hex-encoded public key.
func (kp *KeyPair) PublicKeyHex() string {
	return hex.EncodeToString(kp.PublicKey)
}

// VerifySignature verifies an Ed25519 signature against data using a public key.
func VerifySignature(pubKey ed25519.PublicKey, data []byte, sig []byte) bool {
	return ed25519.Verify(pubKey, data, sig)
}

// VerifySignatureHex verifies a hex-encoded signature using a hex-encoded public key.
func VerifySignatureHex(pubKeyHex string, data []byte, sigHex string) (bool, error) {
	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return false, fmt.Errorf("invalid pubkey hex: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid pubkey size: expected %d, got %d", ed25519.PublicKeySize, len(pubBytes))
	}

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid signature size: expected %d, got %d", ed25519.SignatureSize, len(sigBytes))
	}

	return ed25519.Verify(ed25519.PublicKey(pubBytes), data, sigBytes), nil
}

// SavePrivateKeyFile writes private key bytes to a local file with 0600 permissions.
func (kp *KeyPair) SavePrivateKeyFile(path string) error {
	return os.WriteFile(path, kp.PrivateKey, 0600)
}

// LoadPrivateKeyFile reads an Ed25519 private key from disk.
func LoadPrivateKeyFile(path string) (*KeyPair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	if len(data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: %d", len(data))
	}
	priv := ed25519.PrivateKey(data)
	pub := priv.Public().(ed25519.PublicKey)
	return &KeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}
