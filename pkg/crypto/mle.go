package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

var (
	ErrDecryptionFailed = errors.New("mle decryption failed: authentication tag mismatch or corrupted ciphertext")
	mleSalt             = []byte("unicompute-convergent-encryption-salt-v1")
)

// DeriveKey derives a deterministic 256-bit AES key from the plaintext bytes.
func DeriveKey(plaintext []byte) ([]byte, error) {
	kdf := hkdf.New(sha256.New, plaintext, mleSalt, []byte("unicompute-mle-key"))
	key := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("failed to derive convergent key: %w", err)
	}
	return key, nil
}

// deriveDeterministicNonce derives a 12-byte GCM nonce deterministically from the key and plaintext hash.
func deriveDeterministicNonce(key []byte, plaintextHash []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(plaintextHash)
	mac.Write([]byte("unicompute-mle-nonce"))
	h := mac.Sum(nil)
	return h[:12] // 96-bit standard GCM nonce
}

// EncryptMLE performs Message-Locked Encryption using AES-256-GCM (packed with deterministic nonce).
// Returns ciphertext, the 32-byte convergent key, and the plaintext SHA-256 CID.
func EncryptMLE(plaintext []byte) (ciphertext []byte, key []byte, cid string, err error) {
	return EncryptMLEPacked(plaintext)
}

// DecryptMLE is an alias to DecryptMLEPacked for ease of use.
func DecryptMLE(ciphertext []byte, key []byte) ([]byte, error) {
	return DecryptMLEPacked(ciphertext, key)
}

// EncryptMLEPacked performs MLE and prepends the 12-byte deterministic nonce to the ciphertext.
func EncryptMLEPacked(plaintext []byte) (packedCiphertext []byte, key []byte, cid string, err error) {
	h := sha256.Sum256(plaintext)
	cid = hex.EncodeToString(h[:])

	key, err = DeriveKey(plaintext)
	if err != nil {
		return nil, nil, "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to create GCM block: %w", err)
	}

	nonce := deriveDeterministicNonce(key, h[:])

	// Pack: [12-byte nonce] + [ciphertext + 16-byte tag]
	packedCiphertext = make([]byte, 12+len(plaintext)+gcm.Overhead())
	copy(packedCiphertext[:12], nonce)
	gcm.Seal(packedCiphertext[:12], nonce, plaintext, nil)

	return packedCiphertext, key, cid, nil
}

// DecryptMLEPacked decrypts a packed MLE ciphertext ([12-byte nonce] + [ciphertext]).
func DecryptMLEPacked(packedCiphertext []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid convergent key size: expected 32 bytes for AES-256")
	}
	if len(packedCiphertext) < 12+16 {
		return nil, errors.New("ciphertext too short")
	}

	nonce := packedCiphertext[:12]
	actualCiphertext := packedCiphertext[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM block: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}
