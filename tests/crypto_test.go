package tests

import (
	"bytes"
	"testing"

	"unicompute/pkg/crypto"
)

func TestEd25519SigningAndVerification(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	data := []byte("UniCompute verified system specification payload")
	sig := kp.Sign(data)
	sigHex := kp.SignHex(data)

	// 1. Valid signature
	if !crypto.VerifySignature(kp.PublicKey, data, sig) {
		t.Errorf("Valid signature failed raw verification")
	}

	valid, err := crypto.VerifySignatureHex(kp.PublicKeyHex(), data, sigHex)
	if err != nil || !valid {
		t.Errorf("Valid signature failed hex verification: %v", err)
	}

	// 2. Tampered data
	tamperedData := []byte("UniCompute tampered payload")
	if crypto.VerifySignature(kp.PublicKey, tamperedData, sig) {
		t.Errorf("Tampered data unexpectedly passed verification")
	}

	// 3. Foreign keypair
	kp2, _ := crypto.GenerateKeyPair()
	if crypto.VerifySignature(kp2.PublicKey, data, sig) {
		t.Errorf("Foreign public key unexpectedly passed verification")
	}
}

func TestMessageLockedEncryption(t *testing.T) {
	plaintext := []byte("Deterministic content-addressed dataset partition in genomic alignment")

	// 1. Test convergent key property: identical plaintext produces identical ciphertext & key
	packed1, key1, cid1, err1 := crypto.EncryptMLEPacked(plaintext)
	if err1 != nil {
		t.Fatalf("MLE encryption 1 failed: %v", err1)
	}

	packed2, key2, cid2, err2 := crypto.EncryptMLEPacked(plaintext)
	if err2 != nil {
		t.Fatalf("MLE encryption 2 failed: %v", err2)
	}

	if !bytes.Equal(key1, key2) {
		t.Errorf("MLE failed: convergent keys for identical plaintext differ")
	}

	if !bytes.Equal(packed1, packed2) {
		t.Errorf("MLE failed: deterministic ciphertexts for identical plaintext differ (breaks deduplication)")
	}

	if cid1 != cid2 {
		t.Errorf("MLE failed: CIDs differ")
	}

	// 2. Test decryption
	decrypted, err := crypto.DecryptMLEPacked(packed1, key1)
	if err != nil {
		t.Fatalf("MLE decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted plaintext does not match original: got %s, want %s", decrypted, plaintext)
	}

	// 3. Test tampering detection
	corrupted := make([]byte, len(packed1))
	copy(corrupted, packed1)
	corrupted[len(corrupted)-1] ^= 0xff // Corrupt GCM authentication tag

	_, errCorrupt := crypto.DecryptMLEPacked(corrupted, key1)
	if errCorrupt == nil {
		t.Errorf("Corrupted ciphertext unexpectedly succeeded in decryption")
	}
}

func TestEncryptMLEAndDecryptMLEPair(t *testing.T) {
	plaintext := []byte("Message-Locked Encryption standard API round-trip test")

	ct, key, cid, err := crypto.EncryptMLE(plaintext)
	if err != nil {
		t.Fatalf("EncryptMLE failed: %v", err)
	}
	if cid == "" {
		t.Errorf("Empty CID returned by EncryptMLE")
	}

	decrypted, err := crypto.DecryptMLE(ct, key)
	if err != nil {
		t.Fatalf("DecryptMLE failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted does not match plaintext: got %s, want %s", decrypted, plaintext)
	}
}
