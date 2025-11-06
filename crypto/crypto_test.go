package crypto

import (
	"bytes"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// TestKeyGeneration tests private and public key generation
func TestKeyGeneration(t *testing.T) {
	privKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	pubKey := &privKey.PublicKey
	if pubKey == nil {
		t.Fatal("Public key is nil")
	}

	nodeID := NodeID(pubKey)
	if len(nodeID) != 32 {
		t.Errorf("Node ID length = %d, want 32", len(nodeID))
	}
}

// TestKeySerializationDeserialization tests key encoding and decoding
func TestKeySerializationDeserialization(t *testing.T) {
	privKey, err := ethcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Test private key serialization
	privBytes := ethcrypto.FromECDSA(privKey)
	if len(privBytes) != 32 {
		t.Errorf("Private key bytes length = %d, want 32", len(privBytes))
	}

	recoveredPriv, err := ethcrypto.ToECDSA(privBytes)
	if err != nil {
		t.Fatalf("Failed to recover private key: %v", err)
	}

	if !bytes.Equal(ethcrypto.FromECDSA(privKey), ethcrypto.FromECDSA(recoveredPriv)) {
		t.Error("Recovered private key doesn't match original")
	}

	// Test public key serialization
	compressedPub := ethcrypto.CompressPubkey(&privKey.PublicKey)
	if len(compressedPub) != 33 {
		t.Errorf("Compressed public key length = %d, want 33", len(compressedPub))
	}

	recoveredPub, err := ethcrypto.DecompressPubkey(compressedPub)
	if err != nil {
		t.Fatalf("Failed to recover public key: %v", err)
	}

	if !bytes.Equal(NodeID(&privKey.PublicKey), NodeID(recoveredPub)) {
		t.Error("Recovered public key doesn't match original")
	}
}

// TestECDH tests ECDH key agreement
func TestECDH(t *testing.T) {
	alicePriv, _ := ethcrypto.GenerateKey()
	bobPriv, _ := ethcrypto.GenerateKey()

	alicePub := &alicePriv.PublicKey
	bobPub := &bobPriv.PublicKey

	// Alice computes shared secret
	secret1, err := ECDH(alicePriv, bobPub)
	if err != nil {
		t.Fatalf("Alice ECDH failed: %v", err)
	}

	// Bob computes shared secret
	secret2, err := ECDH(bobPriv, alicePub)
	if err != nil {
		t.Fatalf("Bob ECDH failed: %v", err)
	}

	// Shared secrets should match
	if !bytes.Equal(secret1, secret2) {
		t.Error("ECDH shared secrets don't match")
	}

	if len(secret1) != 32 {
		t.Errorf("Shared secret length = %d, want 32", len(secret1))
	}
}

// TestAESGCM tests AES-GCM encryption and decryption
func TestAESGCM(t *testing.T) {
	key, _ := GenerateRandomBytes(AESKeySize)
	nonce, _ := GenerateRandomBytes(GCMNonceSize)
	plaintext := []byte("Hello, World!")
	aad := []byte("additional authenticated data")

	// Encrypt
	ciphertext, err := AESGCMEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Ciphertext should be longer than plaintext (includes tag)
	if len(ciphertext) != len(plaintext)+GCMTagSize {
		t.Errorf("Ciphertext length = %d, want %d", len(ciphertext), len(plaintext)+GCMTagSize)
	}

	// Decrypt
	decrypted, err := AESGCMDecrypt(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Decrypted should match plaintext
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted = %s, want %s", decrypted, plaintext)
	}
}

// TestAESGCMAuthentication tests GCM authentication
func TestAESGCMAuthentication(t *testing.T) {
	key, _ := GenerateRandomBytes(AESKeySize)
	nonce, _ := GenerateRandomBytes(GCMNonceSize)
	plaintext := []byte("Hello, World!")
	aad := []byte("additional authenticated data")

	ciphertext, _ := AESGCMEncrypt(key, nonce, plaintext, aad)

	// Tamper with ciphertext
	ciphertext[0] ^= 0x01

	// Decryption should fail
	_, err := AESGCMDecrypt(key, nonce, ciphertext, aad)
	if err != ErrDecryptionFailed {
		t.Error("Expected decryption to fail on tampered ciphertext")
	}
}

// TestHKDF tests HKDF key derivation
func TestHKDF(t *testing.T) {
	secret := []byte("shared secret")
	info := []byte("context information")

	key1, err := HKDFExtract(nil, secret, info, 16)
	if err != nil {
		t.Fatalf("HKDF failed: %v", err)
	}

	if len(key1) != 16 {
		t.Errorf("Key length = %d, want 16", len(key1))
	}

	// Same inputs should produce same output
	key2, _ := HKDFExtract(nil, secret, info, 16)
	if !bytes.Equal(key1, key2) {
		t.Error("HKDF should be deterministic")
	}

	// Different info should produce different output
	key3, _ := HKDFExtract(nil, secret, []byte("different context"), 16)
	if bytes.Equal(key1, key3) {
		t.Error("HKDF should produce different keys for different context")
	}
}

// TestDeriveSessionKeys tests session key derivation
func TestDeriveSessionKeys(t *testing.T) {
	secret, _ := GenerateRandomBytes(32)
	challenge := []byte("challenge data")

	// Derive keys as initiator
	initEncKey, initDecKey, err := DeriveSessionKeys(secret, true, challenge)
	if err != nil {
		t.Fatalf("Failed to derive session keys: %v", err)
	}

	// Derive keys as recipient
	recpEncKey, recpDecKey, err := DeriveSessionKeys(secret, false, challenge)
	if err != nil {
		t.Fatalf("Failed to derive session keys: %v", err)
	}

	// Initiator's encryption key should match recipient's decryption key
	if !bytes.Equal(initEncKey, recpDecKey) {
		t.Error("Initiator encryption key should match recipient decryption key")
	}

	// Initiator's decryption key should match recipient's encryption key
	if !bytes.Equal(initDecKey, recpEncKey) {
		t.Error("Initiator decryption key should match recipient encryption key")
	}

	// Keys should be different
	if bytes.Equal(initEncKey, initDecKey) {
		t.Error("Encryption and decryption keys should be different")
	}
}

// TestNonceGeneration tests nonce generation from counter
func TestNonceGeneration(t *testing.T) {
	counter := uint64(12345)
	nonce := NonceFromUint64(counter)

	if len(nonce) != GCMNonceSize {
		t.Errorf("Nonce length = %d, want %d", len(nonce), GCMNonceSize)
	}

	// Extract counter back
	extractedCounter, err := ExtractNonceCounter(nonce)
	if err != nil {
		t.Fatalf("Failed to extract counter: %v", err)
	}

	if extractedCounter != counter {
		t.Errorf("Extracted counter = %d, want %d", extractedCounter, counter)
	}
}

// TestSignAndVerify tests signature creation and verification
func TestSignAndVerify(t *testing.T) {
	privKey, _ := ethcrypto.GenerateKey()
	pubKey := &privKey.PublicKey

	message := []byte("message to sign")
	hash := ethcrypto.Keccak256(message)

	// Sign
	sig, err := ethcrypto.Sign(hash, privKey)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) != 65 {
		t.Errorf("Signature length = %d, want 65", len(sig))
	}

	// Verify (without recovery ID)
	if !ethcrypto.VerifySignature(ethcrypto.CompressPubkey(pubKey), hash, sig[:64]) {
		t.Error("Signature verification failed")
	}

	// Recover public key
	recoveredPubKey, err := ethcrypto.SigToPub(hash, sig)
	if err != nil {
		t.Fatalf("Failed to recover public key: %v", err)
	}

	if !bytes.Equal(NodeID(pubKey), NodeID(recoveredPubKey)) {
		t.Error("Recovered public key doesn't match original")
	}
}

// TestPublicKeyValidation tests public key validation
func TestPublicKeyValidation(t *testing.T) {
	// Generate valid key
	privKey, _ := ethcrypto.GenerateKey()
	pubKey := &privKey.PublicKey

	// Should pass validation
	if err := ValidatePublicKey(pubKey); err != nil {
		t.Errorf("Valid key failed validation: %v", err)
	}

	// Test nil key
	if err := ValidatePublicKey(nil); err == nil {
		t.Error("Nil key should fail validation")
	}
}

// TestIDSignature tests node ID signature creation and verification
func TestIDSignature(t *testing.T) {
	nodePriv, _ := ethcrypto.GenerateKey()
	ephemeralPriv, _ := ethcrypto.GenerateKey()
	ephemeralPub := &ephemeralPriv.PublicKey

	// Create signature
	sig, err := DeriveIDSignature(nodePriv, ephemeralPub)
	if err != nil {
		t.Fatalf("Failed to create ID signature: %v", err)
	}

	// Verify signature
	nodeID := NodeID(&nodePriv.PublicKey)
	if !VerifyIDSignature(sig, nodeID, ephemeralPub) {
		t.Error("ID signature verification failed")
	}

	// Verify with wrong node ID should fail
	wrongNodeID := make([]byte, 32)
	if VerifyIDSignature(sig, wrongNodeID, ephemeralPub) {
		t.Error("ID signature should fail with wrong node ID")
	}
}

// BenchmarkECDH benchmarks ECDH key agreement
func BenchmarkECDH(b *testing.B) {
	privKey, _ := ethcrypto.GenerateKey()
	remotePubKey, _ := ethcrypto.GenerateKey()
	remotePub := &remotePubKey.PublicKey

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ECDH(privKey, remotePub)
	}
}

// BenchmarkAESGCMEncrypt benchmarks AES-GCM encryption
func BenchmarkAESGCMEncrypt(b *testing.B) {
	key, _ := GenerateRandomBytes(AESKeySize)
	nonce, _ := GenerateRandomBytes(GCMNonceSize)
	plaintext := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AESGCMEncrypt(key, nonce, plaintext, nil)
	}
}

// BenchmarkHKDF benchmarks HKDF key derivation
func BenchmarkHKDF(b *testing.B) {
	secret := make([]byte, 32)
	info := []byte("context")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HKDFExtract(nil, secret, info, 16)
	}
}
