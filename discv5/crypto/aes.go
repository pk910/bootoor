package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

const (
	// AESKeySize is the key size for AES-128 (16 bytes / 128 bits).
	// discv5 uses AES-128-GCM for message encryption.
	AESKeySize = 16

	// GCMNonceSize is the nonce size for GCM mode (12 bytes / 96 bits).
	// This is the recommended nonce size for AES-GCM.
	GCMNonceSize = 12

	// GCMTagSize is the authentication tag size for GCM mode (16 bytes / 128 bits).
	// This provides 128-bit authentication security.
	GCMTagSize = 16
)

var (
	// ErrInvalidKeySize is returned when an invalid key size is provided.
	ErrInvalidKeySize = fmt.Errorf("crypto: invalid key size, expected %d bytes", AESKeySize)

	// ErrInvalidNonceSize is returned when an invalid nonce size is provided.
	ErrInvalidNonceSize = fmt.Errorf("crypto: invalid nonce size, expected %d bytes", GCMNonceSize)

	// ErrDecryptionFailed is returned when GCM decryption/authentication fails.
	ErrDecryptionFailed = fmt.Errorf("crypto: decryption or authentication failed")
)

// AESGCMEncrypt encrypts plaintext using AES-128-GCM.
//
// Parameters:
//   - key: 16-byte AES-128 key
//   - nonce: 12-byte nonce (must be unique for each message with the same key)
//   - plaintext: Data to encrypt
//   - additionalData: Additional authenticated data (AAD) that is authenticated but not encrypted
//
// Returns ciphertext with authentication tag appended (len = len(plaintext) + 16).
//
// The nonce MUST be unique for each encryption with the same key.
// Reusing a nonce compromises security. In discv5, nonces are derived
// from message sequence numbers or generated randomly.
//
// Example:
//
//	key := []byte{...} // 16 bytes
//	nonce, _ := GenerateRandomBytes(12)
//	ciphertext, err := AESGCMEncrypt(key, nonce, []byte("secret message"), nil)
func AESGCMEncrypt(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, ErrInvalidKeySize
	}

	if len(nonce) != GCMNonceSize {
		return nil, ErrInvalidNonceSize
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create GCM: %w", err)
	}

	// Encrypt and authenticate
	ciphertext := gcm.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// AESGCMDecrypt decrypts ciphertext using AES-128-GCM.
//
// Parameters:
//   - key: 16-byte AES-128 key (must match encryption key)
//   - nonce: 12-byte nonce (must match encryption nonce)
//   - ciphertext: Encrypted data with authentication tag (from AESGCMEncrypt)
//   - additionalData: Additional authenticated data (must match encryption AAD)
//
// Returns plaintext if decryption and authentication succeed.
// Returns ErrDecryptionFailed if the ciphertext has been tampered with
// or if the key/nonce/AAD don't match.
//
// Example:
//
//	plaintext, err := AESGCMDecrypt(key, nonce, ciphertext, nil)
//	if err != nil {
//	    // Decryption failed - either wrong key or tampered ciphertext
//	    return err
//	}
func AESGCMDecrypt(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(key) != AESKeySize {
		return nil, ErrInvalidKeySize
	}

	if len(nonce) != GCMNonceSize {
		return nil, ErrInvalidNonceSize
	}

	// Ciphertext must include the authentication tag (at least 16 bytes)
	if len(ciphertext) < GCMTagSize {
		return nil, fmt.Errorf("crypto: ciphertext too short")
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create GCM: %w", err)
	}

	// Decrypt and verify authentication
	plaintext, err := gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// EncryptSession encrypts a message using session keys.
//
// This is a convenience wrapper around AESGCMEncrypt that handles
// the session key format used in discv5.
//
// Parameters:
//   - encryptionKey: 16-byte session encryption key
//   - nonce: 12-byte nonce
//   - message: Message to encrypt
//   - header: Protocol header (used as AAD)
//
// Example:
//
//	encryptionKey := session.EncryptionKey()
//	nonce := session.NextNonce()
//	ciphertext, err := EncryptSession(encryptionKey, nonce, message, header)
func EncryptSession(encryptionKey, nonce, message, header []byte) ([]byte, error) {
	return AESGCMEncrypt(encryptionKey, nonce, message, header)
}

// DecryptSession decrypts a message using session keys.
//
// This is a convenience wrapper around AESGCMDecrypt that handles
// the session key format used in discv5.
//
// Parameters:
//   - decryptionKey: 16-byte session decryption key
//   - nonce: 12-byte nonce (from message header)
//   - ciphertext: Encrypted message
//   - header: Protocol header (used as AAD)
//
// Example:
//
//	decryptionKey := session.DecryptionKey()
//	plaintext, err := DecryptSession(decryptionKey, nonce, ciphertext, header)
func DecryptSession(decryptionKey, nonce, ciphertext, header []byte) ([]byte, error) {
	return AESGCMDecrypt(decryptionKey, nonce, ciphertext, header)
}

// GenerateNonce generates a random 12-byte nonce for AES-GCM.
//
// Each nonce must be unique for a given key. In discv5, nonces
// are typically derived from message sequence numbers rather than
// generated randomly, to ensure uniqueness and allow replay detection.
//
// Example:
//
//	nonce, err := GenerateNonce()
//	if err != nil {
//	    return err
//	}
//	ciphertext, _ := AESGCMEncrypt(key, nonce, plaintext, nil)
func GenerateNonce() ([]byte, error) {
	return GenerateRandomBytes(GCMNonceSize)
}

// NonceFromUint64 converts a uint64 counter to a 12-byte nonce.
//
// This is used in discv5 to derive nonces from message sequence numbers.
// The counter is encoded as a big-endian uint64 in the last 8 bytes,
// with the first 4 bytes set to zero.
//
// Format: [0, 0, 0, 0, counter as 8 bytes big-endian]
//
// Example:
//
//	nonce := NonceFromUint64(session.GetAndIncrementCounter())
//	ciphertext, _ := AESGCMEncrypt(key, nonce, plaintext, nil)
func NonceFromUint64(counter uint64) []byte {
	nonce := make([]byte, GCMNonceSize)
	// Put counter in last 8 bytes (big-endian)
	for i := 0; i < 8; i++ {
		nonce[GCMNonceSize-1-i] = byte(counter >> (uint(i) * 8))
	}
	return nonce
}

// ExtractNonceCounter extracts the counter from a nonce created by NonceFromUint64.
//
// This is useful for replay detection and message ordering.
func ExtractNonceCounter(nonce []byte) (uint64, error) {
	if len(nonce) != GCMNonceSize {
		return 0, ErrInvalidNonceSize
	}

	var counter uint64
	for i := 0; i < 8; i++ {
		counter |= uint64(nonce[GCMNonceSize-1-i]) << (uint(i) * 8)
	}
	return counter, nil
}
