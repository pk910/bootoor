package crypto

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/hkdf"
)

// HKDFExtract performs HKDF key derivation (extract-and-expand).
//
// HKDF (HMAC-based Key Derivation Function) is used in discv5 to derive
// session keys from the ECDH shared secret. It provides cryptographic
// separation between different uses of the same shared secret.
//
// Parameters:
//   - salt: Optional salt value (can be nil). Used for key stretching.
//   - ikm: Input key material (e.g., ECDH shared secret)
//   - info: Context-specific information (e.g., "discovery v5 session keys")
//   - keyLen: Desired output length in bytes
//
// The info parameter is crucial for domain separation - it ensures that
// keys derived for different purposes are cryptographically independent.
//
// Returns keyLen bytes of key material.
//
// Example:
//
//	sharedSecret, _ := ECDH(localPriv, remotePub)
//	sessionKey, err := HKDFExtract(
//	    nil, // No salt
//	    sharedSecret,
//	    []byte("discovery v5 session"),
//	    16, // 128-bit key
//	)
func HKDFExtract(salt, ikm, info []byte, keyLen int) ([]byte, error) {
	if keyLen <= 0 {
		return nil, fmt.Errorf("crypto: invalid key length: %d", keyLen)
	}

	// HKDF uses HMAC-SHA256
	hkdf := hkdf.New(sha256.New, ikm, salt, info)

	// Extract key material
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, fmt.Errorf("crypto: HKDF extraction failed: %w", err)
	}

	return key, nil
}

// DeriveSessionKeys derives both encryption and decryption keys from a shared secret.
//
// In discv5, sessions use separate keys for each direction:
//   - initiatorKey: Used by the initiator to encrypt, recipient to decrypt
//   - recipientKey: Used by the recipient to encrypt, initiator to decrypt
//
// This function derives both keys from the shared secret using HKDF with
// different context strings for domain separation.
//
// Parameters:
//   - sharedSecret: ECDH shared secret (32 bytes)
//   - isInitiator: True if we are the session initiator, false if recipient
//   - challengeData: Challenge data from WHOAREYOU packet (for binding)
//
// Returns (ourEncryptionKey, ourDecryptionKey, error)
//
// Example:
//
//	sharedSecret, _ := ECDH(localPriv, remotePub)
//	encKey, decKey, err := DeriveSessionKeys(sharedSecret, true, challengeData)
//	// Use encKey for encrypting outgoing messages
//	// Use decKey for decrypting incoming messages
func DeriveSessionKeys(sharedSecret []byte, isInitiator bool, challengeData []byte) ([]byte, []byte, error) {
	if len(sharedSecret) != 32 {
		return nil, nil, fmt.Errorf("crypto: shared secret must be 32 bytes, got %d", len(sharedSecret))
	}

	// Combine challenge data with secret for key derivation
	ikm := append(sharedSecret, challengeData...)

	// Derive initiator key (used by initiator to encrypt)
	initiatorKey, err := HKDFExtract(
		nil,
		ikm,
		[]byte("discovery v5 initiator key"),
		AESKeySize,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: failed to derive initiator key: %w", err)
	}

	// Derive recipient key (used by recipient to encrypt)
	recipientKey, err := HKDFExtract(
		nil,
		ikm,
		[]byte("discovery v5 recipient key"),
		AESKeySize,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: failed to derive recipient key: %w", err)
	}

	// Return keys in the correct order based on our role
	if isInitiator {
		return initiatorKey, recipientKey, nil
	}
	return recipientKey, initiatorKey, nil
}

// DeriveHandshakeSecrets derives secrets used during the handshake.
//
// The discv5 handshake uses multiple derived secrets:
//   - Key agreement key: For encrypting the handshake response
//   - Challenge data: For binding the handshake to a specific node
//
// This function derives these secrets using HKDF with appropriate
// context strings.
//
// Parameters:
//   - nodeID: Local node ID (32 bytes)
//   - ephemeralSecret: ECDH shared secret from ephemeral keys
//   - challengeData: Random challenge from WHOAREYOU
//
// Example:
//
//	ephemeralSecret, _ := ECDH(ephemeralPriv, remotePub)
//	handshakeKey, err := DeriveHandshakeSecrets(localNodeID, ephemeralSecret, challenge)
func DeriveHandshakeSecrets(nodeID, ephemeralSecret, challengeData []byte) ([]byte, error) {
	if len(nodeID) != 32 {
		return nil, fmt.Errorf("crypto: node ID must be 32 bytes, got %d", len(nodeID))
	}

	if len(ephemeralSecret) != 32 {
		return nil, fmt.Errorf("crypto: ephemeral secret must be 32 bytes, got %d", len(ephemeralSecret))
	}

	// Combine inputs for key derivation
	ikm := append(append(nodeID, ephemeralSecret...), challengeData...)

	// Derive handshake key
	handshakeKey, err := HKDFExtract(
		nil,
		ikm,
		[]byte("discovery v5 handshake"),
		AESKeySize,
	)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to derive handshake key: %w", err)
	}

	return handshakeKey, nil
}

// DeriveKey is a general-purpose key derivation function.
//
// This is a more flexible version of HKDFExtract that allows
// specifying custom context strings for different use cases.
//
// Example:
//
//	// Derive different keys for different purposes from same secret
//	encKey := DeriveKey(secret, "encryption", 16)
//	macKey := DeriveKey(secret, "authentication", 32)
func DeriveKey(secret []byte, context string, keyLen int) ([]byte, error) {
	return HKDFExtract(nil, secret, []byte(context), keyLen)
}

// DeriveIDSignature derives a signature key for node identity.
//
// This is used in the handshake to prove ownership of a node ID
// without revealing the long-term private key.
func DeriveIDSignature(nodePrivKey *ecdsa.PrivateKey, ephemeralPubKey *ecdsa.PublicKey) ([]byte, error) {
	// Get node ID from private key
	nodeID := NodeID(&nodePrivKey.PublicKey)

	// Get compressed ephemeral public key
	ephemeralBytes := crypto.CompressPubkey(ephemeralPubKey)

	// Combine for signing
	data := append(nodeID, ephemeralBytes...)

	// Hash the data
	hash := crypto.Keccak256(data)

	// Sign with node private key
	sig, err := crypto.Sign(hash, nodePrivKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: failed to create ID signature: %w", err)
	}

	return sig, nil
}

// VerifyIDSignature verifies a node identity signature.
//
// This is used to verify that a peer actually owns the claimed node ID.
func VerifyIDSignature(sig []byte, nodeID []byte, ephemeralPubKey *ecdsa.PublicKey) bool {
	// Get compressed ephemeral public key
	ephemeralBytes := crypto.CompressPubkey(ephemeralPubKey)

	// Reconstruct signed data
	data := append(nodeID, ephemeralBytes...)

	// Hash the data
	hash := crypto.Keccak256(data)

	// Recover public key from signature
	recoveredPubKey, err := crypto.SigToPub(hash, sig)
	if err != nil {
		return false
	}

	// Verify that recovered public key matches claimed node ID
	recoveredNodeID := NodeID(recoveredPubKey)
	return constantTimeCompare(recoveredNodeID, nodeID)
}

// constantTimeCompare performs constant-time comparison of two byte slices.
//
// This prevents timing attacks when comparing sensitive data like
// cryptographic keys or authentication tags.
func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
