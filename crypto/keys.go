// Package crypto provides cryptographic utilities for the discv5 protocol.
//
// This package wraps and extends go-ethereum's crypto primitives with
// discv5-specific functionality:
//   - ECDH key agreement for session establishment
//   - AES-GCM encryption and decryption
//   - HKDF key derivation for session keys
//
// For basic key operations (generation, signing, verification), use
// github.com/ethereum/go-ethereum/crypto directly.
package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"io"

	"github.com/ethereum/go-ethereum/crypto"
)

// NodeID returns the node ID derived from a public key.
//
// The node ID is computed as:
//
//	nodeID = keccak256(uncompressed_public_key[1:])
//
// This is the 32-byte identifier used in the Kademlia DHT and routing table.
//
// Example:
//
//	privKey, _ := crypto.GenerateKey()
//	nodeID := NodeID(&privKey.PublicKey)
//	fmt.Printf("Node ID: %x\n", nodeID)
func NodeID(pubKey *ecdsa.PublicKey) []byte {
	// Remove the 0x04 prefix from uncompressed key
	uncompressed := crypto.FromECDSAPub(pubKey)[1:]
	return crypto.Keccak256(uncompressed)
}

// GenerateRandomBytes generates n random bytes using a cryptographically secure RNG.
//
// This uses crypto/rand.Read which is the standard way to generate
// cryptographically secure random bytes in Go.
//
// Example:
//
//	nonce, err := GenerateRandomBytes(16)
//	if err != nil {
//	    return err
//	}
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	// Use crypto/rand for cryptographically secure random bytes
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
