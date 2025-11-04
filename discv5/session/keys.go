// Package session implements session management and encryption for discv5.
//
// The session module handles:
//   - WHOAREYOU challenge/response handshakes
//   - Session key derivation using ECDH + HKDF
//   - AES-GCM encryption and decryption
//   - Session caching and lifecycle management
//   - Nonce tracking to prevent replay attacks
package session

import (
	"crypto/ecdsa"
	"fmt"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/crypto"
	"github.com/ethpandaops/bootnodoor/discv5/node"
)

// SessionKeys contains the derived encryption keys for a session.
//
// Keys are derived from the ECDH shared secret using HKDF-SHA256
// with protocol-specific context strings.
type SessionKeys struct {
	// InitiatorKey is used by the session initiator for encryption
	InitiatorKey []byte

	// RecipientKey is used by the session recipient for encryption
	RecipientKey []byte

	// AuthRespKey is used for authenticating handshake responses
	AuthRespKey []byte
}

// DeriveSessionKeys derives session keys from an ECDH shared secret.
//
// The key derivation follows the discv5 specification:
//  1. Compute ECDH shared secret from ephemeral keys
//  2. Use HKDF-SHA256 to derive three keys:
//     - initiator-key (16 bytes)
//     - recipient-key (16 bytes)
//     - auth-resp-key (16 bytes)
//
// Parameters:
//   - secret: ECDH shared secret
//   - initiatorNodeID: Node ID of the session initiator
//   - recipientNodeID: Node ID of the session recipient
//   - challengeData: Challenge data from WHOAREYOU packet (idnonce)
//
// Example:
//
//	secret, _ := crypto.ComputeECDH(localPrivKey, remotePubKey)
//	keys, err := DeriveSessionKeys(secret, localNodeID, remoteNodeID, challenge)
func DeriveSessionKeys(
	secret []byte,
	initiatorNodeID node.ID,
	recipientNodeID node.ID,
	challengeData []byte,
) (*SessionKeys, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("session: empty ECDH secret")
	}

	if len(initiatorNodeID) != 32 || len(recipientNodeID) != 32 {
		return nil, fmt.Errorf("session: invalid node ID lengths")
	}

	if len(challengeData) != 32 {
		return nil, fmt.Errorf("session: invalid challenge data length: %d", len(challengeData))
	}

	// Construct info string for HKDF: "discovery v5 key agreement" + initiator-id + recipient-id
	info := make([]byte, 0, 26+32+32)
	info = append(info, []byte("discovery v5 key agreement")...)
	info = append(info, initiatorNodeID[:]...)
	info = append(info, recipientNodeID[:]...)

	// Derive 48 bytes total (16 + 16 + 16)
	keyMaterial, err := crypto.HKDFExtract(challengeData, secret, info, 48)
	if err != nil {
		return nil, fmt.Errorf("session: key derivation failed: %w", err)
	}

	keys := &SessionKeys{
		InitiatorKey: keyMaterial[0:16],
		RecipientKey: keyMaterial[16:32],
		AuthRespKey:  keyMaterial[32:48],
	}

	return keys, nil
}

// GenerateEphemeralKey generates a new ephemeral ECDSA key pair.
//
// Ephemeral keys are used once per session and discarded after
// the session keys are derived.
//
// Example:
//
//	ephemeralKey, err := GenerateEphemeralKey()
//	if err != nil {
//	    return err
//	}
func GenerateEphemeralKey() (*ecdsa.PrivateKey, error) {
	// Use go-ethereum's crypto package for key generation
	// Import at package level: "github.com/ethereum/go-ethereum/crypto" as ethcrypto
	return ethcrypto.GenerateKey()
}
