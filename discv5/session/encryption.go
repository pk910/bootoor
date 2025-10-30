package session

import (
	"fmt"

	"github.com/pk910/bootoor/discv5/crypto"
)

// EncryptMessage encrypts a message using AES-128-GCM.
//
// The encryption uses:
//   - Key: 16-byte session key (initiator or recipient key)
//   - Nonce: 12-byte nonce from packet header
//   - Additional Data: Complete packet header (IV + masked static header + masked authdata)
//
// Returns the ciphertext with appended authentication tag (16 bytes).
//
// According to discv5 spec, authData for GCM is the entire header data before the message.
// For ordinary packets, this is typically 71 bytes (16 IV + 23 header + 32 authdata).
//
// Example:
//
//	ciphertext, err := EncryptMessage(key, nonce, headerData, plaintext)
func EncryptMessage(key, nonce, authData, plaintext []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("session: invalid key length: %d (expected 16)", len(key))
	}

	if len(nonce) != 12 {
		return nil, fmt.Errorf("session: invalid nonce length: %d (expected 12)", len(nonce))
	}

	// Use crypto module for AES-GCM encryption
	ciphertext, err := crypto.AESGCMEncrypt(key, nonce, plaintext, authData)
	if err != nil {
		return nil, fmt.Errorf("session: encryption failed: %w", err)
	}

	return ciphertext, nil
}

// DecryptMessage decrypts a message using AES-128-GCM.
//
// The decryption uses:
//   - Key: 16-byte session key (initiator or recipient key)
//   - Nonce: 12-byte nonce from packet header
//   - Additional Data: Complete packet header (IV + masked static header + masked authdata)
//
// The ciphertext must include the 16-byte authentication tag at the end.
//
// According to discv5 spec, authData for GCM is the entire header data before the message.
//
// Example:
//
//	plaintext, err := DecryptMessage(key, nonce, headerData, ciphertext)
func DecryptMessage(key, nonce, authData, ciphertext []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("session: invalid key length: %d (expected 16)", len(key))
	}

	if len(nonce) != 12 {
		return nil, fmt.Errorf("session: invalid nonce length: %d (expected 12)", len(nonce))
	}

	// Use crypto module for AES-GCM decryption
	plaintext, err := crypto.AESGCMDecrypt(key, nonce, ciphertext, authData)
	if err != nil {
		return nil, fmt.Errorf("session: decryption failed: %w", err)
	}

	return plaintext, nil
}
