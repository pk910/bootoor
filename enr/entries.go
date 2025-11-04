package enr

import (
	"crypto/ecdsa"
	"net"

	"github.com/ethereum/go-ethereum/crypto"
)

// Entry is an interface for ENR key-value entries.
//
// Each entry knows how to encode itself into a record and provides
// metadata about the entry (key name, description).
type Entry interface {
	// Key returns the ENR key for this entry
	Key() string
}

// WithIP sets the IPv4 address in the record.
//
// Example:
//
//	record.Set(WithIP(net.IPv4(192, 168, 1, 1)))
func WithIP(ip net.IP) (string, interface{}) {
	return "ip", ip.To4()
}

// WithIP6 sets the IPv6 address in the record.
//
// Example:
//
//	record.Set(WithIP6(net.ParseIP("2001:db8::1")))
func WithIP6(ip net.IP) (string, interface{}) {
	return "ip6", ip.To16()
}

// WithUDP sets the UDP port in the record.
//
// Example:
//
//	record.Set(WithUDP(9000))
func WithUDP(port uint16) (string, interface{}) {
	return "udp", port
}

// WithTCP sets the TCP port in the record.
//
// Example:
//
//	record.Set(WithTCP(9000))
func WithTCP(port uint16) (string, interface{}) {
	return "tcp", port
}

// WithPublicKey sets the secp256k1 public key in the record.
//
// The key is stored in compressed form (33 bytes).
//
// Example:
//
//	privateKey, _ := crypto.GenerateKey()
//	record.Set(WithPublicKey(&privateKey.PublicKey))
func WithPublicKey(pubKey *ecdsa.PublicKey) (string, interface{}) {
	return "secp256k1", crypto.CompressPubkey(pubKey)
}

// WithIdentityScheme sets the identity scheme in the record.
//
// Common schemes:
//   - "v4": secp256k1-based identity (most common)
//
// Example:
//
//	record.Set(WithIdentityScheme("v4"))
func WithIdentityScheme(scheme string) (string, interface{}) {
	return "id", scheme
}

// WithEth2 sets the eth2 field in the record.
//
// This field contains Ethereum 2.0 specific metadata including
// the fork digest, next fork version, and next fork epoch.
//
// Example:
//
//	eth2Data := Eth2ENRData{
//	    ForkDigest: [4]byte{0x01, 0x02, 0x03, 0x04},
//	    NextForkVersion: [4]byte{0x00, 0x00, 0x00, 0x00},
//	    NextForkEpoch: 0,
//	}
//	record.Set(WithEth2(eth2Data))
func WithEth2(data Eth2ENRData) (string, interface{}) {
	return "eth2", data
}

// WithAttnets sets the attnets field in the record.
//
// This field is a bitvector indicating which attestation subnets
// the Ethereum 2.0 node is subscribed to (used for subnet discovery).
//
// Example:
//
//	attnets := make([]byte, 8) // 64-bit bitvector
//	attnets[0] = 0xFF // Subscribed to first 8 subnets
//	record.Set(WithAttnets(attnets))
func WithAttnets(attnets []byte) (string, interface{}) {
	return "attnets", attnets
}

// WithSyncnets sets the syncnets field in the record.
//
// This field is a bitvector indicating which sync committee subnets
// the Ethereum 2.0 node is subscribed to.
//
// Example:
//
//	syncnets := make([]byte, 1) // 4-bit bitvector
//	syncnets[0] = 0x0F // Subscribed to all 4 subnets
//	record.Set(WithSyncnets(syncnets))
func WithSyncnets(syncnets []byte) (string, interface{}) {
	return "syncnets", syncnets
}

// Common helper functions for building records

// NewRecord creates a new ENR record with the given key-value pairs.
//
// This is a convenience function for building records with multiple fields.
//
// Example:
//
//	record, err := NewRecord(
//	    WithIP(net.IPv4(192, 168, 1, 1)),
//	    WithUDP(9000),
//	    WithTCP(9000),
//	)
func NewRecord(entries ...interface{}) (*Record, error) {
	record := New()

	// Process entries in pairs (key, value)
	for i := 0; i < len(entries); i += 2 {
		if i+1 >= len(entries) {
			break
		}

		key, ok := entries[i].(string)
		if !ok {
			continue
		}

		value := entries[i+1]
		if err := record.Set(key, value); err != nil {
			return nil, err
		}
	}

	return record, nil
}

// CreateSignedRecord creates and signs a new ENR record with the given entries.
//
// This is a convenience function that:
//  1. Creates a new record
//  2. Sets all provided entries
//  3. Signs the record with the private key
//
// Example:
//
//	privateKey, _ := crypto.GenerateKey()
//	record, err := CreateSignedRecord(
//	    privateKey,
//	    WithIP(net.IPv4(192, 168, 1, 1)),
//	    WithUDP(9000),
//	)
func CreateSignedRecord(privKey *ecdsa.PrivateKey, entries ...interface{}) (*Record, error) {
	record, err := NewRecord(entries...)
	if err != nil {
		return nil, err
	}

	if err := record.Sign(privKey); err != nil {
		return nil, err
	}

	return record, nil
}

// UpdateRecord creates an updated version of an existing record.
//
// The new record will have:
//   - Incremented sequence number
//   - All entries from the old record
//   - Updates from the provided entries
//   - New signature
//
// Example:
//
//	// Update IP address and UDP port
//	newRecord, err := UpdateRecord(
//	    oldRecord,
//	    privateKey,
//	    WithIP(net.IPv4(192, 168, 1, 2)),
//	    WithUDP(9001),
//	)
func UpdateRecord(old *Record, privKey *ecdsa.PrivateKey, entries ...interface{}) (*Record, error) {
	// Create new record with incremented sequence number
	record := New()
	record.SetSeq(old.Seq() + 1)

	// Copy all entries from old record
	for key, value := range old.Pairs() {
		if err := record.Set(key, value); err != nil {
			return nil, err
		}
	}

	// Apply updates
	for i := 0; i < len(entries); i += 2 {
		if i+1 >= len(entries) {
			break
		}

		key, ok := entries[i].(string)
		if !ok {
			continue
		}

		value := entries[i+1]
		if err := record.Set(key, value); err != nil {
			return nil, err
		}
	}

	// Sign the updated record
	if err := record.Sign(privKey); err != nil {
		return nil, err
	}

	return record, nil
}
