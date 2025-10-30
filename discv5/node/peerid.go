package node

import (
	"crypto/ecdsa"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multihash"
)

func BuildPeerID(pubKey *ecdsa.PublicKey) string {
	compressedPubKey := crypto.CompressPubkey(pubKey)

	// Wrap in libp2p PublicKey protobuf message
	// Field 1 (Type): wire type 0 (varint), field number 1: 0x08, value 0x02 (secp256k1)
	// Field 2 (Data): wire type 2 (length-delimited), field number 2: 0x12, length 0x21 (33), key bytes
	protobuf := make([]byte, 0, 37)
	protobuf = append(protobuf, 0x08, 0x02) // Type field: secp256k1 = 0x02 (2)
	protobuf = append(protobuf, 0x12, 0x21) // Data field: length 33 (0x21)
	protobuf = append(protobuf, compressedPubKey...)

	// Wrap in IDENTITY multihash (code 0x00)
	multihashBytes, err := multihash.Encode(protobuf, multihash.IDENTITY)
	if err != nil {
		return ""
	}

	// Base58 encode the multihash
	return base58.Encode(multihashBytes)
}
