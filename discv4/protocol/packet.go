package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

// Packet structure:
// [MAC (32 bytes)][Signature (65 bytes)][Packet Type (1 byte)][RLP Data]
//
// The MAC is Keccak256(signature || type || data)
// The signature is ECDSA over Keccak256(type || data)

const (
	macSize  = 32                     // Size of the MAC hash
	sigSize  = crypto.SignatureLength // Size of ECDSA signature (65 bytes)
	headSize = macSize + sigSize      // Total header size (97 bytes)
)

var (
	// ErrPacketTooSmall is returned when a packet is smaller than the minimum size
	ErrPacketTooSmall = errors.New("packet too small")

	// ErrBadHash is returned when the MAC hash doesn't match
	ErrBadHash = errors.New("bad hash")

	// ErrBadSignature is returned when signature recovery fails
	ErrBadSignature = errors.New("bad signature")

	// ErrUnknownPacket is returned for unknown packet types
	ErrUnknownPacket = errors.New("unknown packet type")

	// ErrExpired is returned when a packet has expired
	ErrExpired = errors.New("packet expired")
)

// headSpace is a buffer used during encoding
var headSpace = make([]byte, headSize)

// Decode decodes a discv4 UDP packet.
//
// Returns:
//   - packet: The decoded packet message
//   - fromKey: The sender's public key (64 bytes, uncompressed without 0x04)
//   - hash: The packet hash (used as reply token)
//   - error: Any decoding error
//
// The packet structure is:
//
//	[MAC 32][Signature 65][Type 1][RLP Data...]
func Decode(input []byte) (Packet, Pubkey, []byte, error) {
	if len(input) < headSize+1 {
		return nil, Pubkey{}, nil, ErrPacketTooSmall
	}

	// Extract components
	hash := input[:macSize]
	sig := input[macSize:headSize]
	sigdata := input[headSize:] // Type + RLP data

	// Verify MAC hash
	shouldhash := crypto.Keccak256(input[macSize:])
	if !bytes.Equal(hash, shouldhash) {
		return nil, Pubkey{}, nil, ErrBadHash
	}

	// Recover sender's public key from signature
	fromKey, err := recoverNodeKey(crypto.Keccak256(input[headSize:]), sig)
	if err != nil {
		return nil, fromKey, hash, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}

	// Decode packet based on type
	var req Packet
	switch ptype := sigdata[0]; ptype {
	case PingPacket:
		req = new(Ping)
	case PongPacket:
		req = new(Pong)
	case FindnodePacket:
		req = new(Findnode)
	case NeighborsPacket:
		req = new(Neighbors)
	case ENRRequestPacket:
		req = new(ENRRequest)
	case ENRResponsePacket:
		req = new(ENRResponse)
	default:
		return nil, fromKey, hash, fmt.Errorf("%w: %d", ErrUnknownPacket, ptype)
	}

	// Decode RLP data
	// Use NewStream for forward compatibility (allows trailing data)
	s := rlp.NewStream(bytes.NewReader(sigdata[1:]), 0)
	if err := s.Decode(req); err != nil {
		return nil, fromKey, hash, fmt.Errorf("rlp decode error: %w", err)
	}

	return req, fromKey, hash, nil
}

// Encode encodes a discv4 packet with signature.
//
// Returns:
//   - packet: The complete encoded packet
//   - hash: The packet hash (used as reply token)
//   - error: Any encoding error
//
// The packet structure is:
//
//	[MAC 32][Signature 65][Type 1][RLP Data...]
func Encode(priv *ecdsa.PrivateKey, req Packet) (packet, hash []byte, err error) {
	// Build packet: [headSpace][Type][RLP Data]
	b := new(bytes.Buffer)
	b.Write(headSpace)
	b.WriteByte(req.Kind())

	// RLP encode the message
	if err := rlp.Encode(b, req); err != nil {
		return nil, nil, fmt.Errorf("rlp encode error: %w", err)
	}

	packet = b.Bytes()

	// Sign the packet data (type + RLP)
	sig, err := crypto.Sign(crypto.Keccak256(packet[headSize:]), priv)
	if err != nil {
		return nil, nil, fmt.Errorf("signing error: %w", err)
	}

	// Copy signature into packet
	copy(packet[macSize:], sig)

	// Calculate and add MAC hash
	hash = crypto.Keccak256(packet[macSize:])
	copy(packet, hash)

	return packet, hash, nil
}

// recoverNodeKey recovers the public key from a signature.
//
// Returns the public key in the wire format (64 bytes, X||Y without 0x04 prefix).
func recoverNodeKey(hash, sig []byte) (Pubkey, error) {
	var key Pubkey

	// Recover the full public key (65 bytes with 0x04 prefix)
	pubkey, err := crypto.Ecrecover(hash, sig)
	if err != nil {
		return key, err
	}

	// Copy without the 0x04 prefix
	copy(key[:], pubkey[1:])
	return key, nil
}

// EncodePacket is a convenience function to encode a packet.
//
// This is useful when you just need the packet bytes without the hash.
func EncodePacket(priv *ecdsa.PrivateKey, req Packet) ([]byte, error) {
	packet, _, err := Encode(priv, req)
	return packet, err
}

// DecodePacket is a convenience function to decode a packet.
//
// This is useful when you don't need the sender key or hash.
func DecodePacket(input []byte) (Packet, error) {
	packet, _, _, err := Decode(input)
	return packet, err
}
