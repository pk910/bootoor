// Package node provides core types for representing network nodes.
//
// A Node combines:
//   - Identity: ENR record with node metadata
//   - Network info: IP address, UDP/TCP ports
//   - Statistics: Last seen, failure counts, RTT
//
// Nodes are the fundamental unit in the discv5 peer discovery system.
package node

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pk910/bootoor/discv5/enr"
)

// ID represents a unique node identifier (32 bytes).
//
// The node ID is derived from the node's public key:
//
//	nodeID = keccak256(uncompressed_pubkey[1:])
//
// This ID is used in the Kademlia DHT for routing and distance calculations.
type ID [32]byte

// String returns the hex representation of the node ID.
func (id ID) String() string {
	return fmt.Sprintf("%x", id[:])
}

// Bytes returns the byte slice representation of the node ID.
func (id ID) Bytes() []byte {
	return id[:]
}

// PubkeyToID converts a public key to a node ID.
//
// Example:
//
//	privKey, _ := crypto.GenerateKey()
//	nodeID := PubkeyToID(&privKey.PublicKey)
func PubkeyToID(pub *ecdsa.PublicKey) ID {
	var id ID
	// Remove 0x04 prefix from uncompressed public key
	hash := crypto.Keccak256(crypto.FromECDSAPub(pub)[1:])
	copy(id[:], hash)
	return id
}

// Node represents a network node in the discv5 protocol.
//
// It combines the node's ENR record with additional runtime information
// like network statistics and last seen time.
type Node struct {
	// record is the ENR record containing node identity and metadata
	record *enr.Record

	// id is the cached node ID derived from the public key
	id ID

	// addr is the network address (IP + UDP port)
	addr *net.UDPAddr

	// tcpPort is the TCP port (if different from UDP)
	tcpPort uint16

	// firstSeen is the first time we discovered this node
	firstSeen time.Time

	// lastSeen is the last time we successfully communicated with this node
	lastSeen time.Time

	// lastPing is the last time we sent a PING to this node
	lastPing time.Time

	// failureCount tracks consecutive failed communication attempts
	failureCount int

	// successCount tracks successful communications
	successCount int

	// avgRTT is the average round-trip time for PING/PONG
	avgRTT time.Duration
}

// New creates a new Node from an ENR record.
//
// The node ID and network address are extracted from the ENR.
// Returns an error if the ENR is missing required fields.
//
// Example:
//
//	privKey, _ := crypto.GenerateKey()
//	record, _ := enr.CreateSignedRecord(
//	    privKey,
//	    "ip", net.IPv4(192, 168, 1, 1),
//	    "udp", uint16(9000),
//	)
//	node, err := New(record)
func New(record *enr.Record) (*Node, error) {
	if record == nil {
		return nil, fmt.Errorf("node: nil ENR record")
	}

	// Extract public key and derive node ID
	pubKey := record.PublicKey()
	if pubKey == nil {
		return nil, fmt.Errorf("node: ENR missing public key")
	}
	id := PubkeyToID(pubKey)

	// Extract IP address
	ip := record.IP()
	if ip == nil {
		ip = record.IP6()
	}
	if ip == nil {
		return nil, fmt.Errorf("node: ENR missing IP address")
	}

	// Extract UDP port
	udpPort := record.UDP()
	if udpPort == 0 {
		return nil, fmt.Errorf("node: ENR missing UDP port")
	}

	// Create UDP address
	addr := &net.UDPAddr{
		IP:   ip,
		Port: int(udpPort),
	}

	// Extract optional TCP port
	tcpPort := record.TCP()

	now := time.Now()
	return &Node{
		record:       record,
		id:           id,
		addr:         addr,
		tcpPort:      tcpPort,
		firstSeen:    now,
		lastSeen:     time.Time{}, // Zero time indicates never seen
		lastPing:     time.Time{},
		failureCount: 0,
		successCount: 0,
		avgRTT:       0,
	}, nil
}

// ID returns the node's unique identifier.
func (n *Node) ID() ID {
	return n.id
}

// Record returns the node's ENR record.
func (n *Node) Record() *enr.Record {
	return n.record
}

// Addr returns the node's UDP address.
func (n *Node) Addr() *net.UDPAddr {
	return n.addr
}

// IP returns the node's IP address.
func (n *Node) IP() net.IP {
	return n.addr.IP
}

// UDPPort returns the node's UDP port.
func (n *Node) UDPPort() uint16 {
	return uint16(n.addr.Port)
}

// TCPPort returns the node's TCP port (0 if not set).
func (n *Node) TCPPort() uint16 {
	return n.tcpPort
}

// PublicKey returns the node's public key.
func (n *Node) PublicKey() *ecdsa.PublicKey {
	return n.record.PublicKey()
}

// PeerID returns the libp2p peer ID for this node.
//
// The peer ID is constructed from the secp256k1 public key using the libp2p format:
//   - Compressed secp256k1 public key (33 bytes)
//   - Wrapped in libp2p PublicKey protobuf message:
//   - Field 1 (Type): 0x08 0x02 (secp256k1 = 2)
//   - Field 2 (Data): 0x12 0x21 [33 bytes of compressed key]
//   - Wrapped in IDENTITY multihash (code 0x00)
//   - Base58 encoded
//
// Example output: "16Uiu2HAkyttpvpDTRdEnUqSPvbDpRgbSgrmeqTqi4R7EWECG5jso"
func (n *Node) PeerID() string {
	pubKey := n.PublicKey()
	if pubKey == nil {
		return ""
	}

	return BuildPeerID(pubKey)
}

// Digest returns the node's fork digest.
func (n *Node) Digest() [4]byte {
	eth2Data, ok := n.record.Eth2()
	if !ok {
		return [4]byte{}
	}
	return eth2Data.ForkDigest
}

// FirstSeen returns the first time we discovered this node.
func (n *Node) FirstSeen() time.Time {
	return n.firstSeen
}

// SetFirstSeen updates the first seen time.
func (n *Node) SetFirstSeen(t time.Time) {
	n.firstSeen = t
}

// LastSeen returns the last time this node was seen.
//
// A zero time indicates the node has never been successfully contacted.
func (n *Node) LastSeen() time.Time {
	return n.lastSeen
}

// SetLastSeen updates the last seen time to now.
//
// This should be called when we receive a valid response from the node.
func (n *Node) SetLastSeen(t time.Time) {
	n.lastSeen = t
}

// LastPing returns the last time we sent a PING to this node.
func (n *Node) LastPing() time.Time {
	return n.lastPing
}

// SetLastPing updates the last ping time to now.
func (n *Node) SetLastPing(t time.Time) {
	n.lastPing = t
}

// FailureCount returns the number of consecutive failed attempts.
func (n *Node) FailureCount() int {
	return n.failureCount
}

// SetFailureCount sets the failure count.
func (n *Node) SetFailureCount(count int) {
	n.failureCount = count
}

// SetSuccessCount sets the success count.
func (n *Node) SetSuccessCount(count int) {
	n.successCount = count
}

// IncrementFailureCount increases the failure count by 1.
//
// This should be called when communication with the node fails.
func (n *Node) IncrementFailureCount() {
	n.failureCount++
}

// ResetFailureCount resets the failure count to 0.
//
// This should be called when communication succeeds.
func (n *Node) ResetFailureCount() {
	n.failureCount = 0
	n.successCount++
}

// SuccessCount returns the total number of successful communications.
func (n *Node) SuccessCount() int {
	return n.successCount
}

// AvgRTT returns the average round-trip time for PING/PONG.
func (n *Node) AvgRTT() time.Duration {
	return n.avgRTT
}

// UpdateRTT updates the average RTT using exponential moving average.
//
// The new average is: avgRTT = (0.875 * avgRTT) + (0.125 * newRTT)
// This gives more weight to recent measurements while smoothing out noise.
func (n *Node) UpdateRTT(rtt time.Duration) {
	if n.avgRTT == 0 {
		n.avgRTT = rtt
	} else {
		// Exponential moving average (7/8 old + 1/8 new)
		n.avgRTT = (n.avgRTT * 7 / 8) + (rtt / 8)
	}
}

// IsAlive checks if the node is considered alive.
//
// A node is alive if:
//   - It has been seen recently (within the last 24 hours), AND
//   - The failure count is below the threshold (< 3)
func (n *Node) IsAlive(maxAge time.Duration, maxFailures int) bool {
	if n.lastSeen.IsZero() {
		return false // Never seen
	}

	age := time.Since(n.lastSeen)
	return age < maxAge && n.failureCount < maxFailures
}

// NeedsPing checks if the node needs a liveness check.
//
// Returns true if:
//   - We've never pinged it, OR
//   - It's been longer than pingInterval since the last ping
func (n *Node) NeedsPing(pingInterval time.Duration) bool {
	if n.lastPing.IsZero() {
		return true // Never pinged
	}

	return time.Since(n.lastPing) > pingInterval
}

// UpdateENR updates the node's ENR record if the new one has a higher sequence number.
//
// Returns true if the record was updated, false if the current record is newer.
func (n *Node) UpdateENR(newRecord *enr.Record) bool {
	if newRecord == nil {
		return false
	}

	// Only update if new record has higher sequence number
	if newRecord.Seq() > n.record.Seq() {
		n.record = newRecord

		// Update network address if changed
		ip := newRecord.IP()
		if ip == nil {
			ip = newRecord.IP6()
		}
		udpPort := newRecord.UDP()
		if ip != nil && udpPort != 0 {
			n.addr = &net.UDPAddr{
				IP:   ip,
				Port: int(udpPort),
			}
		}

		n.tcpPort = newRecord.TCP()
		return true
	}

	return false
}

// String returns a human-readable representation of the node.
//
// Format: Node[id=abc123..., addr=192.168.1.1:9000, seen=1m ago]
func (n *Node) String() string {
	var seenStr string
	if n.lastSeen.IsZero() {
		seenStr = "never"
	} else {
		seenStr = fmt.Sprintf("%v ago", time.Since(n.lastSeen).Round(time.Second))
	}

	return fmt.Sprintf("Node[id=%s, addr=%s, seen=%s]",
		n.id.String()[:8]+"...", // First 8 chars of ID
		n.addr.String(),
		seenStr,
	)
}

// Stats returns a snapshot of the node's statistics.
type Stats struct {
	FirstSeen    time.Time
	LastSeen     time.Time
	LastPing     time.Time
	FailureCount int
	SuccessCount int
	AvgRTT       time.Duration
	ENRSeq       uint64
}

// GetStats returns the current statistics for the node.
func (n *Node) GetStats() Stats {
	return Stats{
		FirstSeen:    n.firstSeen,
		LastSeen:     n.lastSeen,
		LastPing:     n.lastPing,
		FailureCount: n.failureCount,
		SuccessCount: n.successCount,
		AvgRTT:       n.avgRTT,
		ENRSeq:       n.record.Seq(),
	}
}
