// Package enode implements parsing and encoding of the legacy enode:// URL format.
//
// The enode URL scheme is used in Ethereum's discv4 protocol to identify nodes.
// It has the form:
//
//	enode://<hex node id>@<ip>:<tcp_port>?discport=<udp_port>
//
// Where:
//   - hex node id: 128 hex characters (64 bytes) representing the uncompressed public key
//   - ip: IPv4 or IPv6 address
//   - tcp_port: TCP port for RLPx connections
//   - discport: Optional UDP port for discovery (defaults to tcp_port if omitted)
package enode

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"

	"github.com/ethereum/go-ethereum/crypto"
)

var (
	// incompleteNodeURL matches node URLs containing only the public key
	incompleteNodeURL = regexp.MustCompile("(?i)^(?:enode://)?([0-9a-f]+)$")

	// ErrInvalidScheme is returned when the URL scheme is not "enode"
	ErrInvalidScheme = errors.New("enode: invalid URL scheme, want \"enode\"")

	// ErrMissingNodeID is returned when the URL does not contain a node ID
	ErrMissingNodeID = errors.New("enode: does not contain node ID")

	// ErrInvalidNodeID is returned when the node ID is not 128 hex characters
	ErrInvalidNodeID = errors.New("enode: invalid node ID, want 128 hex characters")

	// ErrInvalidIP is returned when the IP address is invalid
	ErrInvalidIP = errors.New("enode: invalid IP address")

	// ErrInvalidPort is returned when the port is invalid
	ErrInvalidPort = errors.New("enode: invalid port")
)

// Enode represents a parsed enode:// URL.
//
// It contains the node's public key and network endpoint information.
type Enode struct {
	// PublicKey is the node's secp256k1 public key
	PublicKey *ecdsa.PublicKey

	// IP is the node's IP address (can be nil for incomplete nodes)
	IP net.IP

	// TCP is the TCP port for RLPx connections
	TCP uint16

	// UDP is the UDP port for discovery protocol
	UDP uint16

	// Hostname is the DNS hostname (if any)
	Hostname string
}

// Parse parses an enode:// URL string.
//
// Supported formats:
//   - Complete: enode://<hex-nodeid>@<ip>:<port>
//   - With discport: enode://<hex-nodeid>@<ip>:<port>?discport=<udp-port>
//   - Incomplete: enode://<hex-nodeid> or just <hex-nodeid>
//
// Example:
//
//	node, err := enode.Parse("enode://1dd9d65c4552b5eb43d5ad55a2ee3f56c6cbc1c64a5c8d659f51fcd51bace24351232b8d7821617d2b29b54b81cdefb9b3e9c37d7fd5f63270bcc9e1a6f6a439@127.0.0.1:30303?discport=30301")
func Parse(rawurl string) (*Enode, error) {
	// Check for incomplete URL (only node ID)
	if m := incompleteNodeURL.FindStringSubmatch(rawurl); m != nil {
		pubkey, err := parsePubkey(m[1])
		if err != nil {
			return nil, fmt.Errorf("enode: invalid public key: %w", err)
		}
		return &Enode{
			PublicKey: pubkey,
		}, nil
	}

	// Parse complete URL
	return parseComplete(rawurl)
}

// MustParse parses an enode:// URL and panics if parsing fails.
//
// This is useful for static URLs that are known to be valid.
func MustParse(rawurl string) *Enode {
	node, err := Parse(rawurl)
	if err != nil {
		panic("enode: invalid URL: " + err.Error())
	}
	return node
}

// parseComplete parses a complete enode:// URL with IP and port information.
func parseComplete(rawurl string) (*Enode, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, fmt.Errorf("enode: failed to parse URL: %w", err)
	}

	if u.Scheme != "enode" {
		return nil, ErrInvalidScheme
	}

	// Parse the node ID from the user portion
	if u.User == nil {
		return nil, ErrMissingNodeID
	}

	pubkey, err := parsePubkey(u.User.String())
	if err != nil {
		return nil, fmt.Errorf("enode: invalid public key: %w", err)
	}

	// Parse hostname (can be IP or DNS name)
	hostname := u.Hostname()
	if hostname == "" {
		return nil, errors.New("enode: missing hostname")
	}

	// Try to parse as IP address
	ip := net.ParseIP(hostname)

	// Parse TCP port
	portStr := u.Port()
	if portStr == "" {
		return nil, errors.New("enode: missing port")
	}

	tcpPort, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, ErrInvalidPort
	}

	// UDP port defaults to TCP port
	udpPort := tcpPort

	// Check for discport query parameter
	qv := u.Query()
	if qv.Get("discport") != "" {
		udpPort, err = strconv.ParseUint(qv.Get("discport"), 10, 16)
		if err != nil {
			return nil, errors.New("enode: invalid discport in query")
		}
	}

	node := &Enode{
		PublicKey: pubkey,
		IP:        ip,
		TCP:       uint16(tcpPort),
		UDP:       uint16(udpPort),
	}

	// Store hostname if it's not an IP address
	if ip == nil {
		node.Hostname = hostname
	}

	return node, nil
}

// parsePubkey parses a hex-encoded secp256k1 public key.
//
// The input should be 128 hex characters (64 bytes) representing
// the uncompressed public key without the 0x04 prefix.
func parsePubkey(in string) (*ecdsa.PublicKey, error) {
	b, err := hex.DecodeString(in)
	if err != nil {
		return nil, err
	}

	if len(b) != 64 {
		return nil, fmt.Errorf("%w (got %d hex chars, want 128)", ErrInvalidNodeID, len(in))
	}

	// Add the 0x04 prefix for uncompressed public key
	b = append([]byte{0x04}, b...)
	return crypto.UnmarshalPubkey(b)
}

// NodeID returns the Keccak256 hash of the public key.
//
// This is used as the node identifier in the discovery protocol.
func (e *Enode) NodeID() []byte {
	if e.PublicKey == nil {
		return nil
	}
	// Hash the uncompressed public key (without 0x04 prefix)
	pubBytes := crypto.FromECDSAPub(e.PublicKey)[1:]
	return crypto.Keccak256(pubBytes)
}

// String returns the enode URL representation.
//
// Format: enode://<hex-nodeid>@<ip>:<tcp-port>?discport=<udp-port>
//
// If UDP port equals TCP port, the discport parameter is omitted.
// If IP is not set (incomplete node), returns: enode://<hex-nodeid>
func (e *Enode) String() string {
	if e.PublicKey == nil {
		return "enode://<invalid>"
	}

	// Get the hex node ID (public key without 0x04 prefix)
	pubBytes := crypto.FromECDSAPub(e.PublicKey)[1:]
	nodeID := hex.EncodeToString(pubBytes)

	// If no IP/port, return incomplete format
	if e.IP == nil && e.Hostname == "" {
		return "enode://" + nodeID
	}

	u := url.URL{Scheme: "enode"}
	u.User = url.User(nodeID)

	// Use hostname if available, otherwise IP
	if e.Hostname != "" {
		u.Host = fmt.Sprintf("%s:%d", e.Hostname, e.TCP)
	} else {
		addr := net.TCPAddr{IP: e.IP, Port: int(e.TCP)}
		u.Host = addr.String()
	}

	// Add discport query parameter if UDP port differs from TCP port
	if e.UDP != e.TCP {
		u.RawQuery = "discport=" + strconv.Itoa(int(e.UDP))
	}

	return u.String()
}

// UDPAddr returns the UDP address for discovery.
//
// Returns nil if the node has no IP address.
func (e *Enode) UDPAddr() *net.UDPAddr {
	if e.IP == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   e.IP,
		Port: int(e.UDP),
	}
}

// TCPAddr returns the TCP address for RLPx connections.
//
// Returns nil if the node has no IP address.
func (e *Enode) TCPAddr() *net.TCPAddr {
	if e.IP == nil {
		return nil
	}
	return &net.TCPAddr{
		IP:   e.IP,
		Port: int(e.TCP),
	}
}

// IsComplete returns true if the enode has IP and port information.
func (e *Enode) IsComplete() bool {
	return e.IP != nil || e.Hostname != ""
}

// IsIncomplete returns true if the enode only has a public key.
func (e *Enode) IsIncomplete() bool {
	return !e.IsComplete()
}
