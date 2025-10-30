package discv5

import (
	"crypto/ecdsa"
	"net"
	"time"

	"github.com/pk910/bootoor/discv5/enr"
	"github.com/pk910/bootoor/discv5/node"
	"github.com/pk910/bootoor/discv5/nodedb"
	"github.com/pk910/bootoor/discv5/protocol"
	"github.com/sirupsen/logrus"
)

// Config contains configuration for the discv5 service.
type Config struct {
	// PrivateKey is the node's private key
	PrivateKey *ecdsa.PrivateKey

	// BindIP is the IP address to bind to
	BindIP net.IP

	// BindPort is the UDP port to bind to
	BindPort int

	// ENRIP is the IPv4 address to advertise in the ENR (optional, uses BindIP if nil)
	ENRIP net.IP

	// ENRIP6 is the IPv6 address to advertise in the ENR (optional)
	ENRIP6 net.IP

	// ENRPort is the UDP port to advertise in the ENR (0 = use BindPort)
	ENRPort int

	// ETH2Data is the eth2 field to include in the ENR (optional)
	// This should be the 16-byte encoded eth2 field containing fork digest and next fork info
	ETH2Data []byte

	// BootNodes are the initial nodes to connect to
	BootNodes []*node.Node

	// NodeDB is the database for storing discovered nodes
	// If nil, an in-memory database is used
	NodeDB nodedb.DB

	// AdmissionFilter is applied before adding nodes to the routing table (Stage 1)
	AdmissionFilter enr.ENRFilter

	// ResponseFilter is applied when serving FINDNODE responses (Stage 2)
	ResponseFilter protocol.ResponseFilter

	// MaxNodesPerIP is the maximum nodes allowed per IP address (default 10)
	MaxNodesPerIP int

	// EnableLANFiltering enables LAN/WAN awareness for response filtering (default true)
	EnableLANFiltering bool

	// SessionLifetime is how long sessions remain valid (default 12 hours)
	SessionLifetime time.Duration

	// MaxSessions is the maximum number of cached sessions (default 1000)
	MaxSessions int

	// PingInterval is how often to ping nodes (default 30 seconds)
	PingInterval time.Duration

	// MaxNodeAge is the maximum time since last seen (default 24 hours)
	MaxNodeAge time.Duration

	// MaxFailures is the maximum consecutive failures (default 3)
	MaxFailures int

	// Logger for debug messages
	Logger logrus.FieldLogger
}

// DefaultConfig returns a default configuration.
func DefaultConfig() *Config {
	return &Config{
		BindIP:             net.IPv4zero,
		BindPort:           9000,
		MaxNodesPerIP:      10,
		EnableLANFiltering: true,
		SessionLifetime:    12 * time.Hour,
		MaxSessions:        1000,
		PingInterval:       30 * time.Second,
		MaxNodeAge:         24 * time.Hour,
		MaxFailures:        3,
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.PrivateKey == nil {
		return ErrMissingPrivateKey
	}

	if c.BindPort <= 0 || c.BindPort > 65535 {
		return ErrInvalidPort
	}

	return nil
}
