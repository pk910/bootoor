package discv4

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"time"

	"github.com/ethpandaops/bootnodoor/discv4/protocol"
	"github.com/ethpandaops/bootnodoor/enr"
)

// Config contains configuration for the discv4 service.
type Config struct {
	// PrivateKey is the node's private key (required)
	PrivateKey *ecdsa.PrivateKey

	// ListenAddr is the UDP address to listen on (required)
	ListenAddr *net.UDPAddr

	// LocalENR is the node's ENR record (optional)
	// If provided, it will be shared via ENRRESPONSE
	LocalENR *enr.Record

	// BondExpiration is how long bonds last (default: 24 hours)
	// Bonds must be refreshed via PING/PONG before expiration
	BondExpiration time.Duration

	// RequestTimeout is how long to wait for request responses (default: 500ms)
	RequestTimeout time.Duration

	// ExpirationWindow is the acceptable time range for packet expiration (default: 20s)
	// Packets with expiration outside this window are rejected
	ExpirationWindow time.Duration

	// Transport Configuration

	// RateLimitPerIP is the maximum packets per second per IP address (default: 25)
	RateLimitPerIP float64

	// ReadBufferSize is the UDP read buffer size in bytes (default: 2MB)
	ReadBufferSize int

	// WriteBufferSize is the UDP write buffer size in bytes (default: 2MB)
	WriteBufferSize int

	// ReceiveWorkers is the number of concurrent receive workers (default: 4)
	ReceiveWorkers int

	// Callbacks

	// OnPing is called when a PING request is received
	OnPing protocol.OnPingCallback

	// OnFindnode is called when a FINDNODE request is received
	// Should return the list of nodes to include in the NEIGHBORS response
	OnFindnode protocol.OnFindnodeCallback

	// OnENRRequest is called when an ENRREQUEST is received
	OnENRRequest protocol.OnENRRequestCallback

	// OnNodeSeen is called when we receive any valid packet from a node
	// Useful for tracking last_seen timestamps in a database
	OnNodeSeen protocol.OnNodeSeenCallback
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.PrivateKey == nil {
		return fmt.Errorf("private key is required")
	}

	if c.ListenAddr == nil {
		return fmt.Errorf("listen address is required")
	}

	if c.BondExpiration < 0 {
		return fmt.Errorf("bond expiration must be positive")
	}

	if c.RequestTimeout < 0 {
		return fmt.Errorf("request timeout must be positive")
	}

	if c.ExpirationWindow < 0 {
		return fmt.Errorf("expiration window must be positive")
	}

	return nil
}

// ApplyDefaults applies default values to unset configuration fields.
func (c *Config) ApplyDefaults() {
	if c.BondExpiration == 0 {
		c.BondExpiration = 24 * time.Hour
	}

	if c.RequestTimeout == 0 {
		c.RequestTimeout = 500 * time.Millisecond
	}

	if c.ExpirationWindow == 0 {
		c.ExpirationWindow = 20 * time.Second
	}

	if c.RateLimitPerIP == 0 {
		c.RateLimitPerIP = 25.0
	}

	if c.ReadBufferSize == 0 {
		c.ReadBufferSize = 2 * 1024 * 1024 // 2MB
	}

	if c.WriteBufferSize == 0 {
		c.WriteBufferSize = 2 * 1024 * 1024 // 2MB
	}

	if c.ReceiveWorkers == 0 {
		c.ReceiveWorkers = 4
	}
}

// DefaultConfig returns a configuration with sensible defaults.
//
// You must set PrivateKey and ListenAddr before using.
func DefaultConfig() *Config {
	config := &Config{}
	config.ApplyDefaults()
	return config
}

// ConfigBuilder provides a fluent interface for building configurations.
type ConfigBuilder struct {
	config *Config
}

// NewConfigBuilder creates a new configuration builder.
func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{
		config: DefaultConfig(),
	}
}

// WithPrivateKey sets the private key.
func (b *ConfigBuilder) WithPrivateKey(key *ecdsa.PrivateKey) *ConfigBuilder {
	b.config.PrivateKey = key
	return b
}

// WithListenAddr sets the listen address.
func (b *ConfigBuilder) WithListenAddr(addr *net.UDPAddr) *ConfigBuilder {
	b.config.ListenAddr = addr
	return b
}

// WithLocalENR sets the local ENR record.
func (b *ConfigBuilder) WithLocalENR(record *enr.Record) *ConfigBuilder {
	b.config.LocalENR = record
	return b
}

// WithBondExpiration sets the bond expiration duration.
func (b *ConfigBuilder) WithBondExpiration(d time.Duration) *ConfigBuilder {
	b.config.BondExpiration = d
	return b
}

// WithRequestTimeout sets the request timeout.
func (b *ConfigBuilder) WithRequestTimeout(d time.Duration) *ConfigBuilder {
	b.config.RequestTimeout = d
	return b
}

// WithExpirationWindow sets the expiration window.
func (b *ConfigBuilder) WithExpirationWindow(d time.Duration) *ConfigBuilder {
	b.config.ExpirationWindow = d
	return b
}

// WithRateLimitPerIP sets the rate limit per IP.
func (b *ConfigBuilder) WithRateLimitPerIP(limit float64) *ConfigBuilder {
	b.config.RateLimitPerIP = limit
	return b
}

// WithOnPing sets the PING callback.
func (b *ConfigBuilder) WithOnPing(cb protocol.OnPingCallback) *ConfigBuilder {
	b.config.OnPing = cb
	return b
}

// WithOnFindnode sets the FINDNODE callback.
func (b *ConfigBuilder) WithOnFindnode(cb protocol.OnFindnodeCallback) *ConfigBuilder {
	b.config.OnFindnode = cb
	return b
}

// WithOnENRRequest sets the ENRREQUEST callback.
func (b *ConfigBuilder) WithOnENRRequest(cb protocol.OnENRRequestCallback) *ConfigBuilder {
	b.config.OnENRRequest = cb
	return b
}

// WithOnNodeSeen sets the OnNodeSeen callback.
func (b *ConfigBuilder) WithOnNodeSeen(cb protocol.OnNodeSeenCallback) *ConfigBuilder {
	b.config.OnNodeSeen = cb
	return b
}

// Build returns the built configuration.
func (b *ConfigBuilder) Build() (*Config, error) {
	if err := b.config.Validate(); err != nil {
		return nil, err
	}
	return b.config, nil
}

// MustBuild returns the built configuration or panics on error.
func (b *ConfigBuilder) MustBuild() *Config {
	config, err := b.Build()
	if err != nil {
		panic(fmt.Sprintf("config build failed: %v", err))
	}
	return config
}
