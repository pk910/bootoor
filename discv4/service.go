// Package discv4 implements the Ethereum Discovery v4 protocol.
//
// Discovery v4 is a UDP-based protocol for finding peers in the Ethereum network.
// It uses a Kademlia-style DHT for distributed node discovery with a bond mechanism
// to prevent amplification attacks.
//
// Key features:
//   - PING/PONG for liveness and endpoint verification
//   - FINDNODE/NEIGHBORS for peer discovery
//   - ENRREQUEST/ENRRESPONSE for ENR record exchange (EIP-868)
//   - Bond mechanism (PING/PONG required before FINDNODE)
//   - No encryption (packets are signed but not encrypted)
package discv4

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net"
	"sync"

	"github.com/ethpandaops/bootnodoor/discv4/node"
	"github.com/ethpandaops/bootnodoor/discv4/protocol"
	"github.com/ethpandaops/bootnodoor/enr"
	"github.com/ethpandaops/bootnodoor/enode"
	"github.com/ethpandaops/bootnodoor/transport"
	"github.com/sirupsen/logrus"
)

// transportAdapter adapts the transport.UDPTransport to the protocol.Transport interface.
type transportAdapter struct {
	sendFunc func(data []byte, to *net.UDPAddr) error
}

func (t *transportAdapter) SendTo(data []byte, to *net.UDPAddr) error {
	return t.sendFunc(data, to)
}

// Service represents a discv4 service instance.
//
// The service manages:
//   - UDP transport layer
//   - Protocol handler
//   - Node database
//   - Request routing
type Service struct {
	// Configuration
	config *Config

	// Private key
	privateKey *ecdsa.PrivateKey

	// Local ENR (optional)
	localENR *enr.Record

	// Transport layer
	transport *transport.UDPTransport

	// Protocol handler
	handler *protocol.Handler

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// Running state
	mu      sync.Mutex
	running bool
}

// New creates a new discv4 service.
func New(config *Config) (*Service, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	config.ApplyDefaults()

	ctx, cancel := context.WithCancel(context.Background())

	s := &Service{
		config:     config,
		privateKey: config.PrivateKey,
		localENR:   config.LocalENR,
		ctx:        ctx,
		cancel:     cancel,
	}

	return s, nil
}

// Start starts the discv4 service.
func (s *Service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("service already running")
	}

	logrus.WithFields(logrus.Fields{
		"listen_addr": s.config.ListenAddr,
	}).Info("Starting discv4 service")

	// Create protocol handler first (needed for transport handler)
	handlerConfig := protocol.HandlerConfig{
		PrivateKey:       s.privateKey,
		LocalENR:         s.localENR,
		LocalAddr:        s.config.ListenAddr,
		BondExpiration:   s.config.BondExpiration,
		RequestTimeout:   s.config.RequestTimeout,
		ExpirationWindow: s.config.ExpirationWindow,
		OnPing:           s.config.OnPing,
		OnFindnode:       s.config.OnFindnode,
		OnENRRequest:     s.config.OnENRRequest,
		OnNodeSeen:       s.config.OnNodeSeen,
	}

	// Dummy transport for handler creation (will be replaced)
	dummyTransport := &transportAdapter{sendFunc: func(data []byte, to *net.UDPAddr) error {
		return fmt.Errorf("transport not initialized")
	}}

	s.handler = protocol.NewHandler(s.ctx, handlerConfig, dummyTransport)

	// Create transport with handler
	// Wrap the handler to match the transport.PacketHandler signature
	packetHandler := func(data []byte, from *net.UDPAddr) {
		if err := s.handler.HandlePacket(data, from); err != nil {
			logrus.WithError(err).Debug("Error handling packet")
		}
	}

	transportConfig := &transport.Config{
		ListenAddr:     s.config.ListenAddr.String(),
		Handler:        packetHandler,
		RateLimitPerIP: int(s.config.RateLimitPerIP),
		ReadBuffer:     s.config.ReadBufferSize,
		WriteBuffer:    s.config.WriteBufferSize,
	}

	t, err := transport.NewUDPTransport(transportConfig)
	if err != nil {
		return fmt.Errorf("failed to create transport: %w", err)
	}

	s.transport = t

	// Update handler with real transport
	s.handler = protocol.NewHandler(s.ctx, handlerConfig, &transportAdapter{
		sendFunc: s.transport.SendTo,
	})

	s.running = true

	logrus.Info("discv4 service started successfully")

	return nil
}

// Stop stops the discv4 service.
func (s *Service) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	logrus.Info("Stopping discv4 service")

	// Cancel context
	s.cancel()

	// Stop transport
	if s.transport != nil {
		if err := s.transport.Close(); err != nil {
			logrus.WithError(err).Error("Error stopping transport")
		}
	}

	s.running = false

	logrus.Info("discv4 service stopped")

	return nil
}

// IsRunning returns whether the service is currently running.
func (s *Service) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Public API Methods

// Ping sends a PING request to a node.
//
// This establishes a bond with the node and verifies liveness.
// Returns the PONG response or an error.
func (s *Service) Ping(n *node.Node) (*protocol.Pong, error) {
	if !s.running {
		return nil, fmt.Errorf("service not running")
	}
	return s.handler.Ping(n)
}

// PingAddr sends a PING to a node identified by address.
//
// This is a convenience method that creates a temporary node from an enode URL.
func (s *Service) PingAddr(enodeURL string) (*protocol.Pong, error) {
	n, err := node.ParseEnode(enodeURL)
	if err != nil {
		return nil, fmt.Errorf("invalid enode URL: %w", err)
	}
	return s.Ping(n)
}

// Findnode sends a FINDNODE request to discover nodes near a target.
//
// The node must have an active bond (will automatically PING if needed).
// Returns a list of discovered nodes.
func (s *Service) Findnode(n *node.Node, target []byte) ([]*node.Node, error) {
	if !s.running {
		return nil, fmt.Errorf("service not running")
	}
	return s.handler.Findnode(n, target)
}

// RequestENR requests a node's ENR record.
//
// Returns the ENR record or an error.
func (s *Service) RequestENR(n *node.Node) (*enr.Record, error) {
	if !s.running {
		return nil, fmt.Errorf("service not running")
	}
	return s.handler.RequestENR(n)
}

// LookupRandom performs a random node lookup.
//
// This is useful for populating the routing table with random nodes.
func (s *Service) LookupRandom() ([]*node.Node, error) {
	// Use our own node ID as target for random lookup
	// (this will return nodes from all distance ranges)
	localID := node.PubkeyToID(&s.privateKey.PublicKey)

	allNodes := s.handler.AllNodes()
	if len(allNodes) == 0 {
		return nil, fmt.Errorf("no bootstrap nodes")
	}

	// Query a random bonded node
	for _, n := range allNodes {
		if n.IsBonded() {
			return s.handler.Findnode(n, localID[:])
		}
	}

	return nil, fmt.Errorf("no bonded nodes available")
}

// Node Management

// AddNode adds a node to the known nodes list.
//
// This is useful for adding bootstrap nodes.
func (s *Service) AddNode(n *node.Node) {
	// The handler will automatically track this node when we communicate with it
	// For now, we can just ping it to add it to the handler's node map
	go func() {
		if _, err := s.Ping(n); err != nil {
			logrus.WithError(err).WithField("node", n.String()).Debug("Failed to ping node")
		}
	}()
}

// AddBootstrapNode adds a bootstrap node from an enode URL.
func (s *Service) AddBootstrapNode(enodeURL string) error {
	n, err := node.ParseEnode(enodeURL)
	if err != nil {
		return fmt.Errorf("invalid enode URL: %w", err)
	}
	s.AddNode(n)
	return nil
}

// GetNode returns a known node by ID.
func (s *Service) GetNode(id node.ID) *node.Node {
	return s.handler.GetNode(id)
}

// AllNodes returns all known nodes.
func (s *Service) AllNodes() []*node.Node {
	return s.handler.AllNodes()
}

// BondedNodes returns all bonded nodes.
func (s *Service) BondedNodes() []*node.Node {
	all := s.handler.AllNodes()
	bonded := make([]*node.Node, 0)
	for _, n := range all {
		if n.IsBonded() {
			bonded = append(bonded, n)
		}
	}
	return bonded
}

// LocalNode Information

// LocalAddr returns the local listening address.
func (s *Service) LocalAddr() *net.UDPAddr {
	return s.config.ListenAddr
}

// LocalNodeID returns the local node ID.
func (s *Service) LocalNodeID() node.ID {
	return node.PubkeyToID(&s.privateKey.PublicKey)
}

// LocalENR returns the local ENR record (if configured).
func (s *Service) LocalENR() *enr.Record {
	return s.localENR
}

// SetLocalENR updates the local ENR record.
//
// This should be called when the ENR is updated (e.g., IP change).
func (s *Service) SetLocalENR(record *enr.Record) {
	s.mu.Lock()
	s.localENR = record
	if s.handler != nil && s.transport != nil {
		// Update handler config
		s.handler = protocol.NewHandler(s.ctx, protocol.HandlerConfig{
			PrivateKey:       s.privateKey,
			LocalENR:         record,
			LocalAddr:        s.config.ListenAddr,
			BondExpiration:   s.config.BondExpiration,
			RequestTimeout:   s.config.RequestTimeout,
			ExpirationWindow: s.config.ExpirationWindow,
			OnPing:           s.config.OnPing,
			OnFindnode:       s.config.OnFindnode,
			OnENRRequest:     s.config.OnENRRequest,
			OnNodeSeen:       s.config.OnNodeSeen,
		}, &transportAdapter{
			sendFunc: s.transport.SendTo,
		})
	}
	s.mu.Unlock()
}

// LocalEnode returns the local enode:// URL.
func (s *Service) LocalEnode() string {
	en := &enode.Enode{
		PublicKey: &s.privateKey.PublicKey,
		IP:        s.config.ListenAddr.IP,
		UDP:       uint16(s.config.ListenAddr.Port),
		TCP:       uint16(s.config.ListenAddr.Port),
	}
	return en.String()
}

// Statistics

// Stats returns service statistics.
func (s *Service) Stats() map[string]interface{} {
	if s.handler == nil {
		return map[string]interface{}{}
	}

	stats := s.handler.Stats()

	// Add transport stats
	if s.transport != nil {
		stats["transport"] = s.transport.Metrics()
	}

	return stats
}

// Utility Methods

// ParseNodeFromEnode creates a node from an enode:// URL.
func ParseNodeFromEnode(enodeURL string) (*node.Node, error) {
	return node.ParseEnode(enodeURL)
}

// ParseNodeFromENR creates a node from an ENR record.
func ParseNodeFromENR(record *enr.Record, addr *net.UDPAddr) (*node.Node, error) {
	return node.FromENR(record, addr)
}
