// Package discv5 implements the Ethereum Discovery v5 protocol.
//
// The service ties together all components:
//   - UDP transport for network communication
//   - Routing table with IP limits and aliveness monitoring
//   - Session management for encrypted communication
//   - Protocol handler for message processing
//   - Discovery operations for node lookup
//   - Node database for persistent storage
package discv5

import (
	"fmt"
	"net"
	"sync"
	"time"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pk910/bootoor/discv5/discover"
	"github.com/pk910/bootoor/discv5/enr"
	"github.com/pk910/bootoor/discv5/node"
	"github.com/pk910/bootoor/discv5/nodedb"
	"github.com/pk910/bootoor/discv5/protocol"
	"github.com/pk910/bootoor/discv5/session"
	"github.com/pk910/bootoor/discv5/table"
	"github.com/pk910/bootoor/discv5/transport"
	"github.com/sirupsen/logrus"
)

// Service is the main discv5 service.
//
// It orchestrates all components and provides a high-level API
// for node discovery and network operations.
type Service struct {
	// config is the service configuration
	config *Config

	// localNode is our node information
	localNode *node.Node

	// transport is the UDP transport layer
	transport *transport.UDPTransport

	// table is the routing table
	table *table.Table

	// sessions manages encrypted sessions
	sessions *session.Cache

	// handler processes protocol messages
	handler *protocol.Handler

	// lookup performs node discovery
	lookup *discover.LookupService

	// ping handles liveness checks
	ping *discover.PingService

	// nodeDB stores discovered nodes
	nodeDB nodedb.DB

	// logger for debug messages
	logger logrus.FieldLogger

	// forkFilterStats stores fork filter statistics provider
	forkFilterStats ForkFilterStatsProvider

	// startTime records when the service started
	startTime time.Time

	// Lifecycle management
	running bool
	mu      sync.RWMutex
	wg      sync.WaitGroup
	stopCh  chan struct{}
}

// New creates a new discv5 service.
//
// Example:
//
//	privKey, _ := crypto.GenerateKey()
//	config := DefaultConfig()
//	config.PrivateKey = privKey
//
//	service, err := New(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer service.Close()
func New(cfg *Config) (*Service, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Set defaults
	if cfg.Logger == nil {
		cfg.Logger = logrus.New()
	}

	if cfg.NodeDB == nil {
		cfg.NodeDB = nodedb.NewMemoryDB(cfg.Logger)
	}

	// Create local ENR
	localENR, err := createLocalENR(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create local ENR: %w", err)
	}

	// Create local node
	localNode, err := node.New(localENR)
	if err != nil {
		return nil, fmt.Errorf("failed to create local node: %w", err)
	}

	cfg.Logger.WithField("peerID", localNode.PeerID()).WithField("ip", cfg.BindIP).WithField("port", cfg.BindPort).Info("created local node")

	// Create routing table with persistence callback
	tableConfig := table.Config{
		LocalID:         localNode.ID(),
		MaxNodesPerIP:   cfg.MaxNodesPerIP,
		AdmissionFilter: cfg.AdmissionFilter,
		PingInterval:    cfg.PingInterval,
		MaxNodeAge:      cfg.MaxNodeAge,
		MaxFailures:     cfg.MaxFailures,
		DB:              cfg.NodeDB, // Use NodeDB for rejection tracking
		Logger:          cfg.Logger,
		NodeChangedCallback: func(n *node.Node) {
			// Persist node to database in background to avoid blocking
			go func() {
				if err := cfg.NodeDB.Store(n); err != nil {
					cfg.Logger.WithError(err).WithField("peerID", n.PeerID()).Warn("failed to persist node to database")
				}
			}()
		},
	}
	routingTable := table.NewTable(tableConfig)

	// Create session cache
	sessionCache := session.NewCache(cfg.MaxSessions, cfg.SessionLifetime, cfg.Logger)

	// Create protocol handler (transport will be set later)
	responseFilter := cfg.ResponseFilter
	if responseFilter == nil && cfg.EnableLANFiltering {
		responseFilter = protocol.LANAwareResponseFilter()
	}

	handlerConfig := protocol.HandlerConfig{
		LocalNode:      localNode,
		Table:          routingTable,
		Sessions:       sessionCache,
		PrivateKey:     cfg.PrivateKey,
		ResponseFilter: responseFilter,
		Logger:         cfg.Logger,
	}
	protocolHandler := protocol.NewHandler(handlerConfig)

	// Create UDP transport
	listenAddr := fmt.Sprintf("%s:%d", cfg.BindIP.String(), cfg.BindPort)
	transportConfig := &transport.Config{
		ListenAddr: listenAddr,
		Handler: func(data []byte, from *net.UDPAddr) {
			protocolHandler.HandleIncomingPacket(data, from)
		},
		Logger:         cfg.Logger,
		RateLimitPerIP: 100, // 100 packets/sec per IP
	}

	udpTransport, err := transport.NewUDPTransport(transportConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP transport: %w", err)
	}

	// Connect transport to handler
	protocolHandler.SetTransport(udpTransport)

	s := &Service{
		config:    cfg,
		localNode: localNode,
		transport: udpTransport,
		table:     routingTable,
		sessions:  sessionCache,
		handler:   protocolHandler,
		nodeDB:    cfg.NodeDB,
		logger:    cfg.Logger,
		stopCh:    make(chan struct{}),
	}

	// Create lookup service with stopCh for graceful shutdown
	lookupConfig := discover.Config{
		LocalNode: localNode,
		Table:     routingTable,
		Handler:   protocolHandler,
		StopCh:    s.stopCh,
		Logger:    cfg.Logger,
	}
	lookupService := discover.NewLookupService(lookupConfig)

	// Create ping service
	pingService := discover.NewPingService(protocolHandler, cfg.Logger)

	// Set lookup and ping services
	s.lookup = lookupService
	s.ping = pingService

	return s, nil
}

// Start starts the discv5 service.
//
// This starts all background tasks:
//   - UDP packet receiver
//   - Periodic table maintenance
//   - Session cleanup
//   - Aliveness monitoring
func (s *Service) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return ErrAlreadyRunning
	}

	// Record start time
	s.startTime = time.Now()

	// Restore nodes from database
	s.restoreNodesFromDB()

	// Start background tasks
	s.wg.Add(1)
	go s.maintenanceLoop()

	// Connect to boot nodes
	if len(s.config.BootNodes) > 0 {
		s.wg.Add(1)
		go s.connectBootNodes()
	}

	s.running = true

	return nil
}

// Stop stops the discv5 service.
//
// This gracefully shuts down all components and waits for
// background tasks to complete.
func (s *Service) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return ErrNotRunning
	}
	s.running = false
	s.mu.Unlock()

	// Signal stop to background tasks
	close(s.stopCh)

	// Wait for background tasks
	s.wg.Wait()

	// Close UDP transport
	if s.transport != nil {
		if err := s.transport.Close(); err != nil {
			s.logger.WithError(err).Error("failed to close UDP transport")
		}
	}

	// Close session cache
	if err := s.sessions.Close(); err != nil {
		s.logger.WithError(err).Error("failed to close session cache")
	}

	// Close node database
	if err := s.nodeDB.Close(); err != nil {
		s.logger.WithError(err).Error("failed to close node database")
	}

	return nil
}

// maintenanceLoop runs periodic maintenance tasks.
func (s *Service) maintenanceLoop() {
	defer s.wg.Done()

	// Tickers for periodic tasks
	tableMaintenance := time.NewTicker(5 * time.Minute)
	sessionCleanup := time.NewTicker(10 * time.Minute)
	alivenessCheck := time.NewTicker(s.config.PingInterval)
	randomWalk := time.NewTicker(30 * time.Second)

	defer tableMaintenance.Stop()
	defer sessionCleanup.Stop()
	defer alivenessCheck.Stop()
	defer randomWalk.Stop()

	for {
		select {
		case <-s.stopCh:
			return

		case <-tableMaintenance.C:
			s.performTableMaintenance()

		case <-sessionCleanup.C:
			s.performSessionCleanup()

		case <-alivenessCheck.C:
			s.performAlivenessCheck()

		case <-randomWalk.C:
			s.performRandomWalk()
		}
	}
}

// performTableMaintenance performs routing table maintenance.
func (s *Service) performTableMaintenance() {
	// Remove stale nodes
	removed := s.table.RemoveStaleNodes()
	if removed > 0 {
		s.logger.WithField("count", removed).Info("removed stale nodes")
	}

	// Cleanup expired rejection log entries
	rejectionCleaned := s.table.CleanupRejectionLog()
	if rejectionCleaned > 0 {
		s.logger.WithField("count", rejectionCleaned).Debug("cleaned up rejection log entries")
	}
}

// performSessionCleanup cleans up expired sessions.
func (s *Service) performSessionCleanup() {
	removed := s.sessions.CleanupExpired()
	if removed > 0 {
		s.logger.WithField("count", removed).Debug("cleaned up expired sessions")
	}
}

// performAlivenessCheck checks node aliveness with PINGs.
func (s *Service) performAlivenessCheck() {
	nodes := s.table.GetNodesNeedingPing()
	if len(nodes) == 0 {
		return
	}

	s.logger.WithField("count", len(nodes)).Debug("performing aliveness check")

	// Ping nodes in parallel
	results := s.ping.PingMultiple(nodes)

	// Update node statistics
	for nodeID, success := range results {
		n := s.table.Get(nodeID)
		if n == nil {
			continue
		}

		if success {
			n.SetLastSeen(time.Now())
			n.ResetFailureCount()
		} else {
			n.IncrementFailureCount()
		}
	}
}

// performRandomWalk performs a random walk for network exploration.
func (s *Service) performRandomWalk() {
	// Check if we're shutting down
	select {
	case <-s.stopCh:
		s.logger.Debug("skipping random walk due to shutdown")
		return
	default:
	}

	// Only perform random walk if table is not full enough
	if s.table.NumBucketsFilled() >= 100 {
		return
	}

	s.logger.Debug("discv5: performing random walk")

	_, err := s.lookup.RandomWalk()
	if err != nil {
		s.logger.WithError(err).Debug("random walk failed")
	}
}

// restoreNodesFromDB restores nodes from the database to the routing table.
func (s *Service) restoreNodesFromDB() {
	nodes := s.nodeDB.List()
	if len(nodes) == 0 {
		s.logger.Info("no nodes to restore from database")
		return
	}

	s.logger.WithField("count", len(nodes)).Info("restoring nodes from database")

	restored := 0
	for _, n := range nodes {
		// Add to routing table (will trigger admission filter and IP limits)
		if s.table.Add(n) {
			restored++
		}
	}

	s.logger.WithFields(logrus.Fields{
		"total":    len(nodes),
		"restored": restored,
	}).Info("finished restoring nodes from database")
}

// connectBootNodes connects to boot nodes on startup.
func (s *Service) connectBootNodes() {
	defer s.wg.Done()

	s.logger.WithField("count", len(s.config.BootNodes)).Info("connecting to boot nodes")

	for _, bootNode := range s.config.BootNodes {
		s.logger.WithFields(logrus.Fields{
			"peerID": bootNode.PeerID(),
			"addr":   bootNode.Addr(),
		}).Info("discv5: attempting to connect to boot node")

		// Add to routing table
		added := s.table.Add(bootNode)
		s.logger.WithFields(logrus.Fields{
			"peerID": bootNode.PeerID(),
			"added":  added,
		}).Debug("discv5: boot node add to table result")

		// First ping the boot node to establish connectivity
		s.logger.WithField("peerID", bootNode.PeerID()).Debug("discv5: pinging boot node")
		success, rtt, err := s.ping.Ping(bootNode)
		if err != nil {
			s.logger.WithFields(logrus.Fields{
				"peerID": bootNode.PeerID(),
				"error":  err,
			}).Warn("discv5: failed to ping boot node")
			continue
		}

		s.logger.WithFields(logrus.Fields{
			"peerID":  bootNode.PeerID(),
			"success": success,
			"rtt":     rtt,
		}).Info("discv5: boot node ping result")

		if !success {
			s.logger.WithField("peerID", bootNode.PeerID()).Warn("discv5: boot node ping unsuccessful")
			continue
		}

		// Perform lookup using boot node
		s.logger.WithField("peerID", bootNode.PeerID()).Debug("discv5: performing lookup via boot node")
		_, err = s.lookup.Lookup(bootNode.ID(), 16)
		if err != nil {
			s.logger.WithField("peerID", bootNode.PeerID()).WithError(err).Debug("boot node lookup failed")
		}
	}
}

// LocalNode returns our local node information.
func (s *Service) LocalNode() *node.Node {
	return s.localNode
}

// Table returns the routing table.
func (s *Service) Table() *table.Table {
	return s.table
}

// NodeDB returns the node database.
func (s *Service) NodeDB() nodedb.DB {
	return s.nodeDB
}

// Lookup performs a node lookup for the target ID.
func (s *Service) Lookup(target node.ID) ([]*node.Node, error) {
	return s.lookup.Lookup(target, 16)
}

// ForkFilterStatsProvider provides fork filter statistics.
type ForkFilterStatsProvider interface {
	GetCurrentFork() string
	GetCurrentDigest() string
	GetGracePeriod() string
	GetOldDigests() map[string]time.Duration
	GetAcceptedCurrent() int
	GetAcceptedOld() int
	GetRejectedInvalid() int
	GetRejectedExpired() int
	GetTotalChecks() int
	GetNetworkName() string
}

// SetForkFilterStats sets the fork filter stats provider.
func (s *Service) SetForkFilterStats(provider ForkFilterStatsProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forkFilterStats = provider
}

// ForkFilterStats contains fork filter statistics for the webui.
type ForkFilterStats struct {
	NetworkName     string
	CurrentFork     string
	CurrentDigest   string
	GracePeriod     string
	OldDigests      map[string]time.Duration
	AcceptedCurrent int
	AcceptedOld     int
	RejectedInvalid int
	RejectedExpired int
	TotalChecks     int
}

// ServiceStats contains statistics about the service.
type ServiceStats struct {
	PeerID          string
	BindAddress     string
	Uptime          time.Duration
	TableSize       int
	BucketsFilled   int
	TableStats      table.TableStats
	HandlerStats    protocol.HandlerStats
	SessionStats    session.Stats
	LookupStats     discover.LookupStats
	PingStats       discover.PingStats
	ForkFilterStats *ForkFilterStats
}

// GetStats returns service statistics.
func (s *Service) GetStats() ServiceStats {
	s.mu.RLock()
	uptime := time.Since(s.startTime)
	forkFilterProvider := s.forkFilterStats
	s.mu.RUnlock()

	stats := ServiceStats{
		PeerID:        s.localNode.PeerID(),
		BindAddress:   fmt.Sprintf("%s:%d", s.config.BindIP, s.config.BindPort),
		Uptime:        uptime,
		TableSize:     s.table.Size(),
		BucketsFilled: s.table.NumBucketsFilled(),
		TableStats:    s.table.GetStats(),
		HandlerStats:  s.handler.GetStats(),
		SessionStats:  s.sessions.GetStats(),
		LookupStats:   s.lookup.GetStats(),
		PingStats:     s.ping.GetStats(),
	}

	// Add fork filter stats if available
	if forkFilterProvider != nil {
		stats.ForkFilterStats = &ForkFilterStats{
			NetworkName:     forkFilterProvider.GetNetworkName(),
			CurrentFork:     forkFilterProvider.GetCurrentFork(),
			CurrentDigest:   forkFilterProvider.GetCurrentDigest(),
			GracePeriod:     forkFilterProvider.GetGracePeriod(),
			OldDigests:      forkFilterProvider.GetOldDigests(),
			AcceptedCurrent: forkFilterProvider.GetAcceptedCurrent(),
			AcceptedOld:     forkFilterProvider.GetAcceptedOld(),
			RejectedInvalid: forkFilterProvider.GetRejectedInvalid(),
			RejectedExpired: forkFilterProvider.GetRejectedExpired(),
			TotalChecks:     forkFilterProvider.GetTotalChecks(),
		}
	}

	return stats
}

// BucketInfo contains information about a routing table bucket.
type BucketInfo struct {
	Index    int
	Distance string
	Nodes    []BucketNodeInfo
}

// BucketNodeInfo contains node information for display.
type BucketNodeInfo struct {
	PeerID       string
	IP           string
	Port         int
	FirstSeen    time.Time
	LastSeen     time.Time
	SuccessCount int
	FailureCount int
	IsAlive      bool
	Score        int
	ForkDigest   string
	HasForkData  bool
	ENRSeq       uint64
	ENR          string
}

// GetBuckets returns information about all routing table buckets.
func (s *Service) GetBuckets() []BucketInfo {
	buckets := make([]BucketInfo, 0, 256)

	for i := 0; i < 256; i++ {
		nodes := s.table.GetBucketNodes(i)
		if len(nodes) == 0 {
			continue
		}

		bucketInfo := BucketInfo{
			Index:    i,
			Distance: fmt.Sprintf("2^%d", i),
			Nodes:    make([]BucketNodeInfo, 0, len(nodes)),
		}

		for _, n := range nodes {
			nodeInfo := BucketNodeInfo{
				PeerID:       n.PeerID(),
				IP:           n.IP().String(),
				Port:         int(n.UDPPort()),
				FirstSeen:    n.FirstSeen(),
				LastSeen:     n.LastSeen(),
				SuccessCount: n.SuccessCount(),
				FailureCount: n.FailureCount(),
				IsAlive:      n.FailureCount() < 3, // Simple heuristic
				Score:        n.SuccessCount() - n.FailureCount(),
				ENRSeq:       n.Record().Seq(),
			}

			// Extract eth2 fork digest if available
			if eth2Data, ok := n.Record().Eth2(); ok {
				nodeInfo.ForkDigest = fmt.Sprintf("%x", eth2Data.ForkDigest)
				nodeInfo.HasForkData = true
			}

			// Get ENR string
			if enrStr, err := n.Record().EncodeBase64(); err == nil {
				nodeInfo.ENR = enrStr
			}

			bucketInfo.Nodes = append(bucketInfo.Nodes, nodeInfo)
		}

		buckets = append(buckets, bucketInfo)
	}

	return buckets
}

// createLocalENR creates the local node's ENR record.
func createLocalENR(cfg *Config) (*enr.Record, error) {
	// Try to load existing ENR from database to maintain sequence number
	var currentSeq uint64 = 0
	if cfg.NodeDB != nil {
		existingENRBytes, err := cfg.NodeDB.LoadLocalENR()
		if err != nil {
			cfg.Logger.WithError(err).Warn("failed to load existing local ENR from database")
		} else if existingENRBytes != nil {
			existingENR := &enr.Record{}
			if err := existingENR.DecodeRLPBytes(existingENRBytes); err == nil {
				currentSeq = existingENR.Seq()
				cfg.Logger.WithField("seq", currentSeq).Info("loaded existing ENR sequence number")
			}
		}
	}

	// Create ENR with IP and port
	record := enr.New()

	// Set sequence number (start at 1 if new, increment if existing)
	if currentSeq == 0 {
		record.SetSeq(1)
	} else {
		record.SetSeq(currentSeq + 1)
	}

	// Determine which IP to use for ENR
	enrIPv4 := cfg.ENRIP
	if enrIPv4 == nil {
		enrIPv4 = cfg.BindIP
	}

	enrIPv6 := cfg.ENRIP6

	// Determine which port to use for ENR
	enrPort := cfg.ENRPort
	if enrPort == 0 {
		enrPort = cfg.BindPort
	}

	// Add IPv4 address
	if enrIPv4 != nil && !enrIPv4.IsUnspecified() && enrIPv4.To4() != nil {
		record.Set("ip", enrIPv4.To4())
	}

	// Add IPv6 address
	if enrIPv6 != nil && !enrIPv6.IsUnspecified() && enrIPv6.To4() == nil {
		record.Set("ip6", enrIPv6)
	}

	// Add UDP port
	record.Set("udp", uint16(enrPort))

	// Add secp256k1 public key
	pubKey := cfg.PrivateKey.PublicKey
	pubKeyBytes := ethcrypto.CompressPubkey(&pubKey)
	record.Set("secp256k1", pubKeyBytes)

	// Add eth2 field if provided
	if len(cfg.ETH2Data) >= 4 {
		record.Set("eth2", cfg.ETH2Data)
		cfg.Logger.WithField("forkDigest", fmt.Sprintf("%x", cfg.ETH2Data[:4])).Info("added eth2 field to ENR")
	}

	// Sign the record with private key
	if err := record.Sign(cfg.PrivateKey); err != nil {
		return nil, fmt.Errorf("failed to sign ENR: %w", err)
	}

	// Save the ENR to database for future use
	if cfg.NodeDB != nil {
		enrBytes, err := record.EncodeRLP()
		if err != nil {
			cfg.Logger.WithError(err).Warn("failed to encode ENR for storage")
		} else {
			if err := cfg.NodeDB.StoreLocalENR(enrBytes); err != nil {
				cfg.Logger.WithError(err).Warn("failed to store local ENR to database")
			} else {
				cfg.Logger.WithField("seq", record.Seq()).Info("stored local ENR to database")
			}
		}
	}

	return record, nil
}

// Common errors
var (
	ErrMissingPrivateKey = fmt.Errorf("private key is required")
	ErrInvalidPort       = fmt.Errorf("invalid port number")
	ErrAlreadyRunning    = fmt.Errorf("service is already running")
	ErrNotRunning        = fmt.Errorf("service is not running")
)
