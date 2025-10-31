package protocol

import (
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/rlp"
	"github.com/pk910/bootoor/discv5/crypto"
	"github.com/pk910/bootoor/discv5/enr"
	"github.com/pk910/bootoor/discv5/node"
	"github.com/pk910/bootoor/discv5/session"
	"github.com/pk910/bootoor/discv5/table"
	"github.com/sirupsen/logrus"
)

// Transport interface for sending packets.
type Transport interface {
	SendTo(data []byte, to *net.UDPAddr) error
}

// PendingHandshake tracks a message waiting for handshake completion
type PendingHandshake struct {
	Message   Message
	ToAddr    *net.UDPAddr
	ToNodeID  node.ID
	Challenge *WHOAREYOUChallenge
	CreatedAt time.Time
}

// PendingChallenge tracks WHOAREYOU challenges we've sent.
type PendingChallenge struct {
	ToAddr        *net.UDPAddr
	ToNodeID      node.ID
	Challenge     *WHOAREYOUChallenge
	ChallengeData []byte // The raw WHOAREYOU packet bytes for signature verification
	CreatedAt     time.Time
}

// Handler handles incoming and outgoing protocol messages.
//
// The handler is responsible for:
//   - Processing incoming packets (PING, FINDNODE, TALKREQ)
//   - Sending responses with appropriate filtering
//   - Managing request/response matching
//   - Applying response filters (LAN/WAN awareness)
type Handler struct {
	// localNode is our node information
	localNode *node.Node

	// table is the routing table
	table *table.Table

	// sessions manages encrypted sessions with peers
	sessions *session.Cache

	// requests tracks pending requests
	requests *RequestTracker

	// pendingHandshakes tracks messages waiting for handshake completion (key: nodeID+addr)
	pendingHandshakes map[string]*PendingHandshake

	// pendingChallenges tracks WHOAREYOU challenges we've sent (key: nodeID+addr)
	pendingChallenges map[string]*PendingChallenge

	// responseFilter is applied when serving FINDNODE responses (Stage 2)
	responseFilter ResponseFilter

	// transport is used to send UDP packets
	transport Transport

	// logger for debug messages
	logger logrus.FieldLogger

	// privateKey is our node's private key (needed for handshake signatures)
	privateKey *ecdsa.PrivateKey

	// mu protects handler state
	mu sync.RWMutex

	// stopChan signals the cleanup routine to stop
	stopChan chan struct{}

	// Stats
	packetsReceived   int
	packetsSent       int
	invalidPackets    int
	filteredResponses int
	findNodeReceived  int
}

const (
	// pendingHandshakeTimeout is how long we keep pending handshakes before cleanup
	pendingHandshakeTimeout = 30 * time.Second

	// pendingChallengeTimeout is how long we keep pending challenges before cleanup
	pendingChallengeTimeout = 30 * time.Second

	// cleanupInterval is how often we run the cleanup routine
	cleanupInterval = 10 * time.Second
)

// HandlerConfig contains configuration for the protocol handler.
type HandlerConfig struct {
	// LocalNode is our node information
	LocalNode *node.Node

	// Table is the routing table
	Table *table.Table

	// Sessions is the session cache
	Sessions *session.Cache

	// PrivateKey is the node's private key (for handshake signatures)
	PrivateKey *ecdsa.PrivateKey

	// ResponseFilter is applied when serving FINDNODE responses (Stage 2)
	ResponseFilter ResponseFilter

	// RequestTimeout is the timeout for requests
	RequestTimeout time.Duration

	// Logger for debug messages
	Logger logrus.FieldLogger
}

// NewHandler creates a new protocol handler.
//
// Example:
//
//	handler := NewHandler(HandlerConfig{
//	    LocalNode: myNode,
//	    Table: routingTable,
//	    Sessions: sessionCache,
//	    ResponseFilter: LANAwareResponseFilter(),
//	})
func NewHandler(cfg HandlerConfig) *Handler {
	if cfg.ResponseFilter == nil {
		cfg.ResponseFilter = LANAwareResponseFilter()
	}

	h := &Handler{
		localNode:         cfg.LocalNode,
		table:             cfg.Table,
		sessions:          cfg.Sessions,
		requests:          NewRequestTracker(cfg.RequestTimeout),
		pendingHandshakes: make(map[string]*PendingHandshake),
		pendingChallenges: make(map[string]*PendingChallenge),
		responseFilter:    cfg.ResponseFilter,
		privateKey:        cfg.PrivateKey,
		logger:            cfg.Logger,
		stopChan:          make(chan struct{}),
	}

	// Start cleanup routine for expired pending entries
	go h.cleanupLoop()

	return h
}

// SetTransport sets the transport for sending packets.
func (h *Handler) SetTransport(transport Transport) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.transport = transport
}

// HandleIncomingPacket processes an incoming UDP packet.
//
// This is called by the UDP transport layer when a packet arrives.
func (h *Handler) HandleIncomingPacket(data []byte, from *net.UDPAddr) error {
	h.mu.Lock()
	h.packetsReceived++
	h.mu.Unlock()

	// Decode packet (unmask header and authdata using our local node ID)
	packet, err := DecodePacket(data, h.localNode.ID())
	if err != nil {
		h.mu.Lock()
		h.invalidPackets++
		h.mu.Unlock()

		h.logger.WithFields(logrus.Fields{
			"from":  from,
			"error": err,
		}).Debug("handler: invalid packet")
		return fmt.Errorf("invalid packet: %w", err)
	}

	// Handle based on packet type
	switch packet.PacketType {
	case OrdinaryPacket:
		return h.handleOrdinaryPacket(packet, from)
	case WHOAREYOUPacket:
		return h.handleWHOAREYOUPacket(packet, from)
	case HandshakePacket:
		return h.handleHandshakePacket(packet, from)
	default:
		h.mu.Lock()
		h.invalidPackets++
		h.mu.Unlock()
		h.logger.WithFields(logrus.Fields{
			"from": from,
			"type": packet.PacketType,
		}).Warn("handler: unknown packet type")
		return fmt.Errorf("unknown packet type: %d", packet.PacketType)
	}
}

// handleOrdinaryPacket handles an ordinary encrypted packet.
func (h *Handler) handleOrdinaryPacket(packet *Packet, from *net.UDPAddr) error {
	// Look up session for this address
	sess := h.sessions.GetByAddr(from)
	if sess == nil {
		// No session exists, send WHOAREYOU challenge
		// Extract dest node ID from packet srcID (sender becomes receiver of WHOAREYOU)
		if len(packet.SrcID) != 32 {
			return fmt.Errorf("no source node ID in packet")
		}
		var destNodeID node.ID
		copy(destNodeID[:], packet.SrcID)
		return h.sendWHOAREYOU(from, destNodeID)
	}

	// Decrypt message using session key
	// HeaderData contains: IV + masked header + masked authdata (used as GCM additional data)
	plaintext, err := session.DecryptMessage(
		sess.DecryptionKey(),
		packet.Header.Nonce,
		packet.HeaderData,
		packet.Message,
	)
	if err != nil {
		// Session might be expired, send WHOAREYOU
		// Extract dest node ID from packet srcID
		if len(packet.SrcID) != 32 {
			return fmt.Errorf("no source node ID in packet")
		}
		var destNodeID node.ID
		copy(destNodeID[:], packet.SrcID)
		return h.sendWHOAREYOU(from, destNodeID)
	}

	// Decode message from plaintext
	// Plaintext format: message-type (1 byte) + RLP-encoded message
	if len(plaintext) < 1 {
		h.logger.WithField("from", from).Debug("handler: message too short")
		return fmt.Errorf("message too short")
	}

	msgType := plaintext[0]
	msgData := plaintext[1:]

	// Convert to Message interface and decode RLP data into it
	msg := h.createMessage(msgType)
	if msg == nil {
		h.logger.WithFields(logrus.Fields{
			"from":    from,
			"msgType": msgType,
		}).Warn("handler: unknown message type")
		return fmt.Errorf("unknown message type: %d", msgType)
	}

	// Decode RLP message data into the message struct
	// ENR records in NODES messages will be properly decoded via the rlp.Decoder interface
	if err := rlp.DecodeBytes(msgData, msg); err != nil {
		h.logger.WithFields(logrus.Fields{
			"from":  from,
			"error": err,
		}).Debug("handler: failed to decode message")
		return fmt.Errorf("failed to decode message: %w", err)
	}

	// Handle message based on type
	return h.handleMessage(msg, sess.RemoteID, from)
}

// handleWHOAREYOUPacket handles a WHOAREYOU challenge.
func (h *Handler) handleWHOAREYOUPacket(packet *Packet, from *net.UDPAddr) error {
	// We need to find which node this is for - extract from pending handshakes
	// Since we don't know the nodeID yet from WHOAREYOU, we need to match by address
	// and find the pending handshake
	var pending *PendingHandshake
	var pendingKey string

	h.mu.Lock()
	for key, p := range h.pendingHandshakes {
		if p.ToAddr.String() == from.String() {
			pending = p
			pendingKey = key
			break
		}
	}
	h.mu.Unlock()

	if pending == nil {
		return fmt.Errorf("no pending handshake for %s", from)
	}

	remoteNodeID := pending.ToNodeID

	// Get remote node from routing table to get its public key
	remoteNode := h.table.Get(remoteNodeID)
	if remoteNode == nil {
		h.logger.WithField("remoteID", remoteNodeID).Warn("handler: remote node not in table")
		return fmt.Errorf("remote node not in table: %s", remoteNodeID)
	}

	// Extract remote node's secp256k1 public key from ENR
	remotePubKey := remoteNode.PublicKey()
	if remotePubKey == nil {
		h.logger.Warn("handler: remote node has no public key")
		return fmt.Errorf("remote node has no public key")
	}

	// Generate ephemeral ECDH key pair
	ephKey, err := generateEphemeralKey()
	if err != nil {
		return fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	ephPubkey := encodePublicKey(&ephKey.PublicKey)

	// The challenge data is the WHOAREYOU packet header (IV + unmasked header + unmasked authdata)
	// This is stored in packet.HeaderData
	challengeData := packet.HeaderData

	// Create ID nonce signature
	signature, err := makeIDSignature(h.privateKey, challengeData, ephPubkey, remoteNodeID)
	if err != nil {
		return fmt.Errorf("failed to create ID signature: %w", err)
	}

	// Derive session keys using HKDF
	// We are the initiator (we sent the random packet first)
	sessionKeys, err := deriveKeys(ephKey, remotePubKey, h.localNode.ID(), remoteNodeID, challengeData)
	if err != nil {
		h.logger.WithError(err).Error("handler: failed to derive session keys")
		return fmt.Errorf("failed to derive session keys: %w", err)
	}

	// Check if we should send our ENR
	// - If ENRSeq is 0, they don't have our ENR, so always send it
	// - If ENRSeq > 0, only send if our seq is higher
	var enrBytes []byte
	localENR := h.localNode.Record()
	if packet.Challenge.ENRSeq == 0 || packet.Challenge.ENRSeq < localENR.Seq() {
		enrBytes, err = localENR.EncodeRLP()
		if err != nil {
			h.logger.WithError(err).Warn("handler: failed to encode ENR")
		} else {
		}
	}

	// Encode the message plaintext: message-type (1 byte) + RLP-encoded message
	msgBytes, err := pending.Message.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode message: %w", err)
	}

	plaintext := make([]byte, 1+len(msgBytes))
	plaintext[0] = pending.Message.Type()
	copy(plaintext[1:], msgBytes)

	// Generate nonce for the handshake packet
	nonce, err := crypto.GenerateRandomBytes(12)
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Build unmasked header data for GCM authentication
	// This returns: maskingIV, unmasked headerData (IV || header || authdata)
	maskingIV, headerData, err := BuildHandshakeHeaderData(h.localNode.ID(), nonce,
		signature, ephPubkey, enrBytes)
	if err != nil {
		return fmt.Errorf("failed to build header data: %w", err)
	}

	// Encrypt the message with GCM using headerData as additional authenticated data
	ciphertext, err := session.EncryptMessage(sessionKeys.InitiatorKey, nonce, headerData, plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt handshake message: %w", err)
	}

	// Encode final handshake packet with encrypted message
	// This uses the same maskingIV to ensure consistency
	packetBytes, err := EncodeHandshakePacket(h.localNode.ID(), remoteNodeID, maskingIV, nonce,
		signature, ephPubkey, enrBytes, ciphertext)
	if err != nil {
		return fmt.Errorf("failed to encode handshake packet: %w", err)
	}

	// Store session keys
	sess := session.NewSession(
		remoteNodeID,
		from,
		sessionKeys,
		true, // we are the initiator
		12*time.Hour,
	)
	h.sessions.Put(sess)

	// Remove pending handshake
	h.mu.Lock()
	delete(h.pendingHandshakes, pendingKey)
	h.mu.Unlock()

	// Send handshake packet
	h.mu.RLock()
	transport := h.transport
	h.mu.RUnlock()

	if transport == nil {
		return fmt.Errorf("transport not initialized")
	}

	if err := transport.SendTo(packetBytes, from); err != nil {
		return fmt.Errorf("failed to send handshake packet: %w", err)
	}

	h.mu.Lock()
	h.packetsSent++
	h.mu.Unlock()

	return nil
}

// makeHandshakeKey creates a unique key for tracking pending handshakes
func makeHandshakeKey(nodeID node.ID, addr *net.UDPAddr) string {
	return fmt.Sprintf("%s@%s", nodeID.String(), addr.String())
}

// buildWHOAREYOUChallengeData builds the unmasked challenge data for signature verification.
// This matches the headerData that the remote node will extract when decoding the WHOAREYOU packet.
// Format: IV (16) || unmasked-header (23) || unmasked-authdata (24)
func buildWHOAREYOUChallengeData(maskingIV, nonce []byte, challenge *WHOAREYOUChallenge) []byte {
	// Build unmasked static header (23 bytes)
	// Format: protocol-id(6) || version(2) || flag(1) || nonce(12) || authsize(2)
	staticHeader := make([]byte, 23)
	copy(staticHeader[0:6], []byte("discv5"))
	binary.BigEndian.PutUint16(staticHeader[6:8], 1) // version
	staticHeader[8] = WHOAREYOUPacket                // flag = 0x01
	copy(staticHeader[9:21], nonce)
	binary.BigEndian.PutUint16(staticHeader[21:23], 24) // authsize

	// Build unmasked authdata (24 bytes): id-nonce (16) || enr-seq (8)
	authdata := make([]byte, 24)
	copy(authdata[0:16], challenge.IDNonce[:16])
	binary.BigEndian.PutUint64(authdata[16:24], challenge.ENRSeq)

	// Build complete challenge data: IV || unmasked-header || unmasked-authdata
	challengeData := make([]byte, 0, 16+23+24)
	challengeData = append(challengeData, maskingIV...)
	challengeData = append(challengeData, staticHeader...)
	challengeData = append(challengeData, authdata...)

	return challengeData
}

// handleHandshakePacket handles a handshake packet.
func (h *Handler) handleHandshakePacket(packet *Packet, from *net.UDPAddr) error {
	// This is a response to our WHOAREYOU challenge

	if packet.Handshake == nil {
		return fmt.Errorf("handshake packet has no handshake data")
	}

	// Convert source node ID
	var sourceNodeID node.ID
	if len(packet.Handshake.SourceNodeID) != 32 {
		return fmt.Errorf("invalid source node ID length: %d", len(packet.Handshake.SourceNodeID))
	}
	copy(sourceNodeID[:], packet.Handshake.SourceNodeID)

	// Look up the pending challenge we sent
	challengeKey := makeHandshakeKey(sourceNodeID, from)
	h.mu.Lock()
	pendingChallenge, exists := h.pendingChallenges[challengeKey]
	if !exists {
		h.mu.Unlock()
		h.logger.WithField("from", from).Debug("handler: no pending challenge found for handshake")
		return fmt.Errorf("no pending challenge for handshake from %s", from)
	}
	delete(h.pendingChallenges, challengeKey)
	h.mu.Unlock()

	// Get sender's static public key for signature verification
	// First try to extract it from the ENR in the handshake packet
	var senderPubKey *ecdsa.PublicKey
	var remoteNodeFromENR *node.Node
	if len(packet.Handshake.ENR) > 0 {
		enrRecord := &enr.Record{}
		if err := enrRecord.DecodeRLPBytes(packet.Handshake.ENR); err != nil {
			h.logger.WithError(err).Warn("handler: failed to decode ENR from handshake")
		} else {
			remoteNode, err := node.New(enrRecord)
			if err != nil {
				h.logger.WithError(err).Warn("handler: failed to create node from ENR")
			} else {
				remoteNodeFromENR = remoteNode
				senderPubKey = remoteNode.PublicKey()
			}
		}
	}

	// Fall back to routing table if ENR not present or failed to decode
	if senderPubKey == nil {
		senderNode := h.table.Get(sourceNodeID)
		if senderNode == nil {
			h.logger.WithField("sourceNodeID", sourceNodeID.String()[:16]).Warn("handler: sender node not in table and no ENR provided")
			return fmt.Errorf("sender node not in table and no ENR provided")
		}
		senderPubKey = senderNode.PublicKey()
		if senderPubKey == nil {
			h.logger.Warn("handler: sender node has no public key")
			return fmt.Errorf("sender node has no public key")
		}
	}

	// Decode ephemeral public key (for ECDH)
	ephPubKey, err := decodePublicKey(packet.Handshake.EphemeralPubKey)
	if err != nil {
		return fmt.Errorf("failed to decode ephemeral public key: %w", err)
	}

	// Verify the ID signature using the sender's STATIC public key
	// The signature is over: "discovery v5 identity proof" || challenge-data || ephemeral-pubkey || dest-id
	// where challenge-data is the WHOAREYOU packet bytes and dest-id is our local node ID
	if !verifyIDSignature(senderPubKey, packet.Handshake.Signature, pendingChallenge.ChallengeData,
		packet.Handshake.EphemeralPubKey, h.localNode.ID()) {
		h.logger.WithField("from", from).Warn("handler: invalid handshake signature")
		return fmt.Errorf("invalid handshake signature")
	}

	// Derive session keys
	// We are the recipient (we sent the WHOAREYOU), they are the initiator
	sessionKeys, err := deriveKeys(
		h.privateKey,                   // Our private key
		ephPubKey,                      // Their ephemeral public key
		sourceNodeID,                   // Initiator ID (them)
		h.localNode.ID(),               // Recipient ID (us)
		pendingChallenge.ChallengeData, // Challenge data as salt
	)
	if err != nil {
		h.logger.WithError(err).Error("handler: failed to derive session keys")
		return fmt.Errorf("failed to derive session keys: %w", err)
	}

	// Decrypt the message
	// The message was encrypted with the initiator key
	plaintext, err := session.DecryptMessage(
		sessionKeys.InitiatorKey,
		packet.Header.Nonce,
		packet.HeaderData, // IV + header + authdata used as GCM additional data
		packet.Message,
	)
	if err != nil {
		h.logger.WithError(err).Error("handler: failed to decrypt handshake message")
		return fmt.Errorf("failed to decrypt handshake message: %w", err)
	}

	// Establish the session
	sess := session.NewSession(
		sourceNodeID,
		from,
		sessionKeys,
		false, // we are the recipient, not the initiator
		12*time.Hour,
	)
	h.sessions.Put(sess)

	h.logger.WithFields(logrus.Fields{
		"sourceNodeID": sourceNodeID.String()[:16],
		"from":         from,
	}).Info("handler: session established successfully")

	// Add node to routing table if we extracted it from the ENR
	if remoteNodeFromENR != nil {
		h.table.Add(remoteNodeFromENR)
	}

	// Decode and process the message
	if len(plaintext) < 1 {
		return fmt.Errorf("handshake message too short")
	}

	msgType := plaintext[0]
	msgData := plaintext[1:]

	// Convert to Message interface and decode
	msg := h.createMessage(msgType)
	if msg == nil {
		h.logger.WithField("msgType", msgType).Warn("handler: unknown message type in handshake")
		return fmt.Errorf("unknown message type: %d", msgType)
	}

	if err := rlp.DecodeBytes(msgData, msg); err != nil {
		h.logger.WithError(err).Error("handler: failed to decode handshake message")
		return fmt.Errorf("failed to decode message: %w", err)
	}

	// Handle the message
	return h.handleMessage(msg, sourceNodeID, from)
}

// handleMessage dispatches a decoded message to the appropriate handler.
func (h *Handler) handleMessage(msg Message, remoteID node.ID, from *net.UDPAddr) error {
	switch msg.Type() {
	case PingMsg:
		return h.handlePing(msg.(*Ping), remoteID, from)
	case PongMsg:
		return h.handlePong(msg.(*Pong), remoteID, from)
	case FindNodeMsg:
		return h.handleFindNode(msg.(*FindNode), remoteID, from)
	case NodesMsg:
		return h.handleNodes(msg.(*Nodes), remoteID, from)
	case TalkReqMsg:
		return h.handleTalkReq(msg.(*TalkReq), remoteID, from)
	case TalkRespMsg:
		return h.handleTalkResp(msg.(*TalkResp), remoteID, from)
	default:
		h.logger.Debug("handler: unknown message type",
			"type", msg.Type(),
			"from", from,
		)
		return fmt.Errorf("unknown message type: %d", msg.Type())
	}
}

// handlePing handles a PING message.
func (h *Handler) handlePing(msg *Ping, remoteID node.ID, from *net.UDPAddr) error {
	h.logger.WithFields(logrus.Fields{
		"from":   from,
		"nodeID": remoteID,
	}).Debug("handler: received PING")

	// Check if remote has a higher ENR sequence than what we have
	if existingNode := h.table.Get(remoteID); existingNode != nil {
		if msg.ENRSeq > existingNode.Record().Seq() {
			h.logger.WithFields(logrus.Fields{
				"nodeID":   remoteID.String()[:16],
				"ourSeq":   existingNode.Record().Seq(),
				"theirSeq": msg.ENRSeq,
			}).Debug("handler: remote has newer ENR, requesting update")
			// Request the updated ENR immediately via FINDNODE distance 0
			h.requestENRUpdate(existingNode)
		}
	}

	// Create PONG response
	pong := &Pong{
		RequestID: msg.RequestID,
		ENRSeq:    h.localNode.Record().Seq(),
		IP:        from.IP,
		Port:      uint16(from.Port),
	}

	// Send PONG
	return h.sendMessage(pong, remoteID, from)
}

// handlePong handles a PONG message.
func (h *Handler) handlePong(msg *Pong, remoteID node.ID, from *net.UDPAddr) error {
	h.logger.WithFields(logrus.Fields{
		"from":   from,
		"nodeID": remoteID,
	}).Debug("handler: received PONG")

	// Match with pending request
	h.requests.MatchResponse(msg.RequestID, remoteID, msg)

	// Update node's last seen time
	if n := h.table.Get(remoteID); n != nil {
		n.SetLastSeen(time.Now())
		n.ResetFailureCount()

		// Check if remote has a higher ENR sequence than what we have
		if msg.ENRSeq > n.Record().Seq() {
			h.logger.WithFields(logrus.Fields{
				"nodeID":   remoteID.String()[:16],
				"ourSeq":   n.Record().Seq(),
				"theirSeq": msg.ENRSeq,
			}).Debug("handler: remote has newer ENR, requesting update")
			// Request the updated ENR immediately via FINDNODE distance 0
			h.requestENRUpdate(n)
		}
	}

	return nil
}

// handleFindNode handles a FINDNODE message.
func (h *Handler) handleFindNode(msg *FindNode, remoteID node.ID, from *net.UDPAddr) error {
	h.mu.Lock()
	h.findNodeReceived++
	h.mu.Unlock()

	h.logger.WithFields(logrus.Fields{
		"from":      from,
		"nodeID":    remoteID,
		"distances": msg.Distances,
	}).Debug("handler: received FINDNODE")

	// Find closest nodes based on requested distances
	var nodes []*node.Node

	if len(msg.Distances) == 1 && msg.Distances[0] == 0 {
		// Special case: distance 0 means "return your own ENR"
		nodes = []*node.Node{h.localNode}
		h.logger.WithFields(logrus.Fields{
			"from":   from,
			"nodeID": remoteID.String()[:16],
		}).Debug("handler: FINDNODE distance 0, returning our ENR")
	} else if len(msg.Distances) == 1 && msg.Distances[0] == 256 {
		// Special case: return all nodes
		nodes = h.table.FindClosestNodes(h.localNode.ID(), 16)
	} else {
		// Find nodes at requested distances
		// Collect nodes from buckets matching the requested distances
		var collectedNodes []*node.Node
		for _, distance := range msg.Distances {
			// Validate distance is in valid range (0-255)
			if distance >= 256 {
				h.logger.WithFields(logrus.Fields{
					"from":     from,
					"nodeID":   remoteID.String()[:16],
					"distance": distance,
				}).Debug("handler: FINDNODE invalid distance, skipping")
				continue
			}

			// Get nodes from the bucket at this distance
			bucketNodes := h.table.GetBucketNodes(int(distance))
			collectedNodes = append(collectedNodes, bucketNodes...)

			// Limit total nodes to 16 (standard Kademlia bucket size)
			if len(collectedNodes) >= 16 {
				collectedNodes = collectedNodes[:16]
				break
			}
		}
		nodes = collectedNodes

		h.logger.WithFields(logrus.Fields{
			"from":      from,
			"nodeID":    remoteID.String()[:16],
			"distances": msg.Distances,
			"found":     len(nodes),
		}).Debug("handler: FINDNODE distance-based lookup completed")
	}

	// Apply response filter (Stage 2)
	filteredNodes := FilterNodes(from, nodes, h.responseFilter)

	if len(filteredNodes) < len(nodes) {
		h.mu.Lock()
		h.filteredResponses += (len(nodes) - len(filteredNodes))
		h.mu.Unlock()
	}

	// Split nodes into multiple packets if needed to stay under max packet size
	// Each ENR is typically 200-400 bytes, so we limit to 3 nodes per packet to be safe
	const maxNodesPerPacket = 3

	// Calculate total number of packets needed
	totalPackets := (len(filteredNodes) + maxNodesPerPacket - 1) / maxNodesPerPacket
	if totalPackets == 0 {
		totalPackets = 1 // Always send at least one response, even if empty
	}

	// Send NODES responses in chunks
	for i := 0; i < totalPackets; i++ {
		start := i * maxNodesPerPacket
		end := start + maxNodesPerPacket
		if end > len(filteredNodes) {
			end = len(filteredNodes)
		}

		chunk := filteredNodes[start:end]
		records := make([]*enr.Record, len(chunk))
		for j, n := range chunk {
			records[j] = n.Record()
		}

		nodesMsg := &Nodes{
			RequestID: msg.RequestID,
			Total:     uint(totalPackets),
			Records:   records,
		}

		if err := h.sendMessage(nodesMsg, remoteID, from); err != nil {
			return err
		}
	}

	return nil
}

// handleNodes handles a NODES message.
func (h *Handler) handleNodes(msg *Nodes, remoteID node.ID, from *net.UDPAddr) error {
	h.logger.WithFields(logrus.Fields{
		"from":   from,
		"nodeID": remoteID,
		"count":  len(msg.Records),
	}).Debug("handler: received NODES")

	// Match with pending request
	h.requests.MatchResponse(msg.RequestID, remoteID, msg)

	// Add discovered nodes to routing table
	for _, record := range msg.Records {
		n, err := node.New(record)
		if err != nil {
			h.logger.WithFields(logrus.Fields{
				"from":   from,
				"nodeID": remoteID,
				"error":  err,
			}).Debug("handler: invalid node in NODES response")
			continue
		}

		// Try to add to routing table (will apply admission filter)
		h.table.Add(n)
	}

	return nil
}

// handleTalkReq handles a TALKREQ message.
func (h *Handler) handleTalkReq(msg *TalkReq, remoteID node.ID, from *net.UDPAddr) error {
	h.logger.WithFields(logrus.Fields{
		"from":     from,
		"nodeID":   remoteID,
		"protocol": string(msg.Protocol),
	}).Debug("handler: received TALKREQ")

	// For now, send empty TALKRESP
	// Applications can register custom TALK handlers
	resp := &TalkResp{
		RequestID: msg.RequestID,
		Response:  []byte{},
	}

	return h.sendMessage(resp, remoteID, from)
}

// handleTalkResp handles a TALKRESP message.
func (h *Handler) handleTalkResp(msg *TalkResp, remoteID node.ID, from *net.UDPAddr) error {
	h.logger.WithFields(logrus.Fields{
		"from":   from,
		"nodeID": remoteID,
	}).Debug("handler: received TALKRESP")

	// Match with pending request
	h.requests.MatchResponse(msg.RequestID, remoteID, msg)

	return nil
}

// sendMessage sends a message to a remote node.
func (h *Handler) sendMessage(msg Message, remoteID node.ID, to *net.UDPAddr) error {
	// Look up session
	sess := h.sessions.Get(remoteID)

	var packetBytes []byte
	var err error

	if sess == nil {
		// No session - send random packet to trigger WHOAREYOU from receiver

		// Store pending message for handshake completion
		handshakeKey := makeHandshakeKey(remoteID, to)
		h.mu.Lock()
		h.pendingHandshakes[handshakeKey] = &PendingHandshake{
			Message:   msg,
			ToAddr:    to,
			ToNodeID:  remoteID,
			CreatedAt: time.Now(),
		}
		h.mu.Unlock()

		// Encode random packet (go-ethereum style)
		// This will be 91 bytes: IV(16) + header(23) + authdata(32) + random(20)
		packetBytes, err = EncodeRandomPacket(h.localNode.ID(), remoteID)
		if err != nil {
			return fmt.Errorf("failed to encode random packet: %w", err)
		}
	} else {
		// Have session - encrypt and send normally

		// Encode message plaintext: message-type (1 byte) + RLP-encoded message
		msgBytes, err := msg.Encode()
		if err != nil {
			return fmt.Errorf("failed to encode message: %w", err)
		}

		// Build plaintext: message type + message data
		plaintext := make([]byte, 1+len(msgBytes))
		plaintext[0] = msg.Type()
		copy(plaintext[1:], msgBytes)

		// Generate nonce
		nonce, err := crypto.GenerateRandomBytes(12)
		if err != nil {
			return fmt.Errorf("failed to generate nonce: %w", err)
		}

		// Get local node ID
		localNodeID := h.localNode.ID()

		// Authdata for ordinary message with session: srcID (32 bytes)
		authdata := localNodeID[:]

		// Build unmasked header data for GCM authentication
		// This returns: maskingIV, unmasked headerData (IV || header || authdata)
		maskingIV, headerData, err := BuildOrdinaryHeaderData(localNodeID, nonce, authdata)
		if err != nil {
			return fmt.Errorf("failed to build header data: %w", err)
		}

		// Encrypt message using session key
		// GCM uses unmasked headerData as additional authenticated data
		ciphertext, err := session.EncryptMessage(sess.EncryptionKey(), nonce, headerData, plaintext)
		if err != nil {
			return fmt.Errorf("failed to encrypt message: %w", err)
		}

		// Now encode the full packet with the encrypted message
		// This uses the same maskingIV to ensure consistency
		packetBytes, err = EncodeOrdinaryPacket(localNodeID, remoteID, maskingIV, nonce, authdata, ciphertext)
		if err != nil {
			return fmt.Errorf("failed to encode ordinary packet: %w", err)
		}
	}

	// Send via UDP transport
	h.mu.RLock()
	transport := h.transport
	h.mu.RUnlock()

	if transport == nil {
		return fmt.Errorf("transport not initialized")
	}

	if err := transport.SendTo(packetBytes, to); err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}

	h.mu.Lock()
	h.packetsSent++
	h.mu.Unlock()

	h.logger.WithFields(logrus.Fields{
		"type":   msg.Type(),
		"to":     to,
		"nodeID": remoteID,
		"size":   len(packetBytes),
	}).Trace("sent message")

	return nil
}

// sendWHOAREYOU sends a WHOAREYOU challenge.
func (h *Handler) sendWHOAREYOU(to *net.UDPAddr, destNodeID node.ID) error {

	// Generate random ID nonce for the challenge (32 bytes, but only first 16 used)
	idNonce, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		return fmt.Errorf("failed to generate ID nonce: %w", err)
	}

	// Generate nonce for packet
	nonce, err := crypto.GenerateRandomBytes(12)
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Get the current ENR sequence we have for this node
	enrSeq := uint64(0)
	if existingNode := h.table.Get(destNodeID); existingNode != nil {
		enrSeq = existingNode.Record().Seq()
	}

	// Create WHOAREYOU challenge
	challenge := &WHOAREYOUChallenge{
		IDNonce: idNonce,
		ENRSeq:  enrSeq, // Send the ENR seq we have, so they know if we need an update
	}

	// Encode WHOAREYOU packet (go-ethereum style)
	// This will be 63 bytes: IV(16) + header(23) + authdata(24)
	packetBytes, maskingIV, err := EncodeWHOAREYOUPacketWithIV(destNodeID, nonce, challenge)
	if err != nil {
		return fmt.Errorf("failed to encode WHOAREYOU packet: %w", err)
	}

	// Build unmasked challenge data for signature verification
	// Format: IV || unmasked-header || unmasked-authdata
	// This is what the remote node will use when creating their handshake signature
	challengeData := buildWHOAREYOUChallengeData(maskingIV, nonce, challenge)

	// Store the challenge so we can verify the handshake response
	challengeKey := makeHandshakeKey(destNodeID, to)
	h.mu.Lock()
	h.pendingChallenges[challengeKey] = &PendingChallenge{
		ToAddr:        to,
		ToNodeID:      destNodeID,
		Challenge:     challenge,
		ChallengeData: challengeData,
		CreatedAt:     time.Now(),
	}
	h.mu.Unlock()

	// Send via UDP transport
	h.mu.RLock()
	transport := h.transport
	h.mu.RUnlock()

	if transport == nil {
		return fmt.Errorf("transport not initialized")
	}

	if err := transport.SendTo(packetBytes, to); err != nil {
		return fmt.Errorf("failed to send WHOAREYOU packet: %w", err)
	}

	return nil
}

// cleanupLoop runs periodically to remove expired pending entries.
func (h *Handler) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.cleanupExpiredEntries()
		case <-h.stopChan:
			return
		}
	}
}

// cleanupExpiredEntries removes expired pending handshakes and challenges.
func (h *Handler) cleanupExpiredEntries() {
	now := time.Now()

	h.mu.Lock()

	// Clean up expired pending handshakes
	expiredHandshakes := 0
	for key, pending := range h.pendingHandshakes {
		if now.Sub(pending.CreatedAt) > pendingHandshakeTimeout {
			delete(h.pendingHandshakes, key)
			expiredHandshakes++
		}
	}

	// Clean up expired pending challenges
	expiredChallenges := 0
	for key, pending := range h.pendingChallenges {
		if now.Sub(pending.CreatedAt) > pendingChallengeTimeout {
			delete(h.pendingChallenges, key)
			expiredChallenges++
		}
	}

	h.mu.Unlock()

	// Clean up expired sessions
	expiredSessions := h.sessions.CleanupExpired()

	if expiredHandshakes > 0 || expiredChallenges > 0 || expiredSessions > 0 {
		h.logger.WithFields(logrus.Fields{
			"expiredHandshakes": expiredHandshakes,
			"expiredChallenges": expiredChallenges,
			"expiredSessions":   expiredSessions,
		}).Debug("handler: cleaned up expired entries")
	}
}

// Close stops the handler and cleans up resources.
func (h *Handler) Close() {
	close(h.stopChan)
}

// SendPing sends a PING to a remote node.
//
// Returns a channel that will receive the PONG response.
func (h *Handler) SendPing(n *node.Node) (<-chan *Response, error) {
	requestID, err := NewRequestID()
	if err != nil {
		return nil, err
	}

	ping := &Ping{
		RequestID: requestID,
		ENRSeq:    h.localNode.Record().Seq(),
	}

	// Register pending request
	respChan := h.requests.AddRequest(requestID, n.ID(), PingMsg)

	// Send PING
	if err := h.sendMessage(ping, n.ID(), n.Addr()); err != nil {
		h.logger.WithFields(logrus.Fields{
			"to":     n.Addr(),
			"nodeID": n.ID(),
			"error":  err,
		}).Debug("handler: failed to send PING")
		h.requests.CancelRequest(requestID)
		return nil, err
	}

	h.logger.WithFields(logrus.Fields{
		"to":     n.Addr(),
		"nodeID": n.ID(),
	}).Debug("handler: PING sent successfully")

	return respChan, nil
}

// requestENRUpdate sends a FINDNODE request with distance 0 to fetch the node's updated ENR.
//
// This is called when we detect that a remote node has a newer ENR sequence.
// The request is sent asynchronously and the response is handled in a goroutine.
func (h *Handler) requestENRUpdate(n *node.Node) {
	go func() {
		h.logger.WithFields(logrus.Fields{
			"nodeID": n.ID().String()[:16],
			"addr":   n.Addr(),
		}).Debug("handler: requesting ENR update via FINDNODE distance 0")

		// Send FINDNODE with distance 0 (requests the node's own ENR)
		respChan, err := h.SendFindNode(n, []uint{0})
		if err != nil {
			h.logger.WithFields(logrus.Fields{
				"nodeID": n.ID().String()[:16],
				"error":  err,
			}).Debug("handler: failed to request ENR update")
			return
		}

		// Wait for response with timeout
		select {
		case resp := <-respChan:
			if resp.Error != nil {
				h.logger.WithFields(logrus.Fields{
					"nodeID": n.ID().String()[:16],
					"error":  resp.Error,
				}).Debug("handler: ENR update request failed")
				return
			}

			// The NODES response handler will automatically update the ENR in our table
			nodesMsg, ok := resp.Message.(*Nodes)
			if ok && len(nodesMsg.Records) > 0 {
				h.logger.WithFields(logrus.Fields{
					"nodeID": n.ID().String()[:16],
					"count":  len(nodesMsg.Records),
				}).Debug("handler: received ENR update")
			}

		case <-time.After(5 * time.Second):
			h.logger.WithFields(logrus.Fields{
				"nodeID": n.ID().String()[:16],
			}).Debug("handler: ENR update request timed out")
		}
	}()
}

// SendFindNode sends a FINDNODE request.
//
// Returns a channel that will receive the NODES response.
func (h *Handler) SendFindNode(n *node.Node, distances []uint) (<-chan *Response, error) {
	requestID, err := NewRequestID()
	if err != nil {
		return nil, err
	}

	findNode := &FindNode{
		RequestID: requestID,
		Distances: distances,
	}

	// Register pending request
	respChan := h.requests.AddRequest(requestID, n.ID(), FindNodeMsg)

	// Send FINDNODE
	if err := h.sendMessage(findNode, n.ID(), n.Addr()); err != nil {
		h.logger.WithFields(logrus.Fields{
			"to":        n.Addr(),
			"nodeID":    n.ID(),
			"distances": distances,
			"error":     err,
		}).Debug("handler: failed to send FINDNODE")
		h.requests.CancelRequest(requestID)
		return nil, err
	}

	h.logger.WithFields(logrus.Fields{
		"to":        n.Addr(),
		"nodeID":    n.ID(),
		"distances": distances,
	}).Debug("handler: FINDNODE sent successfully")

	return respChan, nil
}

// GetStats returns handler statistics.
type HandlerStats struct {
	PacketsReceived   int
	PacketsSent       int
	InvalidPackets    int
	FilteredResponses int
	FindNodeReceived  int
	PendingHandshakes int
	PendingChallenges int
	RequestStats      RequestStats
}

// GetStats returns statistics about the handler.
func (h *Handler) GetStats() HandlerStats {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return HandlerStats{
		PacketsReceived:   h.packetsReceived,
		PacketsSent:       h.packetsSent,
		InvalidPackets:    h.invalidPackets,
		FilteredResponses: h.filteredResponses,
		FindNodeReceived:  h.findNodeReceived,
		PendingHandshakes: len(h.pendingHandshakes),
		PendingChallenges: len(h.pendingChallenges),
		RequestStats:      h.requests.GetStats(),
	}
}

// createMessage creates a Message instance based on message type.
//
// This is a simple factory that returns empty message structs.
// Full decoding would need RLP parsing of the message content.
func (h *Handler) createMessage(msgType byte) Message {
	switch msgType {
	case PingMsg:
		return &Ping{}
	case PongMsg:
		return &Pong{}
	case FindNodeMsg:
		return &FindNode{}
	case NodesMsg:
		return &Nodes{}
	case TalkReqMsg:
		return &TalkReq{}
	case TalkRespMsg:
		return &TalkResp{}
	default:
		return nil
	}
}
