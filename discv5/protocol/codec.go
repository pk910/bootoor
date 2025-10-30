package protocol

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/rlp"
	"github.com/pk910/bootoor/discv5/enr"
)

// encodeMessage encodes message content as RLP.
//
// Format: rlp(message-content)
//
// The message type byte is NOT included here - it's prepended by the handler.
// This is a helper function used by all message types.
func encodeMessage(msgType byte, content []interface{}) ([]byte, error) {
	// RLP encode the content only
	encoded, err := rlp.EncodeToBytes(content)
	if err != nil {
		return nil, fmt.Errorf("failed to RLP encode message: %w", err)
	}

	return encoded, nil
}

// DecodeMessage decodes a message and returns its type and content.
//
// This performs the first level of decoding, extracting the message
// type byte and the remaining RLP-encoded content.
//
// Returns:
//   - msgType: The message type byte
//   - content: The remaining message content as raw RLP
//   - error: Any decoding error
func DecodeMessage(data []byte) (byte, []byte, error) {
	// Decode as RLP list
	var items []interface{}
	if err := rlp.DecodeBytes(data, &items); err != nil {
		return 0, nil, fmt.Errorf("failed to RLP decode message: %w", err)
	}

	if len(items) < 1 {
		return 0, nil, fmt.Errorf("message too short")
	}

	// Extract message type
	typeBytes, ok := items[0].([]byte)
	if !ok || len(typeBytes) != 1 {
		return 0, nil, fmt.Errorf("invalid message type")
	}
	msgType := typeBytes[0]

	// Re-encode remaining content for specific message decoder
	content, err := rlp.EncodeToBytes(items[1:])
	if err != nil {
		return 0, nil, fmt.Errorf("failed to encode content: %w", err)
	}

	return msgType, content, nil
}

// DecodePing decodes a PING message from RLP data.
//
// Expected format: [request-id, enr-seq]
func DecodePing(data []byte) (*Ping, error) {
	var items []interface{}
	if err := rlp.DecodeBytes(data, &items); err != nil {
		return nil, fmt.Errorf("failed to decode PING: %w", err)
	}

	if len(items) != 2 {
		return nil, fmt.Errorf("invalid PING format: expected 2 items, got %d", len(items))
	}

	requestID, ok := items[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid PING request ID")
	}

	enrSeqBytes, ok := items[1].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid PING ENR seq")
	}

	return &Ping{
		RequestID: requestID,
		ENRSeq:    bytesToUint64(enrSeqBytes),
	}, nil
}

// DecodePong decodes a PONG message from RLP data.
//
// Expected format: [request-id, enr-seq, ip, port]
func DecodePong(data []byte) (*Pong, error) {
	var items []interface{}
	if err := rlp.DecodeBytes(data, &items); err != nil {
		return nil, fmt.Errorf("failed to decode PONG: %w", err)
	}

	if len(items) != 4 {
		return nil, fmt.Errorf("invalid PONG format: expected 4 items, got %d", len(items))
	}

	requestID, ok := items[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid PONG request ID")
	}

	enrSeqBytes, ok := items[1].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid PONG ENR seq")
	}

	ip, ok := items[2].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid PONG IP")
	}

	portBytes, ok := items[3].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid PONG port")
	}

	return &Pong{
		RequestID: requestID,
		ENRSeq:    bytesToUint64(enrSeqBytes),
		IP:        ip,
		Port:      uint16(bytesToUint64(portBytes)),
	}, nil
}

// DecodeFindNode decodes a FINDNODE message from RLP data.
//
// Expected format: [request-id, [distance1, distance2, ...]]
func DecodeFindNode(data []byte) (*FindNode, error) {
	var items []interface{}
	if err := rlp.DecodeBytes(data, &items); err != nil {
		return nil, fmt.Errorf("failed to decode FINDNODE: %w", err)
	}

	if len(items) != 2 {
		return nil, fmt.Errorf("invalid FINDNODE format: expected 2 items, got %d", len(items))
	}

	requestID, ok := items[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid FINDNODE request ID")
	}

	distancesList, ok := items[1].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid FINDNODE distances")
	}

	distances := make([]uint, len(distancesList))
	for i, d := range distancesList {
		dBytes, ok := d.([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid distance at index %d", i)
		}
		distances[i] = uint(bytesToUint64(dBytes))
	}

	return &FindNode{
		RequestID: requestID,
		Distances: distances,
	}, nil
}

// DecodeNodes decodes a NODES message from RLP data.
//
// Expected format: [request-id, total, [enr1, enr2, ...]]
func DecodeNodes(data []byte) (*Nodes, error) {
	s := rlp.NewStream(bytes.NewReader(data), 0)

	// Decode outer list
	if _, err := s.List(); err != nil {
		return nil, fmt.Errorf("failed to decode NODES outer list: %w", err)
	}

	// Decode request ID
	var requestID []byte
	if err := s.Decode(&requestID); err != nil {
		return nil, fmt.Errorf("failed to decode NODES request ID: %w", err)
	}

	// Decode total
	var totalBytes []byte
	if err := s.Decode(&totalBytes); err != nil {
		return nil, fmt.Errorf("failed to decode NODES total: %w", err)
	}

	// Decode ENR list - get raw RLP bytes for each ENR
	if _, err := s.List(); err != nil {
		return nil, fmt.Errorf("failed to decode NODES ENR list: %w", err)
	}

	var records []*enr.Record
	for {
		// Use Raw() to get the raw RLP bytes without decoding
		enrBytes, err := s.Raw()
		if err == rlp.EOL {
			break // End of list
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get raw ENR bytes: %w", err)
		}

		record := enr.New()
		if err := record.DecodeRLPBytes(enrBytes); err != nil {
			return nil, fmt.Errorf("failed to decode ENR record: %w", err)
		}
		records = append(records, record)
	}

	if err := s.ListEnd(); err != nil {
		return nil, fmt.Errorf("failed to end NODES ENR list: %w", err)
	}

	if err := s.ListEnd(); err != nil {
		return nil, fmt.Errorf("failed to end NODES outer list: %w", err)
	}

	return &Nodes{
		RequestID: requestID,
		Total:     uint(bytesToUint64(totalBytes)),
		Records:   records,
	}, nil
}

// DecodeTalkReq decodes a TALKREQ message from RLP data.
//
// Expected format: [request-id, protocol, request]
func DecodeTalkReq(data []byte) (*TalkReq, error) {
	var items []interface{}
	if err := rlp.DecodeBytes(data, &items); err != nil {
		return nil, fmt.Errorf("failed to decode TALKREQ: %w", err)
	}

	if len(items) != 3 {
		return nil, fmt.Errorf("invalid TALKREQ format: expected 3 items, got %d", len(items))
	}

	requestID, ok := items[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid TALKREQ request ID")
	}

	protocol, ok := items[1].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid TALKREQ protocol")
	}

	request, ok := items[2].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid TALKREQ request")
	}

	return &TalkReq{
		RequestID: requestID,
		Protocol:  protocol,
		Request:   request,
	}, nil
}

// DecodeTalkResp decodes a TALKRESP message from RLP data.
//
// Expected format: [request-id, response]
func DecodeTalkResp(data []byte) (*TalkResp, error) {
	var items []interface{}
	if err := rlp.DecodeBytes(data, &items); err != nil {
		return nil, fmt.Errorf("failed to decode TALKRESP: %w", err)
	}

	if len(items) != 2 {
		return nil, fmt.Errorf("invalid TALKRESP format: expected 2 items, got %d", len(items))
	}

	requestID, ok := items[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid TALKRESP request ID")
	}

	response, ok := items[1].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid TALKRESP response")
	}

	return &TalkResp{
		RequestID: requestID,
		Response:  response,
	}, nil
}

// bytesToUint64 converts a big-endian byte slice to uint64.
func bytesToUint64(b []byte) uint64 {
	if len(b) == 0 {
		return 0
	}

	var result uint64
	for _, byte := range b {
		result = (result << 8) | uint64(byte)
	}
	return result
}

// uint64ToBytes converts a uint64 to a big-endian byte slice.
func uint64ToBytes(n uint64) []byte {
	if n == 0 {
		return []byte{0}
	}

	// Find the minimum number of bytes needed
	bytes := make([]byte, 0, 8)
	for n > 0 {
		bytes = append([]byte{byte(n & 0xFF)}, bytes...)
		n >>= 8
	}
	return bytes
}
