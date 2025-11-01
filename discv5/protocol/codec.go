package protocol

import (
	"fmt"

	"github.com/ethereum/go-ethereum/rlp"
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
