package node

import (
	"errors"
)

var (
	// ErrInvalidAddress is returned when a network address is invalid.
	ErrInvalidAddress = errors.New("node: invalid network address")

	// ErrInvalidPort is returned when a port number is invalid.
	ErrInvalidPort = errors.New("node: invalid port number")

	// ErrInvalidNodeID is returned when a node ID is invalid.
	ErrInvalidNodeID = errors.New("node: invalid node ID")

	// ErrInvalidENR is returned when an ENR record is invalid.
	ErrInvalidENR = errors.New("node: invalid ENR record")

	// ErrMulticastNotSupported is returned for multicast addresses.
	ErrMulticastNotSupported = errors.New("node: multicast addresses not supported")

	// ErrNodeNotFound is returned when a node is not in the database.
	ErrNodeNotFound = errors.New("node: node not found")

	// ErrNodeAlreadyExists is returned when trying to add a duplicate node.
	ErrNodeAlreadyExists = errors.New("node: node already exists")

	// ErrTimeout is returned when an operation times out.
	ErrTimeout = errors.New("node: operation timed out")

	// ErrNetworkError is returned for network-related errors.
	ErrNetworkError = errors.New("node: network error")

	// ErrProtocolError is returned for protocol violations.
	ErrProtocolError = errors.New("node: protocol error")
)

// IsTimeout checks if an error is a timeout error.
func IsTimeout(err error) bool {
	return errors.Is(err, ErrTimeout)
}

// IsNetworkError checks if an error is a network error.
func IsNetworkError(err error) bool {
	return errors.Is(err, ErrNetworkError)
}

// IsProtocolError checks if an error is a protocol error.
func IsProtocolError(err error) bool {
	return errors.Is(err, ErrProtocolError)
}
