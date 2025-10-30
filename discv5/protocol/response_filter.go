package protocol

import (
	"net"

	"github.com/pk910/bootoor/discv5/enr"
	"github.com/pk910/bootoor/discv5/node"
)

// ResponseFilter filters nodes before including them in a FINDNODE response.
//
// This is Stage 2 filtering - applied when serving responses to other nodes.
// The filter can be context-aware (e.g., based on requester's address).
//
// Parameters:
//   - requester: The address of the node requesting FINDNODE
//   - record: The ENR record being considered for the response
//
// Returns true if the node should be included in the response.
type ResponseFilter func(requester *net.UDPAddr, record *enr.Record) bool

// LANAwareResponseFilter prevents serving LAN addresses to WAN requesters.
//
// This is a built-in security feature to prevent leaking private network
// topology to external nodes.
//
// Behavior:
//   - LAN requesters receive all nodes (LAN and WAN)
//   - WAN requesters only receive WAN nodes
//
// Example:
//
//	filter := LANAwareResponseFilter()
//	handler := NewHandler(HandlerConfig{
//	    ResponseFilter: filter,
//	})
func LANAwareResponseFilter() ResponseFilter {
	return func(requester *net.UDPAddr, record *enr.Record) bool {
		requesterIsLAN := node.IsLANAddress(requester.IP)

		// Get node's IP from ENR
		nodeIP := record.IP()
		if nodeIP == nil {
			nodeIP = record.IP6()
		}
		if nodeIP == nil {
			// No IP in ENR, exclude from response
			return false
		}

		nodeIsLAN := node.IsLANAddress(nodeIP)

		// Don't serve LAN nodes to WAN requesters
		if !requesterIsLAN && nodeIsLAN {
			return false
		}

		return true
	}
}

// ChainResponseFilters combines multiple response filters with AND logic.
//
// All filters must pass for a node to be included in the response.
//
// Example:
//
//	filter := ChainResponseFilters(
//	    LANAwareResponseFilter(),
//	    CustomVersionFilter(),
//	)
func ChainResponseFilters(filters ...ResponseFilter) ResponseFilter {
	return func(requester *net.UDPAddr, record *enr.Record) bool {
		for _, filter := range filters {
			if !filter(requester, record) {
				return false
			}
		}
		return true
	}
}

// AlwaysAllowFilter is a no-op filter that allows all nodes.
//
// Use this if you don't want any response filtering.
func AlwaysAllowFilter() ResponseFilter {
	return func(requester *net.UDPAddr, record *enr.Record) bool {
		return true
	}
}

// IPRangeResponseFilter creates a filter that only serves nodes in allowed IP ranges.
//
// Example:
//
//	// Only serve nodes in 10.0.0.0/8
//	filter := IPRangeResponseFilter([]*net.IPNet{
//	    {IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
//	})
func IPRangeResponseFilter(allowedRanges []*net.IPNet) ResponseFilter {
	return func(requester *net.UDPAddr, record *enr.Record) bool {
		nodeIP := record.IP()
		if nodeIP == nil {
			nodeIP = record.IP6()
		}
		if nodeIP == nil {
			return false
		}

		// Check if IP is in any allowed range
		for _, ipNet := range allowedRanges {
			if ipNet.Contains(nodeIP) {
				return true
			}
		}

		return false
	}
}

// FilterNodes applies a response filter to a list of nodes.
//
// Returns only the nodes that pass the filter.
func FilterNodes(requester *net.UDPAddr, nodes []*node.Node, filter ResponseFilter) []*node.Node {
	if filter == nil {
		return nodes
	}

	result := make([]*node.Node, 0, len(nodes))

	for _, n := range nodes {
		if filter(requester, n.Record()) {
			result = append(result, n)
		}
	}

	return result
}
