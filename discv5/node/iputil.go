package node

import (
	"net"
)

// IsLANAddress checks if an IP address is a private/local address.
//
// Returns true for:
//   - 10.0.0.0/8 (RFC1918)
//   - 172.16.0.0/12 (RFC1918)
//   - 192.168.0.0/16 (RFC1918)
//   - fc00::/7 (IPv6 ULA)
//   - fe80::/10 (IPv6 link-local)
//   - 127.0.0.0/8 (loopback)
//   - ::1 (IPv6 loopback)
//
// This is used to prevent serving LAN addresses to WAN peers.
//
// Example:
//
//	if IsLANAddress(node.IP()) {
//	    // Don't serve to WAN requesters
//	}
func IsLANAddress(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check for loopback
	if ip.IsLoopback() {
		return true
	}

	// Check for link-local
	if ip.IsLinkLocalUnicast() {
		return true
	}

	// IPv4 private ranges
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		return false
	}

	// IPv6 private ranges
	if ip6 := ip.To16(); ip6 != nil {
		// fc00::/7 (ULA - Unique Local Address)
		if ip6[0]&0xfe == 0xfc {
			return true
		}
		// fe80::/10 (link-local) - already checked above
	}

	return false
}

// IsWANAddress checks if an IP address is a publicly routable address.
//
// This is the inverse of IsLANAddress - returns true for public internet IPs.
//
// Example:
//
//	if IsWANAddress(requester.IP) && IsLANAddress(node.IP()) {
//	    // Don't serve LAN node to WAN requester
//	    return false
//	}
func IsWANAddress(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return !IsLANAddress(ip)
}

// IsRoutableAddress checks if an IP address is globally routable.
//
// Returns false for:
//   - Private addresses (RFC1918, ULA)
//   - Loopback addresses
//   - Link-local addresses
//   - Multicast addresses
//   - Unspecified addresses (0.0.0.0, ::)
//
// Example:
//
//	if !IsRoutableAddress(node.IP()) {
//	    // Skip this node in public discovery
//	}
func IsRoutableAddress(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check for unspecified address (0.0.0.0 or ::)
	if ip.IsUnspecified() {
		return false
	}

	// Check for multicast
	if ip.IsMulticast() {
		return false
	}

	// Check for private/local addresses
	if IsLANAddress(ip) {
		return false
	}

	return true
}

// IsSameNetwork checks if two IP addresses are on the same network.
//
// For IPv4, this checks if they're both LAN or both WAN.
// This is used to determine if nodes can directly communicate.
//
// Example:
//
//	if !IsSameNetwork(localIP, remoteIP) {
//	    // May need NAT traversal
//	}
func IsSameNetwork(ip1, ip2 net.IP) bool {
	if ip1 == nil || ip2 == nil {
		return false
	}

	// Both LAN or both WAN
	lan1 := IsLANAddress(ip1)
	lan2 := IsLANAddress(ip2)

	return lan1 == lan2
}

// GetIPVersion returns the IP version (4 or 6) of an address.
//
// Returns:
//   - 4 for IPv4 addresses
//   - 6 for IPv6 addresses
//   - 0 for invalid/nil addresses
func GetIPVersion(ip net.IP) int {
	if ip == nil {
		return 0
	}

	if ip.To4() != nil {
		return 4
	}

	return 6
}

// ValidateUDPAddr checks if a UDP address is valid for discv5 communication.
//
// Returns an error if:
//   - Address is nil
//   - IP is nil or unspecified
//   - Port is 0
//   - IP is multicast
//
// Example:
//
//	if err := ValidateUDPAddr(addr); err != nil {
//	    return fmt.Errorf("invalid address: %w", err)
//	}
func ValidateUDPAddr(addr *net.UDPAddr) error {
	if addr == nil {
		return ErrInvalidAddress
	}

	if addr.IP == nil || addr.IP.IsUnspecified() {
		return ErrInvalidAddress
	}

	if addr.Port == 0 {
		return ErrInvalidPort
	}

	if addr.IP.IsMulticast() {
		return ErrMulticastNotSupported
	}

	return nil
}

// ParseNodeAddr parses a node address string in the format "ip:port".
//
// Example:
//
//	addr, err := ParseNodeAddr("192.168.1.1:9000")
func ParseNodeAddr(addrStr string) (*net.UDPAddr, error) {
	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return nil, err
	}

	if err := ValidateUDPAddr(addr); err != nil {
		return nil, err
	}

	return addr, nil
}

// NormalizeIP normalizes an IP address for consistent comparison.
//
// IPv4 addresses are returned in 4-byte form.
// IPv6 addresses are returned in 16-byte form.
func NormalizeIP(ip net.IP) net.IP {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip.To16()
}

// SameIP checks if two IP addresses are the same.
//
// This handles IPv4 vs IPv6 representation differences.
//
// Example:
//
//	if SameIP(node1.IP(), node2.IP()) {
//	    // Same node or same host
//	}
func SameIP(ip1, ip2 net.IP) bool {
	if ip1 == nil || ip2 == nil {
		return false
	}

	return NormalizeIP(ip1).Equal(NormalizeIP(ip2))
}
