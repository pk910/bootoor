package node

import (
	"net"
	"testing"
)

func TestIsLANAddress(t *testing.T) {
	tests := []struct {
		ip    string
		isLAN bool
	}{
		// RFC1918 private addresses
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},

		// Loopback
		{"127.0.0.1", true},
		{"::1", true},

		// Link-local
		{"169.254.1.1", true},
		{"fe80::1", true},

		// Public addresses
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2001:db8::1", false},

		// IPv6 ULA
		{"fc00::1", true},
		{"fd00::1", true},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Errorf("Failed to parse IP: %s", tt.ip)
			continue
		}

		result := IsLANAddress(ip)
		if result != tt.isLAN {
			t.Errorf("IsLANAddress(%s) = %v, want %v", tt.ip, result, tt.isLAN)
		}
	}
}

func TestIsWANAddress(t *testing.T) {
	tests := []struct {
		ip    string
		isWAN bool
	}{
		{"192.168.1.1", false},
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"10.0.0.1", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Errorf("Failed to parse IP: %s", tt.ip)
			continue
		}

		result := IsWANAddress(ip)
		if result != tt.isWAN {
			t.Errorf("IsWANAddress(%s) = %v, want %v", tt.ip, result, tt.isWAN)
		}
	}
}

func TestIsRoutableAddress(t *testing.T) {
	tests := []struct {
		ip       string
		routable bool
	}{
		// Routable public addresses
		{"8.8.8.8", true},
		{"1.1.1.1", true},

		// Non-routable addresses
		{"192.168.1.1", false}, // Private
		{"127.0.0.1", false},   // Loopback
		{"0.0.0.0", false},     // Unspecified
		{"224.0.0.1", false},   // Multicast
		{"::1", false},         // IPv6 loopback
		{"::", false},          // IPv6 unspecified
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Errorf("Failed to parse IP: %s", tt.ip)
			continue
		}

		result := IsRoutableAddress(ip)
		if result != tt.routable {
			t.Errorf("IsRoutableAddress(%s) = %v, want %v", tt.ip, result, tt.routable)
		}
	}
}

func TestIsSameNetwork(t *testing.T) {
	tests := []struct {
		ip1  string
		ip2  string
		same bool
	}{
		// Both LAN
		{"192.168.1.1", "192.168.1.2", true},
		{"10.0.0.1", "172.16.0.1", true},

		// Both WAN
		{"8.8.8.8", "1.1.1.1", true},

		// Mixed LAN/WAN
		{"192.168.1.1", "8.8.8.8", false},
		{"10.0.0.1", "1.1.1.1", false},
	}

	for _, tt := range tests {
		ip1 := net.ParseIP(tt.ip1)
		ip2 := net.ParseIP(tt.ip2)

		result := IsSameNetwork(ip1, ip2)
		if result != tt.same {
			t.Errorf("IsSameNetwork(%s, %s) = %v, want %v",
				tt.ip1, tt.ip2, result, tt.same)
		}
	}
}

func TestGetIPVersion(t *testing.T) {
	tests := []struct {
		ip      string
		version int
	}{
		{"192.168.1.1", 4},
		{"8.8.8.8", 4},
		{"::1", 6},
		{"2001:db8::1", 6},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Errorf("Failed to parse IP: %s", tt.ip)
			continue
		}

		result := GetIPVersion(ip)
		if result != tt.version {
			t.Errorf("GetIPVersion(%s) = %d, want %d", tt.ip, result, tt.version)
		}
	}

	// Test nil IP
	if GetIPVersion(nil) != 0 {
		t.Error("GetIPVersion(nil) should return 0")
	}
}

func TestValidateUDPAddr(t *testing.T) {
	// Valid address
	addr := &net.UDPAddr{
		IP:   net.IPv4(192, 168, 1, 1),
		Port: 9000,
	}
	if err := ValidateUDPAddr(addr); err != nil {
		t.Errorf("Valid address failed validation: %v", err)
	}

	// Nil address
	if err := ValidateUDPAddr(nil); err != ErrInvalidAddress {
		t.Error("Nil address should return ErrInvalidAddress")
	}

	// Zero port
	addr = &net.UDPAddr{
		IP:   net.IPv4(192, 168, 1, 1),
		Port: 0,
	}
	if err := ValidateUDPAddr(addr); err != ErrInvalidPort {
		t.Error("Zero port should return ErrInvalidPort")
	}

	// Nil IP
	addr = &net.UDPAddr{
		IP:   nil,
		Port: 9000,
	}
	if err := ValidateUDPAddr(addr); err != ErrInvalidAddress {
		t.Error("Nil IP should return ErrInvalidAddress")
	}

	// Multicast address
	addr = &net.UDPAddr{
		IP:   net.IPv4(224, 0, 0, 1),
		Port: 9000,
	}
	if err := ValidateUDPAddr(addr); err != ErrMulticastNotSupported {
		t.Error("Multicast address should return ErrMulticastNotSupported")
	}
}

func TestParseNodeAddr(t *testing.T) {
	// Valid address
	addr, err := ParseNodeAddr("192.168.1.1:9000")
	if err != nil {
		t.Errorf("Failed to parse valid address: %v", err)
	}
	if addr.Port != 9000 {
		t.Errorf("Port = %d, want 9000", addr.Port)
	}

	// Invalid format
	_, err = ParseNodeAddr("invalid")
	if err == nil {
		t.Error("Should fail to parse invalid address")
	}

	// Zero port
	_, err = ParseNodeAddr("192.168.1.1:0")
	if err != ErrInvalidPort {
		t.Error("Should return ErrInvalidPort for zero port")
	}
}

func TestNormalizeIP(t *testing.T) {
	// IPv4 should be normalized to 4 bytes
	ip4 := net.ParseIP("192.168.1.1")
	normalized := NormalizeIP(ip4)
	if len(normalized) != 4 {
		t.Errorf("Normalized IPv4 length = %d, want 4", len(normalized))
	}

	// IPv6 should be normalized to 16 bytes
	ip6 := net.ParseIP("2001:db8::1")
	normalized = NormalizeIP(ip6)
	if len(normalized) != 16 {
		t.Errorf("Normalized IPv6 length = %d, want 16", len(normalized))
	}
}

func TestSameIP(t *testing.T) {
	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.1")
	ip3 := net.ParseIP("192.168.1.2")

	// Same IPs
	if !SameIP(ip1, ip2) {
		t.Error("SameIP should return true for identical IPs")
	}

	// Different IPs
	if SameIP(ip1, ip3) {
		t.Error("SameIP should return false for different IPs")
	}

	// Nil IPs
	if SameIP(nil, ip1) {
		t.Error("SameIP should return false for nil IP")
	}

	if SameIP(ip1, nil) {
		t.Error("SameIP should return false for nil IP")
	}
}
