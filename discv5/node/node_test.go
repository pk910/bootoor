package node

import (
	"net"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethpandaops/bootnodoor/enr"
)

func TestNewNode(t *testing.T) {
	privKey, _ := crypto.GenerateKey()

	record, err := enr.CreateSignedRecord(
		privKey,
		"ip", net.IPv4(192, 168, 1, 1),
		"udp", uint16(9000),
		"tcp", uint16(9000),
	)
	if err != nil {
		t.Fatalf("Failed to create record: %v", err)
	}

	node, err := New(record)
	if err != nil {
		t.Fatalf("Failed to create node: %v", err)
	}

	// Check node properties
	if node.UDPPort() != 9000 {
		t.Errorf("UDP port = %d, want 9000", node.UDPPort())
	}

	if node.TCPPort() != 9000 {
		t.Errorf("TCP port = %d, want 9000", node.TCPPort())
	}

	if !node.IP().Equal(net.IPv4(192, 168, 1, 1)) {
		t.Errorf("IP = %v, want 192.168.1.1", node.IP())
	}

	// Check derived node ID matches
	expectedID := PubkeyToID(&privKey.PublicKey)
	if node.ID() != expectedID {
		t.Error("Node ID doesn't match derived ID from public key")
	}
}

func TestNodeStatistics(t *testing.T) {
	privKey, _ := crypto.GenerateKey()
	record, _ := enr.CreateSignedRecord(
		privKey,
		"ip", net.IPv4(192, 168, 1, 1),
		"udp", uint16(9000),
	)
	node, _ := New(record)

	// Initial state
	if node.FailureCount() != 0 {
		t.Error("Initial failure count should be 0")
	}

	if node.SuccessCount() != 0 {
		t.Error("Initial success count should be 0")
	}

	// Increment failures
	node.IncrementFailureCount()
	node.IncrementFailureCount()

	if node.FailureCount() != 2 {
		t.Errorf("Failure count = %d, want 2", node.FailureCount())
	}

	// Reset on success
	node.ResetFailureCount()

	if node.FailureCount() != 0 {
		t.Error("Failure count should be 0 after reset")
	}

	if node.SuccessCount() != 1 {
		t.Errorf("Success count = %d, want 1", node.SuccessCount())
	}
}

func TestNodeRTT(t *testing.T) {
	privKey, _ := crypto.GenerateKey()
	record, _ := enr.CreateSignedRecord(
		privKey,
		"ip", net.IPv4(192, 168, 1, 1),
		"udp", uint16(9000),
	)
	node, _ := New(record)

	// First RTT measurement
	node.UpdateRTT(100 * time.Millisecond)
	if node.AvgRTT() != 100*time.Millisecond {
		t.Errorf("First RTT = %v, want 100ms", node.AvgRTT())
	}

	// Second RTT measurement (should be averaged)
	node.UpdateRTT(200 * time.Millisecond)

	// Average should be weighted toward old value
	// (7/8 * 100ms) + (1/8 * 200ms) = 87.5ms + 25ms = 112.5ms
	expected := (100*time.Millisecond*7/8 + 200*time.Millisecond/8)
	if node.AvgRTT() != expected {
		t.Errorf("Avg RTT = %v, want %v", node.AvgRTT(), expected)
	}
}

func TestNodeAliveness(t *testing.T) {
	privKey, _ := crypto.GenerateKey()
	record, _ := enr.CreateSignedRecord(
		privKey,
		"ip", net.IPv4(192, 168, 1, 1),
		"udp", uint16(9000),
	)
	node, _ := New(record)

	// Never seen - not alive
	if node.IsAlive(24*time.Hour, 3) {
		t.Error("Node should not be alive if never seen")
	}

	// Mark as seen
	node.SetLastSeen(time.Now())

	// Should be alive
	if !node.IsAlive(24*time.Hour, 3) {
		t.Error("Node should be alive after being seen")
	}

	// Too many failures - not alive
	node.IncrementFailureCount()
	node.IncrementFailureCount()
	node.IncrementFailureCount()

	if node.IsAlive(24*time.Hour, 3) {
		t.Error("Node should not be alive with too many failures")
	}

	// Reset failures
	node.ResetFailureCount()

	// Should be alive again
	if !node.IsAlive(24*time.Hour, 3) {
		t.Error("Node should be alive after failure reset")
	}
}

func TestNodeNeedsPing(t *testing.T) {
	privKey, _ := crypto.GenerateKey()
	record, _ := enr.CreateSignedRecord(
		privKey,
		"ip", net.IPv4(192, 168, 1, 1),
		"udp", uint16(9000),
	)
	node, _ := New(record)

	// Never pinged - needs ping
	if !node.NeedsPing(30 * time.Second) {
		t.Error("Node should need ping if never pinged")
	}

	// Just pinged - doesn't need ping
	node.SetLastPing(time.Now())

	if node.NeedsPing(30 * time.Second) {
		t.Error("Node should not need ping right after being pinged")
	}

	// Ping too old - needs ping
	node.SetLastPing(time.Now().Add(-1 * time.Minute))

	if !node.NeedsPing(30 * time.Second) {
		t.Error("Node should need ping after interval expires")
	}
}

func TestNodeENRUpdate(t *testing.T) {
	privKey, _ := crypto.GenerateKey()

	record1, _ := enr.CreateSignedRecord(
		privKey,
		"ip", net.IPv4(192, 168, 1, 1),
		"udp", uint16(9000),
	)
	node, _ := New(record1)

	oldSeq := node.Record().Seq()

	// Create updated record with higher sequence
	record2, _ := enr.UpdateRecord(
		record1,
		privKey,
		"ip", net.IPv4(192, 168, 1, 2),
		"udp", uint16(9001),
	)

	// Update should succeed
	if !node.UpdateENR(record2) {
		t.Error("ENR update should succeed for higher sequence")
	}

	// Check updated values
	if node.Record().Seq() <= oldSeq {
		t.Error("ENR sequence should be higher after update")
	}

	if node.UDPPort() != 9001 {
		t.Errorf("UDP port = %d, want 9001 after update", node.UDPPort())
	}

	// Try to update with older record - should fail
	if node.UpdateENR(record1) {
		t.Error("ENR update should fail for older sequence")
	}
}

func TestNodeString(t *testing.T) {
	privKey, _ := crypto.GenerateKey()
	record, _ := enr.CreateSignedRecord(
		privKey,
		"ip", net.IPv4(192, 168, 1, 1),
		"udp", uint16(9000),
	)
	node, _ := New(record)

	str := node.String()
	if str == "" {
		t.Error("Node string representation should not be empty")
	}

	// String should contain key information
	// (exact format may vary, just checking it doesn't panic)
	t.Logf("Node string: %s", str)
}
