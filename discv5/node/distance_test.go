package node

import (
	"testing"
)

func TestDistance(t *testing.T) {
	// Test distance to self is zero
	id1 := ID{1, 2, 3, 4, 5}
	dist := Distance(id1, id1)

	for i := range dist {
		if dist[i] != 0 {
			t.Error("Distance to self should be zero")
			break
		}
	}

	// Test symmetric property: d(a,b) = d(b,a)
	id2 := ID{5, 4, 3, 2, 1}
	dist1 := Distance(id1, id2)
	dist2 := Distance(id2, id1)

	if dist1 != dist2 {
		t.Error("Distance should be symmetric")
	}

	// Test XOR calculation
	id3 := ID{0xFF, 0x00}
	id4 := ID{0x0F, 0xF0}
	dist = Distance(id3, id4)

	// 0xFF XOR 0x0F = 0xF0
	if dist[0] != 0xF0 {
		t.Errorf("Distance[0] = %x, want 0xF0", dist[0])
	}

	// 0x00 XOR 0xF0 = 0xF0
	if dist[1] != 0xF0 {
		t.Errorf("Distance[1] = %x, want 0xF0", dist[1])
	}
}

func TestLogDistance(t *testing.T) {
	// Distance to self should be -1
	id1 := ID{1, 2, 3}
	logDist := LogDistance(id1, id1)

	if logDist != -1 {
		t.Errorf("LogDistance to self = %d, want -1", logDist)
	}

	// Test specific distances
	tests := []struct {
		a        ID
		b        ID
		expected int
	}{
		// MSB in first byte, bit 7 (leftmost)
		{ID{0x00}, ID{0x80}, 7},
		// MSB in first byte, bit 0 (rightmost)
		{ID{0x00}, ID{0x01}, 0},
		// MSB in second byte, bit 7
		{ID{0x00, 0x00}, ID{0x00, 0x80}, 15},
		// MSB in second byte, bit 0
		{ID{0x00, 0x00}, ID{0x00, 0x01}, 8},
	}

	for _, tt := range tests {
		result := LogDistance(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("LogDistance(%v, %v) = %d, want %d",
				tt.a[:2], tt.b[:2], result, tt.expected)
		}
	}
}

func TestCompare(t *testing.T) {
	target := ID{0x80}
	a := ID{0x81} // Distance 0x01
	b := ID{0x82} // Distance 0x02
	c := ID{0x81} // Distance 0x01 (same as a)

	// a is closer than b
	if Compare(target, a, b) != -1 {
		t.Error("Compare should return -1 when a is closer")
	}

	// b is farther than a
	if Compare(target, b, a) != 1 {
		t.Error("Compare should return 1 when b is farther")
	}

	// a and c are equidistant
	if Compare(target, a, c) != 0 {
		t.Error("Compare should return 0 when distances are equal")
	}
}

func TestCloserTo(t *testing.T) {
	target := ID{0x80}
	closer := ID{0x81}  // Distance 0x01
	farther := ID{0x90} // Distance 0x10

	if !CloserTo(target, closer, farther) {
		t.Error("CloserTo should return true when first is closer")
	}

	if CloserTo(target, farther, closer) {
		t.Error("CloserTo should return false when first is farther")
	}
}

func TestFindClosest(t *testing.T) {
	target := ID{0x80}

	nodes := []ID{
		{0x81}, // Distance 0x01
		{0x90}, // Distance 0x10
		{0x82}, // Distance 0x02
		{0xA0}, // Distance 0x20
		{0x83}, // Distance 0x03
	}

	// Find 3 closest
	closest := FindClosest(target, nodes, 3)

	if len(closest) != 3 {
		t.Errorf("FindClosest returned %d nodes, want 3", len(closest))
	}

	// Verify they're sorted by distance
	if closest[0] != (ID{0x81}) {
		t.Error("Closest[0] should be 0x81")
	}
	if closest[1] != (ID{0x82}) {
		t.Error("Closest[1] should be 0x82")
	}
	if closest[2] != (ID{0x83}) {
		t.Error("Closest[2] should be 0x83")
	}
}

func TestBucketIndex(t *testing.T) {
	local := ID{0x00}
	remote := ID{0x80}

	// MSB is at position 7 (first byte, bit 7)
	bucket := BucketIndex(local, remote)

	if bucket != 7 {
		t.Errorf("BucketIndex = %d, want 7", bucket)
	}

	// Same node should return -1
	bucket = BucketIndex(local, local)
	if bucket != -1 {
		t.Errorf("BucketIndex for same node = %d, want -1", bucket)
	}
}

func TestRandomNodeID(t *testing.T) {
	base := ID{0x00}

	// Generate ID at distance 7 (MSB should be at position 7)
	random := RandomNodeID(base, 7)

	// Check the logarithmic distance
	bucket := BucketIndex(base, random)
	if bucket != 7 {
		t.Errorf("Generated ID bucket = %d, want 7", bucket)
	}

	// Verify the distance has MSB at bit 7
	dist := Distance(base, random)
	if dist[0]&0x80 == 0 {
		t.Errorf("Distance MSB not at position 7: distance = %x", dist[0])
	}

	// Generate another ID at the same distance
	random2 := RandomNodeID(base, 7)
	bucket2 := BucketIndex(base, random2)
	if bucket2 != 7 {
		t.Errorf("Second generated ID bucket = %d, want 7", bucket2)
	}

	// Test different distance
	random3 := RandomNodeID(base, 15)
	bucket3 := BucketIndex(base, random3)
	if bucket3 != 15 {
		t.Errorf("Generated ID at distance 15 bucket = %d, want 15", bucket3)
	}
}

// BenchmarkDistance benchmarks the distance calculation
func BenchmarkDistance(b *testing.B) {
	id1 := ID{1, 2, 3, 4, 5, 6, 7, 8}
	id2 := ID{8, 7, 6, 5, 4, 3, 2, 1}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Distance(id1, id2)
	}
}

// BenchmarkLogDistance benchmarks the log distance calculation
func BenchmarkLogDistance(b *testing.B) {
	id1 := ID{1, 2, 3, 4, 5, 6, 7, 8}
	id2 := ID{8, 7, 6, 5, 4, 3, 2, 1}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		LogDistance(id1, id2)
	}
}
