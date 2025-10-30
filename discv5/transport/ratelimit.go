package transport

import (
	"net"
	"sync"
	"time"
)

// RateLimiter implements per-IP rate limiting using a token bucket algorithm.
//
// Each IP address gets its own bucket with a maximum number of tokens.
// Tokens are refilled at a constant rate. When a packet arrives, a token
// is consumed. If no tokens are available, the packet is rejected.
type RateLimiter struct {
	// rate is the number of packets per second allowed per IP
	rate int

	// buckets tracks token buckets for each IP
	buckets map[string]*bucket

	// mu protects buckets map
	mu sync.RWMutex

	// cleanupTicker periodically removes old buckets
	cleanupTicker *time.Ticker

	// done signals cleanup goroutine to stop
	done chan struct{}
}

// bucket represents a token bucket for rate limiting.
type bucket struct {
	// tokens is the current number of available tokens
	tokens float64

	// lastRefill is the last time tokens were refilled
	lastRefill time.Time

	// mu protects tokens and lastRefill
	mu sync.Mutex
}

// NewRateLimiter creates a new per-IP rate limiter.
//
// rate specifies the maximum number of packets per second per IP address.
//
// Example:
//
//	// Allow 100 packets per second per IP
//	limiter := NewRateLimiter(100)
//	defer limiter.Stop()
func NewRateLimiter(rate int) *RateLimiter {
	rl := &RateLimiter{
		rate:          rate,
		buckets:       make(map[string]*bucket),
		cleanupTicker: time.NewTicker(5 * time.Minute),
		done:          make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// Allow checks if a packet from the given IP should be allowed.
//
// Returns true if the packet should be processed, false if it should be dropped.
//
// This method is thread-safe.
func (rl *RateLimiter) Allow(ip net.IP) bool {
	if ip == nil {
		return false
	}

	key := ip.String()

	// Get or create bucket for this IP
	rl.mu.RLock()
	b, exists := rl.buckets[key]
	rl.mu.RUnlock()

	if !exists {
		// Create new bucket
		b = &bucket{
			tokens:     float64(rl.rate),
			lastRefill: time.Now(),
		}

		rl.mu.Lock()
		rl.buckets[key] = b
		rl.mu.Unlock()
	}

	return b.consume(rl.rate)
}

// consume attempts to consume one token from the bucket.
//
// Returns true if a token was available, false otherwise.
func (b *bucket) consume(rate int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()

	// Refill tokens based on elapsed time
	tokensToAdd := elapsed * float64(rate)
	b.tokens += tokensToAdd
	b.lastRefill = now

	// Cap at rate (burst allowance)
	if b.tokens > float64(rate) {
		b.tokens = float64(rate)
	}

	// Try to consume one token
	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}

	return false
}

// cleanup periodically removes old bucket entries to prevent memory leaks.
func (rl *RateLimiter) cleanup() {
	for {
		select {
		case <-rl.cleanupTicker.C:
			rl.doCleanup()
		case <-rl.done:
			return
		}
	}
}

// doCleanup removes buckets that haven't been accessed recently.
func (rl *RateLimiter) doCleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	threshold := 10 * time.Minute

	for key, b := range rl.buckets {
		b.mu.Lock()
		age := now.Sub(b.lastRefill)
		b.mu.Unlock()

		if age > threshold {
			delete(rl.buckets, key)
		}
	}
}

// Stop stops the rate limiter and cleans up resources.
func (rl *RateLimiter) Stop() {
	close(rl.done)
	rl.cleanupTicker.Stop()
}

// Stats returns statistics about the rate limiter.
type RateLimiterStats struct {
	// ActiveIPs is the number of IPs currently being tracked
	ActiveIPs int

	// Rate is the configured rate limit per IP
	Rate int
}

// Stats returns current statistics about the rate limiter.
func (rl *RateLimiter) Stats() RateLimiterStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	return RateLimiterStats{
		ActiveIPs: len(rl.buckets),
		Rate:      rl.rate,
	}
}
