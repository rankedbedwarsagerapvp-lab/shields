package ratelimit

import (
	"net"
	"sync"
	"time"
)

type RateLimiter struct {
	mu                        sync.RWMutex
	enabled                   bool
	connectionsPerSecond      int
	totalConnectionsPerSecond int
	autoDisableThreshold      int
	autoDisableDuration       time.Duration
	emergencyModeDuration     time.Duration
	whitelist                 map[string]bool
	blacklist                 map[string]bool

	// Tracking
	ipConnections    map[string]*ipCounter
	totalConnections int
	lastReset        time.Time

	// Emergency mode
	emergencyMode      bool
	emergencyModeStart time.Time

	// Auto-disable
	disabled      bool
	disabledUntil time.Time

	cleanupTicker *time.Ticker
	stopCleanup   chan bool
}

type ipCounter struct {
	count      int
	lastSeen   time.Time
	blocked    bool
	blockUntil time.Time
}

func New(enabled bool, connPerSec, totalConnPerSec, autoDisableThreshold int,
	emergencyDuration, autoDisableDuration time.Duration,
	whitelistIPs, blacklistIPs []string) *RateLimiter {

	whitelist := make(map[string]bool)
	for _, ip := range whitelistIPs {
		whitelist[ip] = true
	}

	blacklist := make(map[string]bool)
	for _, ip := range blacklistIPs {
		blacklist[ip] = true
	}

	rl := &RateLimiter{
		enabled:                   enabled,
		connectionsPerSecond:      connPerSec,
		totalConnectionsPerSecond: totalConnPerSec,
		autoDisableThreshold:      autoDisableThreshold,
		autoDisableDuration:       autoDisableDuration,
		emergencyModeDuration:     emergencyDuration,
		whitelist:                 whitelist,
		blacklist:                 blacklist,
		ipConnections:             make(map[string]*ipCounter),
		lastReset:                 time.Now(),
		stopCleanup:               make(chan bool),
	}

	// Start cleanup goroutine
	rl.cleanupTicker = time.NewTicker(1 * time.Second)
	go rl.cleanup()

	return rl
}

// Allow checks if connection from IP is allowed
func (rl *RateLimiter) Allow(ip net.IP) (bool, string) {
	if !rl.enabled {
		return true, ""
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check if auto-disabled
	if rl.disabled {
		if time.Now().Before(rl.disabledUntil) {
			return true, "" // Allow all during auto-disable period
		}
		rl.disabled = false
	}

	ipStr := ip.String()

	// Check blacklist
	if rl.blacklist[ipStr] {
		return false, "IP is blacklisted"
	}

	// Check whitelist
	if rl.whitelist[ipStr] {
		return true, ""
	}

	// Reset counters every second
	now := time.Now()
	if now.Sub(rl.lastReset) >= 1*time.Second {
		rl.totalConnections = 0
		rl.lastReset = now

		// Check if emergency mode should end
		if rl.emergencyMode && now.Sub(rl.emergencyModeStart) >= rl.emergencyModeDuration {
			rl.emergencyMode = false
		}
	}

	// Check total connections for auto-disable
	if rl.autoDisableThreshold > 0 && rl.totalConnections >= rl.autoDisableThreshold {
		rl.disabled = true
		rl.disabledUntil = now.Add(rl.autoDisableDuration)
		return true, "" // Allow connection but system is now disabled
	}

	// Check total connections for emergency mode
	if rl.totalConnectionsPerSecond > 0 && rl.totalConnections >= rl.totalConnectionsPerSecond {
		if !rl.emergencyMode {
			rl.emergencyMode = true
			rl.emergencyModeStart = now
		}
		return false, "Emergency mode: too many total connections"
	}

	// Check per-IP rate limit
	counter, exists := rl.ipConnections[ipStr]
	if !exists {
		counter = &ipCounter{
			count:    0,
			lastSeen: now,
		}
		rl.ipConnections[ipStr] = counter
	}

	// Check if IP is blocked
	if counter.blocked && now.Before(counter.blockUntil) {
		return false, "IP temporarily blocked"
	} else if counter.blocked {
		counter.blocked = false
	}

	// Reset counter if more than 1 second has passed
	if now.Sub(counter.lastSeen) >= 1*time.Second {
		counter.count = 0
		counter.lastSeen = now
	}

	// Check rate limit
	if counter.count >= rl.connectionsPerSecond {
		// Block IP for 60 seconds
		counter.blocked = true
		counter.blockUntil = now.Add(60 * time.Second)
		return false, "Rate limit exceeded"
	}

	// Increment counters
	counter.count++
	counter.lastSeen = now
	rl.totalConnections++

	return true, ""
}

// AddToBlacklist adds IP to blacklist
func (rl *RateLimiter) AddToBlacklist(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.blacklist[ip] = true
}

// RemoveFromBlacklist removes IP from blacklist
func (rl *RateLimiter) RemoveFromBlacklist(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.blacklist, ip)
}

// AddToWhitelist adds IP to whitelist
func (rl *RateLimiter) AddToWhitelist(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.whitelist[ip] = true
}

// GetStats returns current statistics
func (rl *RateLimiter) GetStats() map[string]interface{} {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	return map[string]interface{}{
		"enabled":           rl.enabled,
		"emergency_mode":    rl.emergencyMode,
		"disabled":          rl.disabled,
		"total_connections": rl.totalConnections,
		"tracked_ips":       len(rl.ipConnections),
		"blacklist_size":    len(rl.blacklist),
		"whitelist_size":    len(rl.whitelist),
	}
}

// cleanup removes old IP counters
func (rl *RateLimiter) cleanup() {
	for {
		select {
		case <-rl.cleanupTicker.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, counter := range rl.ipConnections {
				// Remove IPs not seen in last 5 minutes
				if now.Sub(counter.lastSeen) > 5*time.Minute {
					delete(rl.ipConnections, ip)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopCleanup:
			return
		}
	}
}

// Stop stops the rate limiter
func (rl *RateLimiter) Stop() {
	rl.cleanupTicker.Stop()
	close(rl.stopCleanup)
}
