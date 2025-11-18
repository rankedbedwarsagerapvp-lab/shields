package filter

import (
	"bytes"
	"net"
	"strings"
)

type Filter struct {
	enabled                 bool
	blockInvalidPackets     bool
	blockBotSignatures      bool
	blockMalformedHandshake bool
	maxPacketSize           int
}

func New(enabled, blockInvalid, blockBots, blockMalformed bool, maxPacketSize int) *Filter {
	return &Filter{
		enabled:                 enabled,
		blockInvalidPackets:     blockInvalid,
		blockBotSignatures:      blockBots,
		blockMalformedHandshake: blockMalformed,
		maxPacketSize:           maxPacketSize,
	}
}

// CheckPacketSize validates packet size
func (f *Filter) CheckPacketSize(size int) (bool, string) {
	if !f.enabled || !f.blockInvalidPackets {
		return true, ""
	}

	if size <= 0 {
		return false, "Invalid packet size: zero or negative"
	}

	if size > f.maxPacketSize {
		return false, "Packet size exceeds maximum allowed"
	}

	return true, ""
}

// CheckHandshake validates handshake packet
func (f *Filter) CheckHandshake(protocolVersion int32, hostname string, port uint16, nextState int32) (bool, string) {
	if !f.enabled || !f.blockMalformedHandshake {
		return true, ""
	}

	// Check protocol version (valid range: 0-9999)
	if protocolVersion < 0 || protocolVersion > 9999 {
		return false, "Invalid protocol version"
	}

	// Check hostname length
	if len(hostname) == 0 {
		return false, "Empty hostname"
	}

	if len(hostname) > 255 {
		return false, "Hostname too long"
	}

	// Check for null bytes in hostname (except Forge markers)
	cleanHostname := strings.Split(hostname, "\x00")[0]
	if len(cleanHostname) == 0 {
		return false, "Invalid hostname: starts with null byte"
	}

	// Check port (should be 0-65535, already validated by uint16)
	// But 0 is suspicious
	if port == 0 {
		return false, "Invalid port: 0"
	}

	// Check next state (1 = status, 2 = login)
	if nextState != 1 && nextState != 2 {
		return false, "Invalid next state"
	}

	return true, ""
}

// CheckBotSignature checks for known bot signatures
func (f *Filter) CheckBotSignature(hostname string, ip net.IP) (bool, string) {
	if !f.enabled || !f.blockBotSignatures {
		return true, ""
	}

	hostname = strings.ToLower(hostname)

	// Known bot signatures in hostname
	botSignatures := []string{
		"bot",
		"scanner",
		"exploit",
		"vulnerability",
		"test",
		"probe",
		"masscan",
		"shodan",
		"censys",
		"zgrab",
		"nmap",
	}

	for _, sig := range botSignatures {
		if strings.Contains(hostname, sig) {
			return false, "Bot signature detected in hostname"
		}
	}

	// Check for suspicious IP patterns
	if f.isSuspiciousIP(ip) {
		return false, "Suspicious IP detected"
	}

	// Check for very short hostnames (often bots)
	cleanHostname := strings.Split(hostname, "\x00")[0]
	if len(cleanHostname) < 3 && !isValidShortHostname(cleanHostname) {
		return false, "Suspicious short hostname"
	}

	// Check for hostnames with only numbers and dots (IP-like but malformed)
	if isMalformedIPLike(cleanHostname) {
		return false, "Malformed IP-like hostname"
	}

	return true, ""
}

// isSuspiciousIP checks if IP is from known bad ranges
func (f *Filter) isSuspiciousIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	// Add known bad IP ranges here if needed
	// For now, just check for obviously invalid IPs

	return false
}

// isValidShortHostname checks if short hostname is valid
func isValidShortHostname(hostname string) bool {
	// Allow localhost, IP addresses, etc.
	validShort := []string{"localhost", "127.0.0.1", "::1"}
	for _, valid := range validShort {
		if hostname == valid {
			return true
		}
	}

	// Check if it's a valid IP
	if net.ParseIP(hostname) != nil {
		return true
	}

	return false
}

// isMalformedIPLike checks if hostname looks like IP but is malformed
func isMalformedIPLike(hostname string) bool {
	// If it looks like IP (contains dots and only numbers/dots)
	if strings.Contains(hostname, ".") {
		hasOnlyNumsAndDots := true
		for _, c := range hostname {
			if c != '.' && (c < '0' || c > '9') {
				hasOnlyNumsAndDots = false
				break
			}
		}

		if hasOnlyNumsAndDots {
			// Try to parse as IP
			if net.ParseIP(hostname) == nil {
				return true // Looks like IP but isn't valid
			}
		}
	}

	return false
}

// CheckForNullBytes checks for suspicious null bytes
func (f *Filter) CheckForNullBytes(data []byte) (bool, string) {
	if !f.enabled || !f.blockInvalidPackets {
		return true, ""
	}

	// Check for excessive null bytes (potential attack)
	nullCount := bytes.Count(data, []byte{0x00})
	if nullCount > len(data)/2 {
		return false, "Excessive null bytes detected"
	}

	return true, ""
}
