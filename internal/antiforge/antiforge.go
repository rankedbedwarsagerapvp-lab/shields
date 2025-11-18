package antiforge

import (
	"net"
	"strings"
)

type AntiForge struct {
	enabled        bool
	strictMode     bool
	checkHostname  bool
	allowedDomains []string
}

func New(enabled, strictMode, checkHostname bool, allowedDomains []string) *AntiForge {
	return &AntiForge{
		enabled:        enabled,
		strictMode:     strictMode,
		checkHostname:  checkHostname,
		allowedDomains: allowedDomains,
	}
}

// ValidateConnection validates connection against IP spoofing
func (af *AntiForge) ValidateConnection(remoteIP net.IP, proxyIP net.IP, hostname string) bool {
	if !af.enabled {
		return true
	}

	// Check if proxy IP and remote IP are the same (direct connection, not proxied)
	if proxyIP == nil {
		// Direct connection without PROXY protocol is suspicious in strict mode
		if af.strictMode {
			return false
		}
		return true
	}

	// In strict mode, ensure the IPs are different (proxied connection)
	if af.strictMode && remoteIP.Equal(proxyIP) {
		return false
	}

	// Validate hostname if enabled
	if af.checkHostname && hostname != "" {
		if !af.isHostnameAllowed(hostname) {
			return false
		}
	}

	// Check for obviously spoofed IPs
	if af.isSpoofedIP(remoteIP) {
		return false
	}

	return true
}

// isHostnameAllowed checks if hostname matches allowed domains
func (af *AntiForge) isHostnameAllowed(hostname string) bool {
	if len(af.allowedDomains) == 0 {
		return true
	}

	hostname = strings.ToLower(hostname)

	for _, domain := range af.allowedDomains {
		domain = strings.ToLower(domain)

		// Exact match
		if hostname == domain {
			return true
		}

		// Subdomain match
		if strings.HasSuffix(hostname, "."+domain) {
			return true
		}

		// IP address match (if domain is an IP)
		if net.ParseIP(hostname) != nil && hostname == domain {
			return true
		}
	}

	return false
}

// isSpoofedIP checks for obviously spoofed IP addresses
func (af *AntiForge) isSpoofedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}

	// Check for unspecified IP (0.0.0.0 or ::)
	if ip.IsUnspecified() {
		return true
	}

	// Private IPs from public internet are suspicious
	// (This check might be too strict depending on your setup)
	// Uncomment if needed:
	// if af.strictMode && (ip.IsPrivate() || ip.IsLoopback()) {
	// 	return true
	// }

	return false
}

// CheckForgeClient detects Forge/FML mod loader signatures
func (af *AntiForge) CheckForgeClient(hostname string) bool {
	// Forge clients append \x00FML\x00 or \x00FML2\x00 to hostname
	return strings.Contains(hostname, "\x00FML\x00") ||
		strings.Contains(hostname, "\x00FML2\x00") ||
		strings.Contains(hostname, "\x00FML3\x00")
}

// StripForgeMarker removes Forge markers from hostname
func StripForgeMarker(hostname string) string {
	// Remove FML markers
	hostname = strings.Split(hostname, "\x00")[0]
	return hostname
}
