package haproxymanager

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"text/template"
	"time"

	"shield/internal/logger"
	"shield/internal/router"
)

const haproxyConfigTemplate = `# HAProxy Configuration for Shield - Auto-generated
# Generated at: {{ .GeneratedAt }}

global
    maxconn 50000
    log /dev/log local0
    log /dev/log local1 notice
    stats socket /var/run/haproxy.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    daemon

defaults
    log     global
    mode    tcp
    option  tcplog
    option  dontlognull
    timeout connect 5s
    timeout client  1m
    timeout server  1m
    maxconn 50000

# Statistics
listen stats
    bind *:8404
    mode http
    stats enable
    stats uri /stats
    stats refresh 10s
    stats admin if TRUE

{{ range .Routes }}
# Frontend for {{ .Domain }} (Shield ID: {{ .ShieldID }})
frontend frontend_{{ .SafeDomain }}
    bind *:{{ .ProxyPort }}
    mode tcp
    option tcplog
    
    # Connection tracking and rate limiting
    stick-table type ip size 1m expire 30s store conn_rate(10s)
    tcp-request connection track-sc0 src
    tcp-request connection reject if { src_conn_rate gt 20 }
    
    # Logging
    log-format "%ci:%cp [%t] %ft %b/%s %Tw/%Tc/%Tt %B %ts"
    
    default_backend backend_{{ .SafeDomain }}

# Backend for {{ .Domain }}
backend backend_{{ .SafeDomain }}
    mode tcp
    balance roundrobin
    option tcp-check
    
    # PROXY protocol v2 to pass real client IP
    server shield_{{ .SafeDomain }} {{ .BackendIP }}:{{ .BackendPort }} send-proxy-v2 check inter 2s fall 3 rise 2

{{ end }}
`

type HAProxyManager struct {
	mu             sync.RWMutex
	configPath     string
	haproxyBin     string
	socketPath     string
	router         *router.Router
	autoReload     bool
	reloadInterval time.Duration
}

type HAProxyConfig struct {
	GeneratedAt string
	Routes      []RouteConfig
}

type RouteConfig struct {
	ShieldID    string
	Domain      string
	SafeDomain  string // Domain with dots replaced for HAProxy naming
	BackendIP   string
	BackendPort int
	ProxyPort   int
}

// New creates a new HAProxy manager
func New(configPath, haproxyBin, socketPath string, router *router.Router, autoReload bool, reloadInterval time.Duration) *HAProxyManager {
	return &HAProxyManager{
		configPath:     configPath,
		haproxyBin:     haproxyBin,
		socketPath:     socketPath,
		router:         router,
		autoReload:     autoReload,
		reloadInterval: reloadInterval,
	}
}

// Start starts the HAProxy manager
func (hm *HAProxyManager) Start() error {
	// Generate initial config
	if err := hm.GenerateConfig(); err != nil {
		return fmt.Errorf("failed to generate initial config: %w", err)
	}

	// Start auto-reload if enabled
	if hm.autoReload {
		go hm.autoReloadLoop()
	}

	return nil
}

// GenerateConfig generates HAProxy configuration from routes
func (hm *HAProxyManager) GenerateConfig() error {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	routes := hm.router.GetAllRoutes()

	config := HAProxyConfig{
		GeneratedAt: time.Now().Format(time.RFC3339),
		Routes:      make([]RouteConfig, 0, len(routes)),
	}

	for _, route := range routes {
		if route.Status != "active" {
			continue
		}

		safeDomain := strings.ReplaceAll(route.Domain, ".", "_")
		safeDomain = strings.ReplaceAll(safeDomain, "-", "_")

		config.Routes = append(config.Routes, RouteConfig{
			ShieldID:    route.ShieldID,
			Domain:      route.Domain,
			SafeDomain:  safeDomain,
			BackendIP:   route.BackendIP,
			BackendPort: route.BackendPort,
			ProxyPort:   route.ProxyPort,
		})
	}

	// Parse template
	tmpl, err := template.New("haproxy").Parse(haproxyConfigTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, config); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	// Write config file
	if err := os.WriteFile(hm.configPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	logger.Log.WithFields(map[string]interface{}{
		"config_path": hm.configPath,
		"routes":      len(config.Routes),
	}).Info("HAProxy configuration generated")

	return nil
}

// Reload reloads HAProxy configuration
func (hm *HAProxyManager) Reload() error {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	// Validate config first
	if err := hm.validateConfig(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	// Reload HAProxy
	cmd := exec.Command("systemctl", "reload", "haproxy")
	if err := cmd.Run(); err != nil {
		// Try alternative reload method
		cmd = exec.Command(hm.haproxyBin, "-f", hm.configPath, "-sf", "$(cat /var/run/haproxy.pid)")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to reload haproxy: %w", err)
		}
	}

	logger.Log.Info("HAProxy reloaded successfully")
	return nil
}

// validateConfig validates HAProxy configuration
func (hm *HAProxyManager) validateConfig() error {
	cmd := exec.Command(hm.haproxyBin, "-c", "-f", hm.configPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("validation failed: %s", string(output))
	}
	return nil
}

// AddRoute adds a route and regenerates config
func (hm *HAProxyManager) AddRoute(route *router.BackendRoute) error {
	if err := hm.GenerateConfig(); err != nil {
		return err
	}

	if hm.autoReload {
		return hm.Reload()
	}

	return nil
}

// RemoveRoute removes a route and regenerates config
func (hm *HAProxyManager) RemoveRoute(route *router.BackendRoute) error {
	if err := hm.GenerateConfig(); err != nil {
		return err
	}

	if hm.autoReload {
		return hm.Reload()
	}

	return nil
}

// UpdateRoute updates a route and regenerates config
func (hm *HAProxyManager) UpdateRoute(route *router.BackendRoute) error {
	if err := hm.GenerateConfig(); err != nil {
		return err
	}

	if hm.autoReload {
		return hm.Reload()
	}

	return nil
}

// autoReloadLoop automatically reloads HAProxy when config changes
func (hm *HAProxyManager) autoReloadLoop() {
	ticker := time.NewTicker(hm.reloadInterval)
	defer ticker.Stop()

	lastModTime := time.Time{}

	for range ticker.C {
		info, err := os.Stat(hm.configPath)
		if err != nil {
			continue
		}

		if info.ModTime().After(lastModTime) {
			lastModTime = info.ModTime()
			// Config changed, validate and reload
			if err := hm.Reload(); err != nil {
				logger.Log.WithError(err).Error("Failed to auto-reload HAProxy")
			}
		}
	}
}

// GetStats returns HAProxy statistics via socket
func (hm *HAProxyManager) GetStats() (map[string]interface{}, error) {
	// This would require parsing HAProxy stats socket
	// For now, return empty stats
	return map[string]interface{}{
		"status": "running",
	}, nil
}
