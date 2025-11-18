package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"shield/internal/auth"
	"shield/internal/config"
	"shield/internal/database"
	"shield/internal/haproxymanager"
	"shield/internal/logger"
	"shield/internal/router"
)

type API struct {
	config          *config.Config
	configMutex     sync.RWMutex
	stats           *Stats
	onConfigChange  func(*config.Config)
	db              *database.Database
	auth            *auth.Auth
	projectStats    map[string]*ProjectStats // shieldID -> stats
	projectMutex    sync.RWMutex
	domainToProject map[string]string // domain -> shieldID
	router          *router.Router
	haproxyManager  *haproxymanager.HAProxyManager
}

type Stats struct {
	mu                 sync.RWMutex
	TotalConnections   int64            `json:"total_connections"`
	BlockedConnections int64            `json:"blocked_connections"`
	ActiveConnections  int64            `json:"active_connections"`
	EmergencyMode      bool             `json:"emergency_mode"`
	ProtectionDisabled bool             `json:"protection_disabled"`
	Uptime             time.Time        `json:"-"`
	ConnectionsPerMin  []int            `json:"connections_per_min"`
	BlockedPerMin      []int            `json:"blocked_per_min"`
	BlockReasons       map[string]int64 `json:"block_reasons"`
}

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type ProjectStats struct {
	BytesTransferred int64          `json:"bytes_transferred"`
	PacketsPerSecond float64        `json:"packets_per_second"`
	ConnectionsTotal int64          `json:"connections_total"`
	ActivePlayers    int            `json:"active_players"`
	TrafficHistory   []TrafficPoint `json:"traffic_history"`
}

type TrafficPoint struct {
	Timestamp int64   `json:"timestamp"`
	BPS       float64 `json:"bps"`
	PPS       float64 `json:"pps"`
	Players   int     `json:"players"`
}

func New(cfg *config.Config, db *database.Database, onConfigChange func(*config.Config)) *API {
	api := &API{
		config: cfg,
		stats: &Stats{
			Uptime:            time.Now(),
			BlockReasons:      make(map[string]int64),
			ConnectionsPerMin: make([]int, 60),
			BlockedPerMin:     make([]int, 60),
		},
		onConfigChange:  onConfigChange,
		db:              db,
		auth:            auth.New(db),
		projectStats:    make(map[string]*ProjectStats),
		domainToProject: make(map[string]string),
	}

	// Initialize router if enabled
	if cfg.Router.Enabled {
		// Convert config port ranges to router port ranges
		portRanges := make([]router.PortRange, len(cfg.Router.PortRanges))
		for i, pr := range cfg.Router.PortRanges {
			portRanges[i] = router.PortRange{
				Start: pr.Start,
				End:   pr.End,
			}
		}

		// Create router with callback
		api.router = router.NewRouter(portRanges, func(route *router.BackendRoute, action string) {
			// Callback when routes change
			if api.haproxyManager != nil {
				switch action {
				case "add":
					api.haproxyManager.AddRoute(route)
				case "remove":
					api.haproxyManager.RemoveRoute(route)
				case "update":
					api.haproxyManager.UpdateRoute(route)
				}
			}
		})

		// Create HAProxy manager
		reloadInterval := time.Duration(cfg.Router.ReloadInterval) * time.Second
		if reloadInterval == 0 {
			reloadInterval = 10 * time.Second
		}

		api.haproxyManager = haproxymanager.New(
			cfg.Router.HAProxyConfigPath,
			cfg.Router.HAProxyBinaryPath,
			cfg.Router.HAProxySocketPath,
			api.router,
			cfg.Router.AutoReload,
			reloadInterval,
		)

		// Start HAProxy manager
		if err := api.haproxyManager.Start(); err != nil {
			logger.Log.WithError(err).Error("Failed to start HAProxy manager")
		} else {
			logger.Log.Info("Dynamic routing system initialized")
		}
	}

	return api
}

func (a *API) Start(addr string) error {
	mux := http.NewServeMux()

	// Start stats updater goroutine
	go a.startStatsUpdater()

	// CORS middleware
	cors := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next(w, r)
		}
	}

	// Static files
	mux.HandleFunc("/", cors(a.handleIndex))

	// Auth endpoints
	mux.HandleFunc("/api/auth/register", cors(a.handleRegister))
	mux.HandleFunc("/api/auth/login", cors(a.handleLogin))
	mux.HandleFunc("/api/auth/logout", cors(a.handleLogout))
	mux.HandleFunc("/api/auth/me", cors(a.handleMe))

	// Project endpoints
	mux.HandleFunc("/api/projects", cors(a.handleProjects))
	mux.HandleFunc("/api/projects/create", cors(a.handleCreateProject))
	mux.HandleFunc("/api/projects/update-domain", cors(a.handleUpdateProjectDomain))
	mux.HandleFunc("/api/projects/validate-domain", cors(a.handleValidateDomainCNAME))
	mux.HandleFunc("/api/projects/stats", cors(a.handleProjectStats))

	// Backend endpoints
	mux.HandleFunc("/api/backends/add", cors(a.handleAddBackend))
	mux.HandleFunc("/api/backends/remove", cors(a.handleRemoveBackend))

	// Router endpoints
	mux.HandleFunc("/api/routes", cors(a.handleGetRoutes))
	mux.HandleFunc("/api/routes/port-info", cors(a.handleGetPortInfo))

	// API endpoints
	mux.HandleFunc("/api/stats", cors(a.handleStats))
	mux.HandleFunc("/api/config", cors(a.handleConfig))
	mux.HandleFunc("/api/config/update", cors(a.handleConfigUpdate))
	mux.HandleFunc("/api/domains/validate", cors(a.handleValidateDomain))
	mux.HandleFunc("/api/domains/add", cors(a.handleAddDomain))
	mux.HandleFunc("/api/domains/remove", cors(a.handleRemoveDomain))
	mux.HandleFunc("/api/whitelist/add", cors(a.handleAddWhitelist))
	mux.HandleFunc("/api/whitelist/remove", cors(a.handleRemoveWhitelist))
	mux.HandleFunc("/api/blacklist/add", cors(a.handleAddBlacklist))
	mux.HandleFunc("/api/blacklist/remove", cors(a.handleRemoveBlacklist))
	mux.HandleFunc("/api/motd/update", cors(a.handleUpdateMOTD))
	mux.HandleFunc("/api/ratelimit/update", cors(a.handleUpdateRateLimit))

	logger.Log.WithField("api_address", addr).Info("Starting API server")
	return http.ListenAndServe(addr, mux)
}

func (a *API) handleIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func (a *API) handleStats(w http.ResponseWriter, r *http.Request) {
	a.stats.mu.RLock()
	uptime := time.Since(a.stats.Uptime)
	stats := map[string]interface{}{
		"total_connections":   a.stats.TotalConnections,
		"blocked_connections": a.stats.BlockedConnections,
		"active_connections":  a.stats.ActiveConnections,
		"emergency_mode":      a.stats.EmergencyMode,
		"protection_disabled": a.stats.ProtectionDisabled,
		"uptime_seconds":      int(uptime.Seconds()),
		"connections_per_min": a.stats.ConnectionsPerMin,
		"blocked_per_min":     a.stats.BlockedPerMin,
		"block_reasons":       a.stats.BlockReasons,
	}
	a.stats.mu.RUnlock()

	a.sendJSON(w, Response{Success: true, Data: stats})
}

func (a *API) handleConfig(w http.ResponseWriter, r *http.Request) {
	a.configMutex.RLock()
	defer a.configMutex.RUnlock()

	a.sendJSON(w, Response{
		Success: true,
		Data: map[string]interface{}{
			"server":    a.config.Server,
			"haproxy":   a.config.HAProxy,
			"motd":      a.config.MOTD,
			"antiforge": a.config.AntiForge,
			"filter":    a.config.Filter,
			"ratelimit": a.config.RateLimit,
			"logging":   a.config.Logging,
		},
	})
}

func (a *API) handleConfigUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newConfig config.Config
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		a.sendError(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	a.configMutex.Lock()
	a.config = &newConfig
	a.configMutex.Unlock()

	if a.onConfigChange != nil {
		a.onConfigChange(&newConfig)
	}

	logger.Log.Info("Configuration updated via API")
	a.sendJSON(w, Response{Success: true, Message: "Configuration updated"})
}

func (a *API) handleValidateDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	valid, reason := a.validateDomain(req.Domain)
	a.sendJSON(w, Response{
		Success: valid,
		Message: reason,
		Data: map[string]interface{}{
			"domain": req.Domain,
			"valid":  valid,
		},
	})
}

func (a *API) handleAddDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	valid, reason := a.validateDomain(req.Domain)
	if !valid {
		a.sendError(w, reason, http.StatusBadRequest)
		return
	}

	a.configMutex.Lock()
	// Check if domain already exists
	for _, domain := range a.config.AntiForge.AllowedDomains {
		if domain == req.Domain {
			a.configMutex.Unlock()
			a.sendError(w, "Domain already exists", http.StatusBadRequest)
			return
		}
	}
	a.config.AntiForge.AllowedDomains = append(a.config.AntiForge.AllowedDomains, req.Domain)
	a.configMutex.Unlock()

	if a.onConfigChange != nil {
		a.onConfigChange(a.config)
	}

	logger.Log.WithField("domain", req.Domain).Info("Domain added")
	a.sendJSON(w, Response{Success: true, Message: "Domain added successfully"})
}

func (a *API) handleRemoveDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	a.configMutex.Lock()
	newDomains := []string{}
	found := false
	for _, domain := range a.config.AntiForge.AllowedDomains {
		if domain != req.Domain {
			newDomains = append(newDomains, domain)
		} else {
			found = true
		}
	}
	a.config.AntiForge.AllowedDomains = newDomains
	a.configMutex.Unlock()

	if !found {
		a.sendError(w, "Domain not found", http.StatusNotFound)
		return
	}

	if a.onConfigChange != nil {
		a.onConfigChange(a.config)
	}

	logger.Log.WithField("domain", req.Domain).Info("Domain removed")
	a.sendJSON(w, Response{Success: true, Message: "Domain removed successfully"})
}

func (a *API) handleAddWhitelist(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if net.ParseIP(req.IP) == nil {
		a.sendError(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	a.configMutex.Lock()
	a.config.RateLimit.Whitelist = append(a.config.RateLimit.Whitelist, req.IP)
	a.configMutex.Unlock()

	if a.onConfigChange != nil {
		a.onConfigChange(a.config)
	}

	logger.Log.WithField("ip", req.IP).Info("IP added to whitelist")
	a.sendJSON(w, Response{Success: true, Message: "IP added to whitelist"})
}

func (a *API) handleRemoveWhitelist(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	a.configMutex.Lock()
	newWhitelist := []string{}
	for _, ip := range a.config.RateLimit.Whitelist {
		if ip != req.IP {
			newWhitelist = append(newWhitelist, ip)
		}
	}
	a.config.RateLimit.Whitelist = newWhitelist
	a.configMutex.Unlock()

	if a.onConfigChange != nil {
		a.onConfigChange(a.config)
	}

	logger.Log.WithField("ip", req.IP).Info("IP removed from whitelist")
	a.sendJSON(w, Response{Success: true, Message: "IP removed from whitelist"})
}

func (a *API) handleAddBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if net.ParseIP(req.IP) == nil {
		a.sendError(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	a.configMutex.Lock()
	a.config.RateLimit.Blacklist = append(a.config.RateLimit.Blacklist, req.IP)
	a.configMutex.Unlock()

	if a.onConfigChange != nil {
		a.onConfigChange(a.config)
	}

	logger.Log.WithField("ip", req.IP).Info("IP added to blacklist")
	a.sendJSON(w, Response{Success: true, Message: "IP added to blacklist"})
}

func (a *API) handleRemoveBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	a.configMutex.Lock()
	newBlacklist := []string{}
	for _, ip := range a.config.RateLimit.Blacklist {
		if ip != req.IP {
			newBlacklist = append(newBlacklist, ip)
		}
	}
	a.config.RateLimit.Blacklist = newBlacklist
	a.configMutex.Unlock()

	if a.onConfigChange != nil {
		a.onConfigChange(a.config)
	}

	logger.Log.WithField("ip", req.IP).Info("IP removed from blacklist")
	a.sendJSON(w, Response{Success: true, Message: "IP removed from blacklist"})
}

func (a *API) handleUpdateMOTD(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Description string `json:"description"`
		VersionName string `json:"version_name"`
		MaxPlayers  int    `json:"max_players"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	a.configMutex.Lock()
	if req.Description != "" {
		a.config.MOTD.Description = req.Description
	}
	if req.VersionName != "" {
		a.config.MOTD.VersionName = req.VersionName
	}
	if req.MaxPlayers > 0 {
		a.config.MOTD.MaxPlayers = req.MaxPlayers
	}
	a.configMutex.Unlock()

	if a.onConfigChange != nil {
		a.onConfigChange(a.config)
	}

	logger.Log.Info("MOTD updated")
	a.sendJSON(w, Response{Success: true, Message: "MOTD updated successfully"})
}

func (a *API) handleUpdateRateLimit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ConnectionsPerSecond      int `json:"connections_per_second"`
		TotalConnectionsPerSecond int `json:"total_connections_per_second"`
		AutoDisableThreshold      int `json:"auto_disable_threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.sendError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	a.configMutex.Lock()
	if req.ConnectionsPerSecond > 0 {
		a.config.RateLimit.ConnectionsPerSecond = req.ConnectionsPerSecond
	}
	if req.TotalConnectionsPerSecond > 0 {
		a.config.RateLimit.TotalConnectionsPerSecond = req.TotalConnectionsPerSecond
	}
	if req.AutoDisableThreshold > 0 {
		a.config.RateLimit.AutoDisableThreshold = req.AutoDisableThreshold
	}
	a.configMutex.Unlock()

	if a.onConfigChange != nil {
		a.onConfigChange(a.config)
	}

	logger.Log.Info("Rate limit settings updated")
	a.sendJSON(w, Response{Success: true, Message: "Rate limit settings updated successfully"})
}

// Helper functions
func (a *API) validateDomain(domain string) (bool, string) {
	if domain == "" {
		return false, "Domain cannot be empty"
	}

	if len(domain) > 255 {
		return false, "Domain too long (max 255 characters)"
	}

	// Check if it's an IP address
	if net.ParseIP(domain) != nil {
		return true, "Valid IP address"
	}

	// Basic domain validation
	if len(domain) < 3 {
		return false, "Domain too short"
	}

	// Check for invalid characters
	for _, char := range domain {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '.') {
			return false, "Domain contains invalid characters"
		}
	}

	// Check for valid format
	if domain[0] == '-' || domain[0] == '.' || domain[len(domain)-1] == '-' || domain[len(domain)-1] == '.' {
		return false, "Domain has invalid format"
	}

	return true, "Valid domain"
}

func (a *API) sendJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}

func (a *API) sendError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(Response{
		Success: false,
		Error:   message,
	})
}

// Stats update methods (called by proxy)
func (a *API) IncrementConnection() {
	a.stats.mu.Lock()
	a.stats.TotalConnections++
	a.stats.ActiveConnections++
	a.stats.mu.Unlock()
}

func (a *API) DecrementConnection() {
	a.stats.mu.Lock()
	a.stats.ActiveConnections--
	a.stats.mu.Unlock()
}

func (a *API) IncrementBlocked(reason string) {
	a.stats.mu.Lock()
	a.stats.BlockedConnections++
	a.stats.BlockReasons[reason]++
	a.stats.mu.Unlock()
}

func (a *API) SetEmergencyMode(enabled bool) {
	a.stats.mu.Lock()
	a.stats.EmergencyMode = enabled
	a.stats.mu.Unlock()
}

func (a *API) SetProtectionDisabled(disabled bool) {
	a.stats.mu.Lock()
	a.stats.ProtectionDisabled = disabled
	a.stats.mu.Unlock()
}

// TrackProjectTraffic tracks traffic for a specific project
func (a *API) TrackProjectTraffic(shieldID string, bytesReceived int64, bytesSent int64) {
	a.projectMutex.Lock()
	defer a.projectMutex.Unlock()

	stats, exists := a.projectStats[shieldID]
	if !exists {
		stats = &ProjectStats{
			TrafficHistory: make([]TrafficPoint, 0, 60),
		}
		a.projectStats[shieldID] = stats
	}

	stats.BytesTransferred += bytesReceived + bytesSent
	stats.ConnectionsTotal++
}

// IncrementProjectPlayer increments active player count for a project
func (a *API) IncrementProjectPlayer(shieldID string) {
	a.projectMutex.Lock()
	defer a.projectMutex.Unlock()

	stats, exists := a.projectStats[shieldID]
	if !exists {
		stats = &ProjectStats{
			TrafficHistory: make([]TrafficPoint, 0, 60),
		}
		a.projectStats[shieldID] = stats
	}

	stats.ActivePlayers++
}

// DecrementProjectPlayer decrements active player count for a project
func (a *API) DecrementProjectPlayer(shieldID string) {
	a.projectMutex.Lock()
	defer a.projectMutex.Unlock()

	stats, exists := a.projectStats[shieldID]
	if exists && stats.ActivePlayers > 0 {
		stats.ActivePlayers--
	}
}

// GetProjectByDomain returns shieldID for a domain
func (a *API) GetProjectByDomain(domain string) (string, string, int) {
	a.projectMutex.RLock()
	defer a.projectMutex.RUnlock()

	shieldID, ok := a.domainToProject[domain]
	if !ok {
		return "", "", 0
	}

	// Find project and return first backend
	project, err := a.db.GetProjectByShieldID(shieldID)
	if err != nil || project == nil {
		return shieldID, "", 0
	}

	backends, err := a.db.GetProjectBackends(project.ID)
	if err != nil || len(backends) == 0 {
		return shieldID, "", 0
	}

	return shieldID, backends[0].IP, backends[0].Port
}

func (a *API) validateCNAME(domain, expectedShieldID string) (bool, string) {
	expectedCNAME := expectedShieldID + ".mangoprotect.fun"

	// Perform CNAME lookup
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		return false, "CNAME record not found. Please add: " + expectedCNAME
	}

	// Normalize (remove trailing dot)
	if len(cname) > 0 && cname[len(cname)-1] == '.' {
		cname = cname[:len(cname)-1]
	}

	if cname == expectedCNAME {
		return true, "Domain validated successfully"
	}

	return false, fmt.Sprintf("CNAME mismatch. Expected: %s, Got: %s", expectedCNAME, cname)
}

// startStatsUpdater periodically updates traffic history for all projects
func (a *API) startStatsUpdater() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		a.projectMutex.Lock()
		currentTime := time.Now().Unix()

		for shieldID, stats := range a.projectStats {
			// Calculate current BPS and PPS
			bps := float64(stats.BytesTransferred) / 2.0 // bytes per 2 seconds
			pps := stats.PacketsPerSecond

			// Add to history
			point := TrafficPoint{
				Timestamp: currentTime,
				BPS:       bps,
				PPS:       pps,
				Players:   stats.ActivePlayers,
			}

			stats.TrafficHistory = append(stats.TrafficHistory, point)

			// Keep only last 60 points (2 minutes at 2s interval)
			if len(stats.TrafficHistory) > 60 {
				stats.TrafficHistory = stats.TrafficHistory[len(stats.TrafficHistory)-60:]
			}

			// Update PPS
			stats.PacketsPerSecond = float64(stats.ConnectionsTotal) / 2.0

			// Reset counters for next interval
			stats.BytesTransferred = 0
			stats.ConnectionsTotal = 0

			a.projectStats[shieldID] = stats
		}
		a.projectMutex.Unlock()
	}
}

// handleGetRoutes returns all routes for authenticated user
func (a *API) handleGetRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Получаем пользователя из токена
	user, err := a.getUserFromRequest(r)
	if err != nil {
		a.sendError(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	// Get projects
	projects, err := a.db.GetUserProjects(user.ID)
	if err != nil {
		a.sendError(w, "Failed to get projects", http.StatusInternalServerError)
		return
	}

	// Get routes for user's projects
	routes := make([]*router.BackendRoute, 0)
	if a.router != nil {
		for _, project := range projects {
			projectRoutes := a.router.GetRoutesByShieldID(project.ShieldID)
			routes = append(routes, projectRoutes...)
		}
	}

	a.sendJSON(w, Response{Success: true, Data: routes})
}

// handleGetPortInfo returns port information for a specific shield ID
func (a *API) handleGetPortInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		a.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	shieldID := r.URL.Query().Get("shield_id")
	if shieldID == "" {
		a.sendError(w, "shield_id required", http.StatusBadRequest)
		return
	}

	if a.router == nil {
		a.sendError(w, "Router not enabled", http.StatusServiceUnavailable)
		return
	}

	routes := a.router.GetRoutesByShieldID(shieldID)

	portInfo := make([]map[string]interface{}, 0, len(routes))
	for _, route := range routes {
		portInfo = append(portInfo, map[string]interface{}{
			"domain":       route.Domain,
			"proxy_port":   route.ProxyPort,
			"backend_ip":   route.BackendIP,
			"backend_port": route.BackendPort,
			"status":       route.Status,
			"created_at":   route.CreatedAt,
			"last_seen":    route.LastSeen,
		})
	}

	a.sendJSON(w, Response{
		Success: true,
		Data: map[string]interface{}{
			"shield_id": shieldID,
			"routes":    portInfo,
		},
	})
}
