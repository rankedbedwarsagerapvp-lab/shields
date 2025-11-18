package router

import (
	"fmt"
	"net"
	"sync"
	"time"

	"shield/internal/logger"
)

// PortRange represents a range of ports that can be allocated
type PortRange struct {
	Start int
	End   int
}

// PortAllocator manages dynamic port allocation for projects
type PortAllocator struct {
	mu             sync.RWMutex
	allocatedPorts map[int]string // port -> shieldID
	portRanges     []PortRange
	nextPort       int
}

// BackendRoute represents a route to a backend server
type BackendRoute struct {
	ShieldID    string    `json:"shield_id"`
	Domain      string    `json:"domain"`
	BackendIP   string    `json:"backend_ip"`
	BackendPort int       `json:"backend_port"`
	ProxyPort   int       `json:"proxy_port"` // Port on which Shield listens
	Status      string    `json:"status"`     // "active", "inactive"
	CreatedAt   time.Time `json:"created_at"`
	LastSeen    time.Time `json:"last_seen"`
}

// Router manages routing between domains and backend servers
type Router struct {
	mu             sync.RWMutex
	routes         map[string]*BackendRoute   // domain -> route
	shieldToRoutes map[string][]*BackendRoute // shieldID -> routes
	portAllocator  *PortAllocator
	onRouteChange  func(route *BackendRoute, action string) // Callback for route changes
}

// NewPortAllocator creates a new port allocator
func NewPortAllocator(ranges []PortRange) *PortAllocator {
	pa := &PortAllocator{
		allocatedPorts: make(map[int]string),
		portRanges:     ranges,
	}

	if len(ranges) > 0 {
		pa.nextPort = ranges[0].Start
	}

	return pa
}

// AllocatePort allocates a port for a shield ID
func (pa *PortAllocator) AllocatePort(shieldID string) (int, error) {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	// Try to find an available port
	for _, portRange := range pa.portRanges {
		for port := portRange.Start; port <= portRange.End; port++ {
			if _, exists := pa.allocatedPorts[port]; !exists {
				// Check if port is actually free
				if pa.isPortFree(port) {
					pa.allocatedPorts[port] = shieldID
					logger.Log.WithFields(map[string]interface{}{
						"shield_id": shieldID,
						"port":      port,
					}).Info("Port allocated")
					return port, nil
				}
			}
		}
	}

	return 0, fmt.Errorf("no available ports in configured ranges")
}

// ReleasePort releases a port
func (pa *PortAllocator) ReleasePort(port int) {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	shieldID := pa.allocatedPorts[port]
	delete(pa.allocatedPorts, port)

	logger.Log.WithFields(map[string]interface{}{
		"shield_id": shieldID,
		"port":      port,
	}).Info("Port released")
}

// GetAllocatedPort returns the allocated port for a shield ID
func (pa *PortAllocator) GetAllocatedPort(shieldID string) (int, bool) {
	pa.mu.RLock()
	defer pa.mu.RUnlock()

	for port, sid := range pa.allocatedPorts {
		if sid == shieldID {
			return port, true
		}
	}
	return 0, false
}

// isPortFree checks if a port is actually free on the system
func (pa *PortAllocator) isPortFree(port int) bool {
	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	listener.Close()
	return true
}

// NewRouter creates a new router
func NewRouter(portRanges []PortRange, onRouteChange func(route *BackendRoute, action string)) *Router {
	return &Router{
		routes:         make(map[string]*BackendRoute),
		shieldToRoutes: make(map[string][]*BackendRoute),
		portAllocator:  NewPortAllocator(portRanges),
		onRouteChange:  onRouteChange,
	}
}

// AddRoute adds a new route
func (r *Router) AddRoute(shieldID, domain, backendIP string, backendPort int) (*BackendRoute, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if domain already exists
	if existingRoute, exists := r.routes[domain]; exists {
		return existingRoute, fmt.Errorf("domain already routed")
	}

	// Allocate a port for this route
	proxyPort, err := r.portAllocator.AllocatePort(shieldID)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate port: %w", err)
	}

	route := &BackendRoute{
		ShieldID:    shieldID,
		Domain:      domain,
		BackendIP:   backendIP,
		BackendPort: backendPort,
		ProxyPort:   proxyPort,
		Status:      "active",
		CreatedAt:   time.Now(),
		LastSeen:    time.Now(),
	}

	r.routes[domain] = route
	r.shieldToRoutes[shieldID] = append(r.shieldToRoutes[shieldID], route)

	logger.Log.WithFields(map[string]interface{}{
		"shield_id":  shieldID,
		"domain":     domain,
		"backend":    fmt.Sprintf("%s:%d", backendIP, backendPort),
		"proxy_port": proxyPort,
	}).Info("Route added")

	// Notify about route change
	if r.onRouteChange != nil {
		r.onRouteChange(route, "add")
	}

	return route, nil
}

// RemoveRoute removes a route by domain
func (r *Router) RemoveRoute(domain string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	route, exists := r.routes[domain]
	if !exists {
		return fmt.Errorf("route not found")
	}

	// Release the port
	r.portAllocator.ReleasePort(route.ProxyPort)

	// Remove from routes
	delete(r.routes, domain)

	// Remove from shield routes
	if routes, ok := r.shieldToRoutes[route.ShieldID]; ok {
		newRoutes := []*BackendRoute{}
		for _, r := range routes {
			if r.Domain != domain {
				newRoutes = append(newRoutes, r)
			}
		}
		r.shieldToRoutes[route.ShieldID] = newRoutes
	}

	logger.Log.WithFields(map[string]interface{}{
		"domain":     domain,
		"shield_id":  route.ShieldID,
		"proxy_port": route.ProxyPort,
	}).Info("Route removed")

	// Notify about route change
	if r.onRouteChange != nil {
		r.onRouteChange(route, "remove")
	}

	return nil
}

// GetRoute returns a route by domain
func (r *Router) GetRoute(domain string) (*BackendRoute, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	route, exists := r.routes[domain]
	if exists {
		// Update last seen
		route.LastSeen = time.Now()
	}
	return route, exists
}

// GetRoutesByShieldID returns all routes for a shield ID
func (r *Router) GetRoutesByShieldID(shieldID string) []*BackendRoute {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.shieldToRoutes[shieldID]
}

// GetAllRoutes returns all active routes
func (r *Router) GetAllRoutes() []*BackendRoute {
	r.mu.RLock()
	defer r.mu.RUnlock()

	routes := make([]*BackendRoute, 0, len(r.routes))
	for _, route := range r.routes {
		routes = append(routes, route)
	}
	return routes
}

// UpdateRouteBackend updates the backend for a route
func (r *Router) UpdateRouteBackend(domain, backendIP string, backendPort int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	route, exists := r.routes[domain]
	if !exists {
		return fmt.Errorf("route not found")
	}

	route.BackendIP = backendIP
	route.BackendPort = backendPort
	route.LastSeen = time.Now()

	logger.Log.WithFields(map[string]interface{}{
		"domain":  domain,
		"backend": fmt.Sprintf("%s:%d", backendIP, backendPort),
	}).Info("Route backend updated")

	// Notify about route change
	if r.onRouteChange != nil {
		r.onRouteChange(route, "update")
	}

	return nil
}

// SetRouteStatus sets the status of a route
func (r *Router) SetRouteStatus(domain, status string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	route, exists := r.routes[domain]
	if !exists {
		return fmt.Errorf("route not found")
	}

	route.Status = status
	route.LastSeen = time.Now()

	return nil
}
