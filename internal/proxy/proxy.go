package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"time"

	"shield/internal/antiforge"
	"shield/internal/config"
	pkgfilter "shield/internal/filter"
	"shield/internal/haproxy"
	"shield/internal/logger"
	"shield/internal/minecraft"
	"shield/internal/ratelimit"
)

type Proxy struct {
	config      *config.Config
	rateLimiter *ratelimit.RateLimiter
	antiForge   *antiforge.AntiForge
	filter      *pkgfilter.Filter
	listener    net.Listener
	api         interface {
		IncrementConnection()
		DecrementConnection()
		IncrementBlocked(reason string)
		SetEmergencyMode(enabled bool)
		SetProtectionDisabled(disabled bool)
		GetProjectByDomain(domain string) (string, string, int)
		TrackProjectTraffic(shieldID string, bytesReceived int64, bytesSent int64)
		IncrementProjectPlayer(shieldID string)
		DecrementProjectPlayer(shieldID string)
	}
}

type Backend struct {
	ID        string    `json:"id"`
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	CreatedAt time.Time `json:"created_at"`
}

func New(cfg *config.Config) *Proxy {
	rateLimiter := ratelimit.New(
		cfg.RateLimit.Enabled,
		cfg.RateLimit.ConnectionsPerSecond,
		cfg.RateLimit.TotalConnectionsPerSecond,
		cfg.RateLimit.AutoDisableThreshold,
		cfg.RateLimit.EmergencyModeDuration,
		cfg.RateLimit.AutoDisableDuration,
		cfg.RateLimit.Whitelist,
		cfg.RateLimit.Blacklist,
	)

	antiForge := antiforge.New(
		cfg.AntiForge.Enabled,
		cfg.AntiForge.StrictMode,
		cfg.AntiForge.CheckHostname,
		cfg.AntiForge.AllowedDomains,
	)

	filter := pkgfilter.New(
		cfg.Filter.Enabled,
		cfg.Filter.BlockInvalidPackets,
		cfg.Filter.BlockBotSignatures,
		cfg.Filter.BlockMalformedHandshake,
		cfg.Filter.MaxPacketSize,
	)

	return &Proxy{
		config:      cfg,
		rateLimiter: rateLimiter,
		antiForge:   antiForge,
		filter:      filter,
	}
}

func (p *Proxy) Start() error {
	listener, err := net.Listen("tcp", p.config.Server.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	p.listener = listener
	logger.Log.WithField("listen", p.config.Server.ListenAddress).Info("Shield proxy listening")
	logger.Log.WithField("backend", p.config.Server.BackendAddress).Info("Backend server configured")
	logger.Log.WithField("haproxy_mode", p.config.HAProxy.Enabled).Info("HAProxy mode")

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Log.WithError(err).Error("Failed to accept connection")
			continue
		}

		go p.handleConnection(conn)
	}
}

func (p *Proxy) Stop() error {
	if p.listener != nil {
		p.rateLimiter.Stop()
		return p.listener.Close()
	}
	return nil
}

func (p *Proxy) SetAPI(api interface {
	IncrementConnection()
	DecrementConnection()
	IncrementBlocked(reason string)
	SetEmergencyMode(enabled bool)
	SetProtectionDisabled(disabled bool)
	GetProjectByDomain(domain string) (string, string, int)
	TrackProjectTraffic(shieldID string, bytesReceived int64, bytesSent int64)
	IncrementProjectPlayer(shieldID string)
	DecrementProjectPlayer(shieldID string)
}) {
	p.api = api
}

func (p *Proxy) handleConnection(clientConn net.Conn) {
	// Increment connection counter
	if p.api != nil {
		p.api.IncrementConnection()
		defer p.api.DecrementConnection()
	}

	defer func() { _ = clientConn.Close() }()

	clientAddr := clientConn.RemoteAddr().String()
	logger.Log.WithField("addr", clientAddr).Debug("New connection")

	// Set timeouts
	_ = clientConn.SetReadDeadline(time.Now().Add(p.config.Server.ReadTimeout))
	_ = clientConn.SetWriteDeadline(time.Now().Add(p.config.Server.WriteTimeout))

	var realClientIP net.IP
	var proxyInfo *haproxy.ProxyInfo

	// Read HAProxy PROXY protocol if enabled
	if p.config.HAProxy.Enabled {
		if !haproxy.IsTrustedProxy(clientAddr, p.config.HAProxy.TrustedProxies) {
			logger.Log.WithField("addr", clientAddr).Warn("Connection from untrusted proxy")
			return
		}

		info, err := haproxy.ReadProxyProtocolV2(clientConn)
		if err != nil {
			logger.Log.WithFields(map[string]interface{}{
				"addr":  clientAddr,
				"error": err,
			}).Debug("Failed to read PROXY protocol")
			// Continue without proxy info if not available
		} else {
			proxyInfo = info
			realClientIP = info.SourceIP
			logger.Log.WithField("real_ip", realClientIP).Debug("Real client IP from PROXY protocol")
		}
	}

	// If no proxy info, use direct connection IP
	if realClientIP == nil {
		ip, _, err := net.SplitHostPort(clientAddr)
		if err != nil {
			logger.Log.WithFields(map[string]interface{}{
				"addr":  clientAddr,
				"error": err,
			}).Error("Invalid client address")
			return
		}
		realClientIP = net.ParseIP(ip)
	}

	// Rate limiting
	allowed, reason := p.rateLimiter.Allow(realClientIP)
	if !allowed {
		if p.api != nil {
			p.api.IncrementBlocked("rate_limit")
		}
		logger.Log.WithFields(map[string]interface{}{
			"ip":     realClientIP.String(),
			"reason": reason,
		}).Warn("Rate limit blocked")
		return
	}

	// Read first packet (should be handshake)
	packet, err := minecraft.ReadPacket(clientConn, p.config.Filter.MaxPacketSize)
	if err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"ip":    realClientIP.String(),
			"error": err,
		}).Debug("Failed to read packet")
		return
	}

	// Check packet size
	if ok, reason := p.filter.CheckPacketSize(int(packet.Length)); !ok {
		if p.api != nil {
			p.api.IncrementBlocked("invalid_packet_size")
		}
		logger.Log.WithFields(map[string]interface{}{
			"ip":     realClientIP.String(),
			"reason": reason,
		}).Warn("Invalid packet size")
		return
	}

	// Only handle handshake packets
	if packet.PacketID != minecraft.PacketHandshake {
		if p.api != nil {
			p.api.IncrementBlocked("invalid_packet_id")
		}
		logger.Log.WithFields(map[string]interface{}{
			"ip":        realClientIP.String(),
			"packet_id": fmt.Sprintf("0x%02X", packet.PacketID),
		}).Warn("Expected handshake packet")
		return
	}

	// Parse handshake
	handshake, err := minecraft.ParseHandshake(packet.Data)
	if err != nil {
		if p.api != nil {
			p.api.IncrementBlocked("malformed_handshake")
		}
		logger.Log.WithFields(map[string]interface{}{
			"ip":    realClientIP.String(),
			"error": err,
		}).Warn("Failed to parse handshake")
		return
	}

	logger.Log.WithFields(map[string]interface{}{
		"ip":       realClientIP.String(),
		"protocol": handshake.ProtocolVersion,
		"host":     handshake.ServerAddress,
		"port":     handshake.ServerPort,
		"state":    handshake.NextState,
	}).Debug("Handshake received")

	// Strip Forge markers from hostname
	cleanHostname := antiforge.StripForgeMarker(handshake.ServerAddress)

	// Validate handshake
	if ok, reason := p.filter.CheckHandshake(handshake.ProtocolVersion, handshake.ServerAddress, handshake.ServerPort, handshake.NextState); !ok {
		if p.api != nil {
			p.api.IncrementBlocked("invalid_handshake")
		}
		logger.Log.WithFields(map[string]interface{}{
			"ip":     realClientIP.String(),
			"reason": reason,
		}).Warn("Invalid handshake")
		return
	}

	// Check bot signatures
	if ok, reason := p.filter.CheckBotSignature(cleanHostname, realClientIP); !ok {
		if p.api != nil {
			p.api.IncrementBlocked("bot_signature")
		}
		logger.Log.WithFields(map[string]interface{}{
			"ip":     realClientIP.String(),
			"reason": reason,
		}).Warn("Bot signature detected")
		return
	}

	// AntiForge validation
	var proxyIP net.IP
	if proxyInfo != nil {
		ip, _, _ := net.SplitHostPort(clientAddr)
		proxyIP = net.ParseIP(ip)
	}

	if !p.antiForge.ValidateConnection(realClientIP, proxyIP, cleanHostname) {
		if p.api != nil {
			p.api.IncrementBlocked("antiforge")
		}
		logger.Log.WithFields(map[string]interface{}{
			"ip":       realClientIP.String(),
			"hostname": cleanHostname,
		}).Warn("AntiForge blocked connection")
		return
	}

	// Handle status request (MOTD)
	if handshake.NextState == minecraft.StateStatus {
		p.handleStatusRequest(clientConn, handshake, realClientIP)
		return
	}

	// For login state, proxy to backend
	if handshake.NextState == minecraft.StateLogin {
		// Track player connection
		if p.api != nil {
			cleanHostname := antiforge.StripForgeMarker(handshake.ServerAddress)
			sid, _, _ := p.api.GetProjectByDomain(cleanHostname)
			if sid != "" {
				p.api.IncrementProjectPlayer(sid)
			}
		}
		p.proxyToBackend(clientConn, handshake, packet, proxyInfo, realClientIP)
		return
	}
}

func (p *Proxy) handleStatusRequest(clientConn net.Conn, handshake *minecraft.HandshakePacket, clientIP net.IP) {
	// Read status request packet
	packet, err := minecraft.ReadPacket(clientConn, p.config.Filter.MaxPacketSize)
	if err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"ip":    clientIP.String(),
			"error": err,
		}).Debug("Failed to read status request")
		return
	}

	if packet.PacketID != minecraft.PacketStatusRequest {
		logger.Log.WithFields(map[string]interface{}{
			"ip":        clientIP.String(),
			"packet_id": fmt.Sprintf("0x%02X", packet.PacketID),
		}).Warn("Expected status request")
		return
	}

	// Send custom MOTD if enabled
	if p.config.MOTD.Enabled {
		logger.Log.WithField("ip", clientIP.String()).Debug("Sending custom MOTD")

		statusData, err := minecraft.CreateStatusResponse(
			p.config.MOTD.VersionName,
			int(handshake.ProtocolVersion),
			p.config.MOTD.MaxPlayers,
			p.config.MOTD.OnlinePlayers,
			p.config.MOTD.Description,
			p.config.MOTD.Favicon,
		)
		if err != nil {
			logger.Log.WithError(err).Error("Failed to create status response")
			return
		}

		if err := minecraft.WritePacket(clientConn, minecraft.PacketStatusResponse, statusData); err != nil {
			logger.Log.WithFields(map[string]interface{}{
				"ip":    clientIP.String(),
				"error": err,
			}).Debug("Failed to write status response")
			return
		}

		// Handle ping if client sends it
		pingPacket, err := minecraft.ReadPacket(clientConn, p.config.Filter.MaxPacketSize)
		if err == nil && pingPacket.PacketID == minecraft.PacketPingRequest {
			_ = minecraft.WritePacket(clientConn, minecraft.PacketPingResponse, pingPacket.Data)
		}

		return
	}

	// Otherwise, proxy status request to backend
	p.proxyStatusToBackend(clientConn, handshake, packet, clientIP)
}

func (p *Proxy) proxyStatusToBackend(clientConn net.Conn, handshake *minecraft.HandshakePacket, statusPacket *minecraft.Packet, clientIP net.IP) {
	backend, err := net.Dial("tcp", p.config.Server.BackendAddress)
	if err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"ip":    clientIP.String(),
			"error": err,
		}).Error("Failed to connect to backend")
		return
	}
	defer func() { _ = backend.Close() }()

	// Reconstruct and send handshake
	handshakeBuf := new(bytes.Buffer)
	_ = minecraft.WriteVarInt(handshakeBuf, handshake.ProtocolVersion)
	_ = minecraft.WriteString(handshakeBuf, handshake.ServerAddress)
	handshakeBuf.Write([]byte{byte(handshake.ServerPort >> 8), byte(handshake.ServerPort)})
	_ = minecraft.WriteVarInt(handshakeBuf, handshake.NextState)

	if err := minecraft.WritePacket(backend, minecraft.PacketHandshake, handshakeBuf.Bytes()); err != nil {
		logger.Log.WithError(err).Error("Failed to write handshake to backend")
		return
	}

	// Send status request
	if err := minecraft.WritePacket(backend, minecraft.PacketStatusRequest, statusPacket.Data); err != nil {
		logger.Log.WithError(err).Error("Failed to write status request to backend")
		return
	}

	// Copy response back to client
	_, _ = io.Copy(clientConn, backend)
}

func (p *Proxy) proxyToBackend(clientConn net.Conn, handshake *minecraft.HandshakePacket, _ *minecraft.Packet, proxyInfo *haproxy.ProxyInfo, clientIP net.IP) {
	// Get project and backend by domain
	var backendAddr string
	var shieldID string

	if p.api != nil {
		sid, backendIP, backendPort := p.api.GetProjectByDomain(handshake.ServerAddress)
		shieldID = sid
		if backendIP != "" && backendPort > 0 {
			backendAddr = fmt.Sprintf("%s:%d", backendIP, backendPort)
			logger.Log.WithFields(map[string]interface{}{
				"domain":    handshake.ServerAddress,
				"shield_id": shieldID,
				"backend":   backendAddr,
			}).Info("Routing to project backend")
		}
	}

	// Decrement player count on exit
	defer func() {
		if p.api != nil && shieldID != "" {
			p.api.DecrementProjectPlayer(shieldID)
		}
	}()

	// Fallback to default backend
	if backendAddr == "" {
		backendAddr = p.config.Server.BackendAddress
	}

	backend, err := net.Dial("tcp", backendAddr)
	if err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"ip":      clientIP.String(),
			"backend": backendAddr,
			"error":   err,
		}).Error("Failed to connect to backend")
		return
	}
	defer func() { _ = backend.Close() }()

	logger.Log.WithFields(map[string]interface{}{
		"ip":      clientIP.String(),
		"backend": backendAddr,
	}).Info("Proxying connection to backend")

	// Send PROXY protocol to backend if enabled
	if p.config.HAProxy.Enabled && proxyInfo != nil {
		if err := haproxy.WriteProxyProtocolV2(backend, proxyInfo); err != nil {
			logger.Log.WithError(err).Error("Failed to write PROXY protocol to backend")
			return
		}
	}

	// Reconstruct and send handshake
	handshakeBuf := new(bytes.Buffer)
	_ = minecraft.WriteVarInt(handshakeBuf, handshake.ProtocolVersion)
	_ = minecraft.WriteString(handshakeBuf, handshake.ServerAddress)
	handshakeBuf.Write([]byte{byte(handshake.ServerPort >> 8), byte(handshake.ServerPort)})
	_ = minecraft.WriteVarInt(handshakeBuf, handshake.NextState)

	if err := minecraft.WritePacket(backend, minecraft.PacketHandshake, handshakeBuf.Bytes()); err != nil {
		logger.Log.WithError(err).Error("Failed to write handshake to backend")
		return
	}

	// Bidirectional copy with traffic tracking
	done := make(chan bool, 2)
	var bytesFromClient, bytesToClient int64

	go func() {
		n, _ := io.Copy(backend, clientConn)
		bytesFromClient = n
		done <- true
	}()

	go func() {
		n, _ := io.Copy(clientConn, backend)
		bytesToClient = n
		done <- true
	}()

	<-done

	// Track traffic for project
	if p.api != nil && shieldID != "" {
		p.api.TrackProjectTraffic(shieldID, bytesFromClient, bytesToClient)
	}
}
