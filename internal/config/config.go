package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Database  DatabaseConfig  `yaml:"database"`
	HAProxy   HAProxyConfig   `yaml:"haproxy"`
	Router    RouterConfig    `yaml:"router"`
	MOTD      MOTDConfig      `yaml:"motd"`
	AntiForge AntiForgeConfig `yaml:"antiforge"`
	Filter    FilterConfig    `yaml:"filter"`
	RateLimit RateLimitConfig `yaml:"ratelimit"`
	Logging   LoggingConfig   `yaml:"logging"`
}

type ServerConfig struct {
	ListenAddress  string        `yaml:"listen_address"`
	BackendAddress string        `yaml:"backend_address"`
	ReadTimeout    time.Duration `yaml:"read_timeout"`
	WriteTimeout   time.Duration `yaml:"write_timeout"`
	MaxConnections int           `yaml:"max_connections"`
}

type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
}

type HAProxyConfig struct {
	Enabled         bool     `yaml:"enabled"`
	ProxyProtocolV2 bool     `yaml:"proxy_protocol_v2"`
	TrustedProxies  []string `yaml:"trusted_proxies"`
}

type RouterConfig struct {
	Enabled           bool        `yaml:"enabled"`
	PortRanges        []PortRange `yaml:"port_ranges"`
	HAProxyConfigPath string      `yaml:"haproxy_config_path"`
	HAProxyBinaryPath string      `yaml:"haproxy_binary_path"`
	HAProxySocketPath string      `yaml:"haproxy_socket_path"`
	AutoReload        bool        `yaml:"auto_reload"`
	ReloadInterval    int         `yaml:"reload_interval"` // seconds
}

type PortRange struct {
	Start int `yaml:"start"`
	End   int `yaml:"end"`
}

type MOTDConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Description   string `yaml:"description"`
	VersionName   string `yaml:"version_name"`
	MaxPlayers    int    `yaml:"max_players"`
	OnlinePlayers int    `yaml:"online_players"`
	Favicon       string `yaml:"favicon"`
}

type AntiForgeConfig struct {
	Enabled        bool     `yaml:"enabled"`
	StrictMode     bool     `yaml:"strict_mode"`
	CheckHostname  bool     `yaml:"check_hostname"`
	AllowedDomains []string `yaml:"allowed_domains"`
}

type FilterConfig struct {
	Enabled                 bool `yaml:"enabled"`
	BlockInvalidPackets     bool `yaml:"block_invalid_packets"`
	BlockBotSignatures      bool `yaml:"block_bot_signatures"`
	BlockMalformedHandshake bool `yaml:"block_malformed_handshake"`
	MaxPacketSize           int  `yaml:"max_packet_size"`
}

type RateLimitConfig struct {
	Enabled                   bool          `yaml:"enabled"`
	ConnectionsPerSecond      int           `yaml:"connections_per_second"`
	TotalConnectionsPerSecond int           `yaml:"total_connections_per_second"`
	EmergencyModeDuration     time.Duration `yaml:"emergency_mode_duration"`
	AutoDisableThreshold      int           `yaml:"auto_disable_threshold"`
	AutoDisableDuration       time.Duration `yaml:"auto_disable_duration"`
	Whitelist                 []string      `yaml:"whitelist"`
	Blacklist                 []string      `yaml:"blacklist"`
}

type LoggingConfig struct {
	Level    string `yaml:"level"`
	Format   string `yaml:"format"`
	Output   string `yaml:"output"`
	FilePath string `yaml:"file_path"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
