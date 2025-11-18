package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"shield/internal/api"
	"shield/internal/config"
	"shield/internal/database"
	"shield/internal/logger"
	"shield/internal/proxy"
)

var (
	configPath = flag.String("config", "config.yaml", "Path to configuration file")
	apiAddr    = flag.String("api", ":8080", "API server address")
	version    = "1.0.0"
)

func main() {
	flag.Parse()

	// Print banner
	printBanner()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	if err := logger.Init(cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.Output, cfg.Logging.FilePath); err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	logger.Log.Info("Shield protection starting...")
	logger.Log.Infof("Configuration loaded from %s", *configPath)

	// Initialize database
	db, err := database.New(
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Username,
		cfg.Database.Password,
		cfg.Database.Database,
	)
	if err != nil {
		logger.Log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Create proxy
	p := proxy.New(cfg)

	// Create API server
	apiServer := api.New(cfg, db, func(newConfig *config.Config) {
		logger.Log.Info("Configuration changed via API, reloading...")
		// Update proxy with new config (in real implementation, you'd need to handle this)
	})

	// Start API server in background
	go func() {
		logger.Log.Infof("Starting API server on %s", *apiAddr)
		if err := apiServer.Start(*apiAddr); err != nil {
			logger.Log.Fatalf("Failed to start API server: %v", err)
		}
	}()

	// Pass API to proxy for stats updates
	p.SetAPI(apiServer)

	// Handle shutdown gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Log.Info("Shutdown signal received, stopping...")
		if err := p.Stop(); err != nil {
			logger.Log.Errorf("Error stopping proxy: %v", err)
		}
		os.Exit(0)
	}()

	// Start proxy
	if err := p.Start(); err != nil {
		logger.Log.Fatalf("Failed to start proxy: %v", err)
	}
}

func printBanner() {
	banner := `
╔═══════════════════════════════════════════════╗
║                                               ║
║   ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ ║
║   ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗║
║   ███████╗███████║██║█████╗  ██║     ██║  ██║║
║   ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║║
║   ███████║██║  ██║██║███████╗███████╗██████╔╝║
║   ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ ║
║                                               ║
║        Minecraft DDoS Protection System       ║
║              Version %s                   ║
║                                               ║
╚═══════════════════════════════════════════════╝
`
	fmt.Printf(banner, version)
	fmt.Println()
}
