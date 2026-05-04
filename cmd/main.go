// Package main is the entry point for the Go Genkit Network Security Analyzer.
//
// Architecture:
//
//	[gopacket capture] → [IP channel] → [enrichment] → [genkit flow / ollama] → [actions]
//
// Usage:
//
//	sudo ./go-genkit-flow-example-1
//
// Environment variables are loaded from .env file.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"go-genkit-flow-example-1/internal/actions"
	"go-genkit-flow-example-1/internal/capture"
	"go-genkit-flow-example-1/internal/enrichment"
	"go-genkit-flow-example-1/internal/flow"
)

// Config holds all runtime configuration from environment variables.
type Config struct {
	// Network
	NetworkInterface string

	// Ollama
	OllamaBaseURL string
	OllamaModel   string

	// Database
	DatabaseFile string

	// Workers
	WorkerCount int
	IPChanSize  int
}

// loadConfig reads configuration from environment variables.
func loadConfig() Config {
	return Config{
		NetworkInterface: getEnv("NETWORK_INTERFACE", "en0"),
		OllamaBaseURL:    getEnv("OLLAMA_BASE_URL", "http://localhost:11434"),
		OllamaModel:      getEnv("OLLAMA_MODEL", "llama3.2"),
		AbuseIPDBKey:     getEnv("ABUSEIPDB_API_KEY", ""),
		DatabaseFile:     getEnv("DATABASE_FILE", "data/security.db"),
		WorkerCount:      5,
		IPChanSize:       100,
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func main() {
	// Banner
	printBanner()

	// Load .env file if present
	if err := godotenv.Load(); err != nil {
		log.Println("[MAIN] [INFO] No .env file found, using environment variables")
	}

	cfg := loadConfig()
	logConfig(cfg)

	// Ensure data directory exists
	if err := os.MkdirAll("data", 0755); err != nil {
		log.Fatalf("[MAIN] [ERROR] Failed to create data directory: %v", err)
	}

	// Setup context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle OS signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Initialize components
	log.Println("[MAIN] [START] Initializing components...")

	// 2. Action engine
	actionEngine, err := actions.NewEngine(cfg.DatabaseFile)
	if err != nil {
		log.Fatalf("[MAIN] [ERROR] Failed to initialize action engine: %v", err)
	}
	log.Println("[MAIN] [SUCCESS] Action engine ready")

	// 3. IP enricher
	enricher := enrichment.NewEnricher(cfg.AbuseIPDBKey)
	if cfg.AbuseIPDBKey != "" {
		log.Println("[MAIN] [SUCCESS] AbuseIPDB enrichment enabled")
	} else {
		log.Println("[MAIN] [WARNING] AbuseIPDB enrichment disabled (set ABUSEIPDB_API_KEY to enable)")
	}

	// 4. Genkit / Ollama analyzer
	log.Printf("[MAIN] [INFO] Connecting to Ollama at %s with model '%s'...", cfg.OllamaBaseURL, cfg.OllamaModel)
	analyzer, err := flow.NewAnalyzer(ctx, cfg.OllamaBaseURL, cfg.OllamaModel)
	if err != nil {
		log.Fatalf("[MAIN] [ERROR] Failed to initialize AI analyzer: %v", err)
	}
	log.Println("[MAIN] [SUCCESS] AI analyzer ready")

	// 5. IP channel and capturer
	ipChan := make(chan string, cfg.IPChanSize)
	fastBlockChan := make(chan string, cfg.IPChanSize)
	done := make(chan struct{})

	capturer := capture.NewCapturer(cfg.NetworkInterface, ipChan, fastBlockChan)

	// Handle fast-path blocking (rate limit triggers)
	go func() {
		for ip := range fastBlockChan {
			log.Printf("[MAIN] [FAST-PATH] Blocking IP immediately: %s", ip)
			
			result := &flow.AnalysisResult{
				IP:                ip,
				Status:            flow.StatusDangerous,
				Confidence:        1.0,
				Reason:            "Rate limit exceeded (Fast-Path: >50 pkts/sec)",
				Indicators:        []string{"high_packet_rate", "potential_flood"},
				RecommendedAction: "Block immediately at firewall level",
			}
			// Enriched data is nil because we skip external API calls on fast-path
			actionEngine.Execute(result, nil)
		}
	}()

	// Start worker pool for parallel IP analysis
	var wg sync.WaitGroup
	log.Printf("[MAIN] [INFO] Starting %d analysis workers...", cfg.WorkerCount)
	for i := 0; i < cfg.WorkerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			analysisWorker(ctx, workerID, ipChan, enricher, analyzer, actionEngine)
		}(i + 1)
	}

	// Start packet capture in background
	go func() {
		if err := capturer.Start(done); err != nil {
			log.Printf("[MAIN] [ERROR] Capture error: %v", err)
			cancel()
		}
	}()

	// Stats ticker
	statsTicker := time.NewTicker(60 * time.Second)
	defer statsTicker.Stop()

	log.Println("[MAIN] [STARTED] System running! Press Ctrl+C to stop.")
	log.Println("[MAIN] ─────────────────────────────────────────")

	// Main loop
	for {
		select {
		case <-sigChan:
			log.Println("\n[MAIN] [STOPPING] Shutdown signal received...")
			close(done)
			close(fastBlockChan)
			cancel()
			wg.Wait()
			printFinalStats(actionEngine)
			log.Println("[MAIN] [EXIT] Goodbye!")
			return

		case <-ctx.Done():
			close(done)
			wg.Wait()
			return

		case <-statsTicker.C:
			q, b, w := actionEngine.Stats()
			log.Printf("[MAIN] [STATS] Quarantined: %d | Blocked: %d | Whitelisted: %d | Queue: %d/%d",
				q, b, w, len(ipChan), cap(ipChan))
		}
	}
}

// analysisWorker reads IPs from the channel, enriches and analyzes them.
func analysisWorker(
	ctx context.Context,
	id int,
	ipChan <-chan string,
	enricher *enrichment.Enricher,
	analyzer *flow.Analyzer,
	actionEngine *actions.Engine,
) {
	log.Printf("[WORKER-%d] [STARTED] Worker ready", id)
	defer log.Printf("[WORKER-%d] [STOPPED] Worker exit", id)

	for {
		select {
		case <-ctx.Done():
			return

		case ip, ok := <-ipChan:
			if !ok {
				return
			}

			// Skip already blocked/quarantined/whitelisted IPs
			if actionEngine.IsBlocked(ip) {
				log.Printf("[WORKER-%d] [BLOCKED] %s is already blocked, skipping", id, ip)
				continue
			}
			if actionEngine.IsQuarantined(ip) {
				log.Printf("[WORKER-%d] [QUARANTINED] %s is already quarantined, skipping", id, ip)
				continue
			}
			if actionEngine.IsWhitelisted(ip) {
				log.Printf("[WORKER-%d] [WHITELISTED] %s is whitelisted, skipping", id, ip)
				continue
			}

			log.Printf("[WORKER-%d] [ANALYZING] IP: %s", id, ip)

			// Step 1: Enrich IP data
			enriched := enricher.Enrich(ip)

			// Step 2: AI analysis via Genkit flow
			result, err := analyzer.Analyze(ctx, enriched)
			if err != nil {
				log.Printf("[WORKER-%d] [ERROR] Analysis failed for %s: %v", id, ip, err)
				continue
			}

			// Step 3: Execute action based on verdict
			actionEngine.Execute(result, enriched)
		}
	}
}

// printBanner displays the startup banner.
func printBanner() {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║        Go Genkit Network Security Analyzer           ║")
	fmt.Println("║                                                      ║")
	fmt.Println("║   gopacket + Firebase Genkit + Ollama AI             ║")
	fmt.Println("║   Real-time IP Threat Detection & Response           ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Println()
}

// logConfig prints the active configuration.
func logConfig(cfg Config) {
	log.Println("[MAIN] 📋 Configuration:")
	log.Printf("[MAIN]   Network Interface : %s", cfg.NetworkInterface)
	log.Printf("[MAIN]   Ollama URL        : %s", cfg.OllamaBaseURL)
	log.Printf("[MAIN]   Ollama Model      : %s", cfg.OllamaModel)
	log.Printf("[MAIN]   Database File     : %s", cfg.DatabaseFile)
	log.Printf("[MAIN]   Workers           : %d", cfg.WorkerCount)
	log.Printf("[MAIN]   AbuseIPDB         : %v", cfg.AbuseIPDBKey != "")
}

// printFinalStats shows summary statistics on shutdown.
func printFinalStats(engine *actions.Engine) {
	q, b, w := engine.Stats()
	fmt.Println()
	fmt.Println("╔══════════════════════════════╗")
	fmt.Println("║       Session Summary        ║")
	fmt.Printf("║  Quarantined IPs  : %-6d   ║\n", q)
	fmt.Printf("║  Blocked IPs      : %-6d   ║\n", b)
	fmt.Printf("║  Whitelisted IPs  : %-6d   ║\n", w)
	fmt.Println("╚══════════════════════════════╝")
	fmt.Println()
}
