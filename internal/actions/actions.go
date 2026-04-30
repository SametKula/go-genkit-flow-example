// Package actions implements the response actions for each IP threat level:
//   - CLEAN: Log and release (no action)
//   - SUSPICIOUS: Add to quarantine_ips.json
//   - DANGEROUS: Add to blocked_ips.json + send Telegram alert
package actions

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"go-genkit-flow-example-1/internal/enrichment"
	"go-genkit-flow-example-1/internal/flow"
	"go-genkit-flow-example-1/internal/telegram"
)

// IPRecord is stored in the JSON files for quarantined/blocked IPs.
type IPRecord struct {
	IP                string            `json:"ip"`
	Status            flow.ThreatStatus `json:"status"`
	AddedAt           time.Time         `json:"added_at"`
	Confidence        float64           `json:"confidence"`
	Reason            string            `json:"reason"`
	Indicators        []string          `json:"indicators"`
	RecommendedAction string            `json:"recommended_action"`
	Geo               *GeoSummary       `json:"geo,omitempty"`
}

// GeoSummary is a compact geographic summary stored with each IP record.
type GeoSummary struct {
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
}

// ipStore manages read/write access to an IP JSON file.
type ipStore struct {
	path    string
	mu      sync.Mutex
	records []IPRecord
}

// Engine executes security actions based on AI analysis results.
type Engine struct {
	quarantineStore *ipStore
	blockStore      *ipStore
	telegramBot     *telegram.Bot
	whitelist       map[string]time.Time
	whitelistMu     sync.RWMutex
	whitelistTTL    time.Duration
}

// NewEngine creates a new action engine with the given file paths and Telegram bot.
func NewEngine(quarantinePath, blockPath string, bot *telegram.Bot) (*Engine, error) {
	quarantine, err := loadStore(quarantinePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load quarantine store: %w", err)
	}

	block, err := loadStore(blockPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load block store: %w", err)
	}

	return &Engine{
		quarantineStore: quarantine,
		blockStore:      block,
		telegramBot:     bot,
		whitelist:       make(map[string]time.Time),
		whitelistTTL:    1 * time.Hour, // Whitelist CLEAN IPs for 1 hour
	}, nil
}

// Execute performs the appropriate action based on the AI analysis result.
func (e *Engine) Execute(result *flow.AnalysisResult, enriched *enrichment.IPEnrichment) {
	switch result.Status {
	case flow.StatusClean:
		e.handleClean(result)
	case flow.StatusSuspicious:
		e.handleSuspicious(result, enriched)
	case flow.StatusDangerous:
		e.handleDangerous(result, enriched)
	default:
		log.Printf("[ACTION] ⚠️  Unknown status %q for IP %s, treating as SUSPICIOUS", result.Status, result.IP)
		e.handleSuspicious(result, enriched)
	}
}

// handleClean logs the clean result and adds the IP to the temporary whitelist.
func (e *Engine) handleClean(result *flow.AnalysisResult) {
	log.Printf("[ACTION] ✅ CLEAN  | IP: %s | Confidence: %.0f%% | %s",
		result.IP, result.Confidence*100, result.Reason)

	e.whitelistMu.Lock()
	defer e.whitelistMu.Unlock()
	e.whitelist[result.IP] = time.Now().Add(e.whitelistTTL)
	log.Printf("[ACTION] 🏳️  IP %s added to whitelist for %v", result.IP, e.whitelistTTL)
}

// handleSuspicious adds the IP to the quarantine list.
func (e *Engine) handleSuspicious(result *flow.AnalysisResult, enriched *enrichment.IPEnrichment) {
	log.Printf("[ACTION] 🟡 SUSPICIOUS | IP: %s | Confidence: %.0f%% | %s",
		result.IP, result.Confidence*100, result.Reason)

	record := buildRecord(result, enriched)
	if err := e.quarantineStore.add(record); err != nil {
		log.Printf("[ACTION] ❌ Failed to quarantine IP %s: %v", result.IP, err)
		return
	}

	log.Printf("[ACTION] 🔒 IP %s added to quarantine list (%s)", result.IP, e.quarantineStore.path)
}

// handleDangerous blocks the IP and sends a Telegram alert.
func (e *Engine) handleDangerous(result *flow.AnalysisResult, enriched *enrichment.IPEnrichment) {
	log.Printf("[ACTION] 🔴 DANGEROUS | IP: %s | Confidence: %.0f%% | %s",
		result.IP, result.Confidence*100, result.Reason)

	record := buildRecord(result, enriched)
	if err := e.blockStore.add(record); err != nil {
		log.Printf("[ACTION] ❌ Failed to block IP %s: %v", result.IP, err)
		return
	}

	log.Printf("[ACTION] 🚫 IP %s added to BLOCK list (%s)", result.IP, e.blockStore.path)

	// Send Telegram alert
	if e.telegramBot != nil && e.telegramBot.Enabled() {
		if err := e.telegramBot.SendDangerAlert(
			result.IP,
			result.Reason,
			result.Confidence,
			result.Indicators,
		); err != nil {
			log.Printf("[ACTION] ❌ Telegram alert failed for %s: %v", result.IP, err)
		}
	} else {
		log.Printf("[ACTION] ⚠️  Telegram not configured — skipping notification for %s", result.IP)
	}
}

// IsBlocked returns true if the IP is in the block list.
func (e *Engine) IsBlocked(ip string) bool {
	return e.blockStore.contains(ip)
}

// IsQuarantined returns true if the IP is in the quarantine list.
func (e *Engine) IsQuarantined(ip string) bool {
	return e.quarantineStore.contains(ip)
}

// IsWhitelisted returns true if the IP is currently in the temporary whitelist.
func (e *Engine) IsWhitelisted(ip string) bool {
	e.whitelistMu.RLock()
	defer e.whitelistMu.RUnlock()

	exp, exists := e.whitelist[ip]
	if !exists {
		return false
	}

	if time.Now().After(exp) {
		// Clean up expired entry (optional, but good for memory)
		return false
	}

	return true
}

// Stats returns count of quarantined and blocked IPs.
func (e *Engine) Stats() (quarantined, blocked int) {
	e.quarantineStore.mu.Lock()
	quarantined = len(e.quarantineStore.records)
	e.quarantineStore.mu.Unlock()

	e.blockStore.mu.Lock()
	blocked = len(e.blockStore.records)
	e.blockStore.mu.Unlock()

	return
}

// --- ipStore helpers ---

// loadStore loads existing records from a JSON file (creates if not exists).
func loadStore(path string) (*ipStore, error) {
	store := &ipStore{path: path}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// File doesn't exist yet — start with empty list
		store.records = []IPRecord{}
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	if err := json.Unmarshal(data, &store.records); err != nil {
		// File corrupted or empty — start fresh
		log.Printf("[ACTION] ⚠️  Could not parse %s, starting fresh: %v", path, err)
		store.records = []IPRecord{}
	}

	return store, nil
}

// add appends a record to the store and persists it to disk.
func (s *ipStore) add(record IPRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for duplicates
	for _, existing := range s.records {
		if existing.IP == record.IP {
			log.Printf("[ACTION] 📋 IP %s already in %s, updating...", record.IP, s.path)
			// Update existing entry
			for i, r := range s.records {
				if r.IP == record.IP {
					s.records[i] = record
					return s.save()
				}
			}
		}
	}

	s.records = append(s.records, record)
	return s.save()
}

// contains checks if an IP exists in the store.
func (s *ipStore) contains(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, record := range s.records {
		if record.IP == ip {
			return true
		}
	}
	return false
}

// save persists the current records to disk as formatted JSON.
func (s *ipStore) save() error {
	data, err := json.MarshalIndent(s.records, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	if err := os.WriteFile(s.path, data, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

// buildRecord creates an IPRecord from an analysis result and enrichment data.
func buildRecord(result *flow.AnalysisResult, enriched *enrichment.IPEnrichment) IPRecord {
	record := IPRecord{
		IP:                result.IP,
		Status:            result.Status,
		AddedAt:           time.Now(),
		Confidence:        result.Confidence,
		Reason:            result.Reason,
		Indicators:        result.Indicators,
		RecommendedAction: result.RecommendedAction,
	}

	if enriched != nil && enriched.Geo != nil {
		record.Geo = &GeoSummary{
			Country:     enriched.Geo.Country,
			CountryCode: enriched.Geo.CountryCode,
			City:        enriched.Geo.City,
			ISP:         enriched.Geo.ISP,
		}
	}

	return record
}
