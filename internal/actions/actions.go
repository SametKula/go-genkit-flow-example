package actions

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"go-genkit-flow-example-1/internal/enrichment"
	"go-genkit-flow-example-1/internal/flow"
)

// IPRecord is stored in SQLite.
type IPRecord struct {
	IP                string            `json:"ip"`
	Status            flow.ThreatStatus `json:"status"`
	AddedAt           time.Time         `json:"added_at"`
	Confidence        float64           `json:"confidence"`
	Reason            string            `json:"reason"`
	Indicators        []string          `json:"indicators"`
	RecommendedAction string            `json:"recommended_action"`
	AccessCount       int               `json:"access_count"`
	Geo               *GeoSummary       `json:"geo,omitempty"`
}

type GeoSummary struct {
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
}

// Engine executes security actions based on AI analysis results.
type Engine struct {
	db           *sql.DB
	whitelist    map[string]time.Time
	whitelistMu  sync.RWMutex
	whitelistTTL time.Duration
}

// NewEngine creates a new action engine with the given SQLite database path.
func NewEngine(dbPath string) (*Engine, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Create table if not exists
	query := `
	CREATE TABLE IF NOT EXISTS ips (
		ip TEXT PRIMARY KEY,
		status TEXT,
		added_at DATETIME,
		confidence REAL,
		reason TEXT,
		indicators TEXT,
		recommended_action TEXT,
		access_count INTEGER,
		geo_data TEXT
	);
	`
	if _, err := db.Exec(query); err != nil {
		return nil, fmt.Errorf("failed to create table: %w", err)
	}

	e := &Engine{
		db:           db,
		whitelist:    make(map[string]time.Time),
		whitelistTTL: 1 * time.Hour, // Whitelist CLEAN IPs for 1 hour
	}

	e.loadWhitelistFromDB()

	return e, nil
}

func (e *Engine) loadWhitelistFromDB() {
	rows, err := e.db.Query("SELECT ip, added_at FROM ips WHERE status = ?", flow.StatusClean)
	if err != nil {
		log.Printf("[ACTION] [ERROR] Failed to load whitelist from DB: %v", err)
		return
	}
	defer rows.Close()

	e.whitelistMu.Lock()
	defer e.whitelistMu.Unlock()

	for rows.Next() {
		var ip string
		var addedAt time.Time
		if err := rows.Scan(&ip, &addedAt); err != nil {
			continue
		}
		
		// If added_at + TTL is still in the future, add to memory cache
		exp := addedAt.Add(e.whitelistTTL)
		if time.Now().Before(exp) {
			e.whitelist[ip] = exp
		}
	}
}

// Execute performs the appropriate action based on the AI analysis result.
func (e *Engine) Execute(result *flow.AnalysisResult, enriched *enrichment.IPEnrichment) {
	switch result.Status {
	case flow.StatusClean:
		e.handleClean(result, enriched)
	case flow.StatusSuspicious:
		e.handleSuspicious(result, enriched)
	case flow.StatusDangerous:
		e.handleDangerous(result, enriched)
	default:
		log.Printf("[ACTION] [WARNING] Unknown status %q for IP %s, treating as SUSPICIOUS", result.Status, result.IP)
		e.handleSuspicious(result, enriched)
	}
}

func (e *Engine) handleClean(result *flow.AnalysisResult, enriched *enrichment.IPEnrichment) {
	log.Printf("[ACTION] [CLEAN] IP: %s | Confidence: %.0f%% | %s", result.IP, result.Confidence*100, result.Reason)

	e.whitelistMu.Lock()
	e.whitelist[result.IP] = time.Now().Add(e.whitelistTTL)
	e.whitelistMu.Unlock()

	if err := e.saveToDB(buildRecord(result, enriched)); err != nil {
		log.Printf("[ACTION] [ERROR] Failed to persist whitelist IP %s: %v", result.IP, err)
	}
	log.Printf("[ACTION] [WHITELIST] IP %s added to whitelist for %v", result.IP, e.whitelistTTL)
}

func (e *Engine) handleSuspicious(result *flow.AnalysisResult, enriched *enrichment.IPEnrichment) {
	log.Printf("[ACTION] [SUSPICIOUS] IP: %s | Confidence: %.0f%% | %s", result.IP, result.Confidence*100, result.Reason)

	if err := e.saveToDB(buildRecord(result, enriched)); err != nil {
		log.Printf("[ACTION] [ERROR] Failed to quarantine IP %s: %v", result.IP, err)
		return
	}
	log.Printf("[ACTION] [QUARANTINED] IP %s added to quarantine list in DB", result.IP)
}

func (e *Engine) handleDangerous(result *flow.AnalysisResult, enriched *enrichment.IPEnrichment) {
	log.Printf("[ACTION] [DANGEROUS] IP: %s | Confidence: %.0f%% | %s", result.IP, result.Confidence*100, result.Reason)

	if err := e.saveToDB(buildRecord(result, enriched)); err != nil {
		log.Printf("[ACTION] [ERROR] Failed to block IP %s: %v", result.IP, err)
		return
	}
	log.Printf("[ACTION] [BLOCKED] IP %s added to BLOCK list in DB", result.IP)
}

func (e *Engine) IsBlocked(ip string) bool {
	return e.checkStatus(ip, flow.StatusDangerous)
}

func (e *Engine) IsQuarantined(ip string) bool {
	return e.checkStatus(ip, flow.StatusSuspicious)
}

func (e *Engine) checkStatus(ip string, status flow.ThreatStatus) bool {
	var count int
	err := e.db.QueryRow("SELECT COUNT(*) FROM ips WHERE ip = ? AND status = ?", ip, status).Scan(&count)
	if err != nil {
		return false
	}
	return count > 0
}

func (e *Engine) IsWhitelisted(ip string) bool {
	e.whitelistMu.RLock()
	defer e.whitelistMu.RUnlock()

	exp, exists := e.whitelist[ip]
	if !exists {
		return false
	}

	if time.Now().After(exp) {
		return false
	}

	return true
}

func (e *Engine) Stats() (quarantined, blocked, whitelisted int) {
	_ = e.db.QueryRow("SELECT COUNT(*) FROM ips WHERE status = ?", flow.StatusSuspicious).Scan(&quarantined)
	_ = e.db.QueryRow("SELECT COUNT(*) FROM ips WHERE status = ?", flow.StatusDangerous).Scan(&blocked)
	_ = e.db.QueryRow("SELECT COUNT(*) FROM ips WHERE status = ?", flow.StatusClean).Scan(&whitelisted)
	return
}

func (e *Engine) saveToDB(record IPRecord) error {
	indicatorsJSON, _ := json.Marshal(record.Indicators)
	geoJSON, _ := json.Marshal(record.Geo)

	query := `
	INSERT INTO ips (ip, status, added_at, confidence, reason, indicators, recommended_action, access_count, geo_data)
	VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
	ON CONFLICT(ip) DO UPDATE SET 
		status=excluded.status,
		added_at=excluded.added_at,
		confidence=excluded.confidence,
		reason=excluded.reason,
		indicators=excluded.indicators,
		recommended_action=excluded.recommended_action,
		access_count=ips.access_count + 1,
		geo_data=excluded.geo_data;
	`
	_, err := e.db.Exec(query, 
		record.IP, 
		record.Status, 
		record.AddedAt, 
		record.Confidence, 
		record.Reason, 
		string(indicatorsJSON), 
		record.RecommendedAction, 
		string(geoJSON),
	)
	return err
}

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
