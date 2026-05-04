// Package enrichment collects threat intelligence and geographic information
// about IP addresses using public APIs.
package enrichment

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"go-genkit-flow-example-1/internal/capture"
)

// httpClient is a shared HTTP client with timeout.
var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

// GeoInfo holds geographic data about an IP address.
type GeoInfo struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	City        string  `json:"city"`
	Region      string  `json:"regionName"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	Status      string  `json:"status"`
	Message     string  `json:"message"`
}

// AbuseReport holds threat intelligence data from AbuseIPDB.
type AbuseReport struct {
	IsPublic             bool   `json:"isPublic"`
	IPVersion            int    `json:"ipVersion"`
	IsWhitelisted        bool   `json:"isWhitelisted"`
	AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	CountryCode          string `json:"countryCode"`
	UsageType            string `json:"usageType"`
	ISP                  string `json:"isp"`
	Domain               string `json:"domain"`
	TotalReports         int    `json:"totalReports"`
	NumDistinctUsers     int    `json:"numDistinctUsers"`
	LastReportedAt       string `json:"lastReportedAt"`
}

// abuseIPDBResponse wraps the AbuseIPDB API response.
type abuseIPDBResponse struct {
	Data AbuseReport `json:"data"`
}

// IPEnrichment holds all collected data about an IP address.
type IPEnrichment struct {
	IP          string                    `json:"ip"`
	CollectedAt time.Time                 `json:"collected_at"`
	Context     capture.ConnectionContext `json:"context,omitempty"`
	Geo         *GeoInfo                  `json:"geo,omitempty"`
	Abuse       *AbuseReport              `json:"abuse,omitempty"`
	Errors      []string                  `json:"errors,omitempty"`
}

// Enricher collects IP data from multiple sources.
type Enricher struct {
	AbuseIPDBKey string // Optional: AbuseIPDB API key
}

// NewEnricher creates a new Enricher instance.
func NewEnricher(abuseIPDBKey string) *Enricher {
	return &Enricher{AbuseIPDBKey: abuseIPDBKey}
}

// Enrich gathers all available information about an IP address.
func (e *Enricher) Enrich(ctx capture.ConnectionContext) *IPEnrichment {
	ip := ctx.IP
	result := &IPEnrichment{
		IP:          ip,
		CollectedAt: time.Now(),
		Context:     ctx,
	}

	// Collect geographic info
	geo, err := e.fetchGeoInfo(ip)
	if err != nil {
		log.Printf("[ENRICHMENT] [WARNING] Geo lookup failed for %s: %v", ip, err)
		result.Errors = append(result.Errors, fmt.Sprintf("geo: %v", err))
	} else {
		result.Geo = geo
	}

	// Collect abuse report (only if API key provided)
	if e.AbuseIPDBKey != "" {
		abuse, err := e.fetchAbuseReport(ip)
		if err != nil {
			log.Printf("[ENRICHMENT] [WARNING] Abuse lookup failed for %s: %v", ip, err)
			result.Errors = append(result.Errors, fmt.Sprintf("abuse: %v", err))
		} else {
			result.Abuse = abuse
		}
	}

	return result
}

// fetchGeoInfo retrieves geographic information from ip-api.com (free tier).
func (e *Enricher) fetchGeoInfo(ip string) (*GeoInfo, error) {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as", ip)

	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var geo GeoInfo
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil {
		return nil, fmt.Errorf("decode failed: %w", err)
	}

	if geo.Status != "success" {
		return nil, fmt.Errorf("api error: %s", geo.Message)
	}

	return &geo, nil
}

// fetchAbuseReport retrieves threat intelligence from AbuseIPDB.
func (e *Enricher) fetchAbuseReport(ip string) (*AbuseReport, error) {
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose", ip)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %w", err)
	}
	req.Header.Set("Key", e.AbuseIPDBKey)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api returned status %d", resp.StatusCode)
	}

	var result abuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode failed: %w", err)
	}

	return &result.Data, nil
}

// Summary returns a human-readable summary of the enrichment data.
// This is used in the AI prompt.
func (e *IPEnrichment) Summary() string {
	summary := fmt.Sprintf("IP Address: %s\n", e.IP)
	summary += fmt.Sprintf("Analysis Time: %s\n\n", e.CollectedAt.Format(time.RFC3339))

	summary += "=== Local Network Context ===\n"
	summary += fmt.Sprintf("Ports Accessed: %v\n", e.Context.Ports)
	summary += fmt.Sprintf("Protocols Used: %v\n", e.Context.Protocols)
	summary += fmt.Sprintf("Total Bytes Transferred: %d\n", e.Context.TotalBytes)
	summary += fmt.Sprintf("Packets Captured in Window: %d\n\n", e.Context.PacketCount)

	if e.Geo != nil {
		summary += "=== Geographic Information ===\n"
		summary += fmt.Sprintf("Country: %s (%s)\n", e.Geo.Country, e.Geo.CountryCode)
		summary += fmt.Sprintf("City: %s, %s\n", e.Geo.City, e.Geo.Region)
		summary += fmt.Sprintf("ISP: %s\n", e.Geo.ISP)
		summary += fmt.Sprintf("Organization: %s\n", e.Geo.Org)
		summary += fmt.Sprintf("ASN: %s\n", e.Geo.AS)
		summary += fmt.Sprintf("Coordinates: %.4f, %.4f\n", e.Geo.Lat, e.Geo.Lon)
		summary += fmt.Sprintf("Timezone: %s\n\n", e.Geo.Timezone)
	} else {
		summary += "Geographic Information: Not available\n\n"
	}

	if e.Abuse != nil {
		summary += "=== Threat Intelligence (AbuseIPDB) ===\n"
		summary += fmt.Sprintf("Abuse Confidence Score: %d/100\n", e.Abuse.AbuseConfidenceScore)
		summary += fmt.Sprintf("Total Reports: %d\n", e.Abuse.TotalReports)
		summary += fmt.Sprintf("Distinct Reporters: %d\n", e.Abuse.NumDistinctUsers)
		summary += fmt.Sprintf("Usage Type: %s\n", e.Abuse.UsageType)
		summary += fmt.Sprintf("Whitelisted: %v\n", e.Abuse.IsWhitelisted)
		if e.Abuse.LastReportedAt != "" {
			summary += fmt.Sprintf("Last Reported: %s\n", e.Abuse.LastReportedAt)
		}
		summary += "\n"
	} else {
		summary += "Threat Intelligence: AbuseIPDB check not performed (no API key)\n\n"
	}

	if len(e.Errors) > 0 {
		summary += "=== Lookup Errors ===\n"
		for _, errMsg := range e.Errors {
			summary += fmt.Sprintf("- %s\n", errMsg)
		}
	}

	return summary
}
