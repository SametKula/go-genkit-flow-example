// Package flow defines the Genkit AI flow for IP security analysis.
// It sends enriched IP data to a local Ollama model and parses the
// structured security verdict.
package flow

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/firebase/genkit/go/ai"
	"github.com/firebase/genkit/go/genkit"
	"github.com/firebase/genkit/go/plugins/ollama"

	"go-genkit-flow-example-1/internal/enrichment"
)

// ThreatStatus represents the AI-determined security status of an IP.
type ThreatStatus string

const (
	StatusClean      ThreatStatus = "CLEAN"
	StatusSuspicious ThreatStatus = "SUSPICIOUS"
	StatusDangerous  ThreatStatus = "DANGEROUS"
)

// AnalysisInput is the input schema for the IP analysis flow.
type AnalysisInput struct {
	IP      string                    `json:"ip"`
	Summary string                    `json:"summary"`
	Data    *enrichment.IPEnrichment  `json:"data"`
}

// AnalysisResult is the structured output from the AI model.
type AnalysisResult struct {
	IP                string       `json:"ip"`
	Status            ThreatStatus `json:"status"`
	Confidence        float64      `json:"confidence"`
	Reason            string       `json:"reason"`
	Indicators        []string     `json:"indicators"`
	RecommendedAction string       `json:"recommended_action"`
}

// Analyzer wraps the Genkit flow for IP security analysis.
type Analyzer struct {
	g     *genkit.Genkit
	model ai.Model
	flow  *genkit.Flow[*AnalysisInput, *AnalysisResult, struct{}]
}

// systemPrompt is the instruction set for the AI model.
const systemPrompt = `You are an expert cybersecurity analyst specializing in IP threat assessment.

Your task is to analyze IP address data and determine if it poses a security threat.

CLASSIFICATION LEVELS:
- CLEAN: The IP appears legitimate and poses no known threat
- SUSPICIOUS: The IP shows some concerning indicators and should be monitored/quarantined  
- DANGEROUS: The IP is clearly malicious, associated with attacks, or has high abuse scores

ANALYSIS FACTORS:
1. Geographic location (high-risk countries, unusual locations)
2. ISP/Organization type (hosting providers often used for attacks, VPNs, Tor exit nodes)
3. AbuseIPDB confidence score (>50 = suspicious, >80 = dangerous)
4. Number of abuse reports and recent activity
5. ASN reputation (known bad ASNs)

RESPONSE FORMAT (JSON only, no other text):
{
  "status": "CLEAN|SUSPICIOUS|DANGEROUS",
  "confidence": 0.0-1.0,
  "reason": "Brief explanation of the decision",
  "indicators": ["list", "of", "specific", "threat", "indicators"],
  "recommended_action": "What should be done with this IP"
}

Be conservative: when in doubt between CLEAN and SUSPICIOUS, choose SUSPICIOUS.
Between SUSPICIOUS and DANGEROUS, use the abuse score as primary indicator.`

// NewAnalyzer initializes Genkit with Ollama and registers the analysis flow.
func NewAnalyzer(ctx context.Context, ollamaBaseURL, modelName string) (*Analyzer, error) {
	// Initialize Genkit with Ollama plugin
	g := genkit.Init(ctx, genkit.WithPlugins(&ollama.Ollama{
		ServerAddress: ollamaBaseURL,
	}))

	// Get the Ollama model
	model := ollama.Model(g, modelName)
	if model == nil {
		return nil, fmt.Errorf("model %q not found in Ollama", modelName)
	}

	a := &Analyzer{
		g:     g,
		model: model,
	}

	// Define the Genkit flow
	a.flow = genkit.DefineFlow(g, "analyzeIP",
		func(ctx context.Context, input *AnalysisInput) (*AnalysisResult, error) {
			return a.runAnalysis(ctx, input)
		},
	)

	log.Printf("[FLOW] ✅ Genkit flow 'analyzeIP' registered with model: %s", modelName)
	return a, nil
}

// Analyze runs the IP analysis flow for the given enrichment data.
func (a *Analyzer) Analyze(ctx context.Context, data *enrichment.IPEnrichment) (*AnalysisResult, error) {
	input := &AnalysisInput{
		IP:      data.IP,
		Summary: data.Summary(),
		Data:    data,
	}

	result, err := a.flow.Run(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("flow execution failed: %w", err)
	}

	return result, nil
}

// runAnalysis is the core flow handler that calls the AI model.
func (a *Analyzer) runAnalysis(ctx context.Context, input *AnalysisInput) (*AnalysisResult, error) {
	prompt := fmt.Sprintf("%s\n\n=== IP ANALYSIS REQUEST ===\n%s", systemPrompt, input.Summary)

	log.Printf("[FLOW] 🤖 Sending IP %s to AI model for analysis...", input.IP)

	text, err := genkit.GenerateText(ctx, a.g,
		ai.WithModel(a.model),
		ai.WithPrompt(prompt),
		ai.WithConfig(&ai.GenerationCommonConfig{
			Temperature: 0.1, // Low temperature for consistent, deterministic output
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("model generation failed: %w", err)
	}

	// Parse the JSON response
	result, err := parseAIResponse(text, input.IP)
	if err != nil {
		log.Printf("[FLOW] ⚠️  Failed to parse AI response for %s: %v", input.IP, err)
		log.Printf("[FLOW] Raw response: %s", text)
		// Fallback: treat as suspicious if parsing fails
		return &AnalysisResult{
			IP:                input.IP,
			Status:            StatusSuspicious,
			Confidence:        0.5,
			Reason:            "Could not parse AI response; defaulting to SUSPICIOUS for safety",
			Indicators:        []string{"parse_error"},
			RecommendedAction: "Manual review required",
		}, nil
	}

	log.Printf("[FLOW] ✅ Analysis complete for %s: %s (confidence: %.2f)", input.IP, result.Status, result.Confidence)
	return result, nil
}

// parseAIResponse extracts the JSON verdict from the AI model's text output.
func parseAIResponse(text, ip string) (*AnalysisResult, error) {
	// Find JSON block in response (model may include extra text)
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON object found in response")
	}

	jsonStr := text[start : end+1]

	var result AnalysisResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	// Set IP from input (in case model doesn't include it)
	result.IP = ip

	// Validate status
	switch result.Status {
	case StatusClean, StatusSuspicious, StatusDangerous:
		// valid
	default:
		return nil, fmt.Errorf("invalid status value: %q", result.Status)
	}

	return &result, nil
}
