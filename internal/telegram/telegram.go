// Package telegram provides Telegram Bot API integration for sending
// critical security alerts when dangerous IPs are detected.
package telegram

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Bot manages Telegram Bot API communications.
type Bot struct {
	token   string
	chatID  string
	client  *http.Client
	baseURL string
}

// NewBot creates a new Telegram Bot instance.
func NewBot(token, chatID string) *Bot {
	return &Bot{
		token:   token,
		chatID:  chatID,
		baseURL: "https://api.telegram.org",
		client:  &http.Client{Timeout: 15 * time.Second},
	}
}

// SendDangerAlert sends a critical alert message for a dangerous IP.
func (b *Bot) SendDangerAlert(ip, reason string, confidence float64, indicators []string) error {
	indicatorList := ""
	for _, ind := range indicators {
		indicatorList += fmt.Sprintf("  • %s\n", ind)
	}
	if indicatorList == "" {
		indicatorList = "  • No specific indicators\n"
	}

	message := fmt.Sprintf(
		"[CRITICAL SECURITY ALERT]\n\n"+
			"Dangerous IP Detected & Blocked!\n\n"+
			"IP Address: `%s`\n"+
			"Status: DANGEROUS\n"+
			"Confidence: %.0f%%\n\n"+
			"Reason:\n%s\n\n"+
			"Threat Indicators:\n%s\n"+
			"Action Taken: IP added to block list\n\n"+
			"Detected at: %s\n\n"+
			"Please review and take additional protective measures if necessary.",
		ip,
		confidence*100,
		reason,
		indicatorList,
		time.Now().Format("2006-01-02 15:04:05 MST"),
	)

	return b.sendMessage(message)
}

// SendSuspiciousAlert sends a warning message for a suspicious IP.
func (b *Bot) SendSuspiciousAlert(ip, reason string, confidence float64) error {
	message := fmt.Sprintf(
		"[Suspicious IP Quarantined]\n\n"+
			"IP Address: `%s`\n"+
			"Status: SUSPICIOUS\n"+
			"Confidence: %.0f%%\n\n"+
			"Reason: %s\n\n"+
			"Action Taken: IP added to quarantine\n"+
			"Detected at: %s",
		ip,
		confidence*100,
		reason,
		time.Now().Format("2006-01-02 15:04:05 MST"),
	)

	return b.sendMessage(message)
}

// sendMessage sends a message to the configured Telegram chat.
func (b *Bot) sendMessage(text string) error {
	if b.token == "" || b.chatID == "" {
		log.Printf("[TELEGRAM] [WARNING] Token or ChatID not configured, skipping notification")
		return nil
	}

	apiURL := fmt.Sprintf("%s/bot%s/sendMessage", b.baseURL, b.token)

	data := url.Values{}
	data.Set("chat_id", b.chatID)
	data.Set("text", text)
	data.Set("parse_mode", "Markdown")
	data.Set("disable_web_page_preview", "true")

	resp, err := b.client.PostForm(apiURL, data)
	if err != nil {
		return fmt.Errorf("telegram request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned status %d", resp.StatusCode)
	}

	log.Printf("[TELEGRAM] [SUCCESS] Alert sent successfully")
	return nil
}

// Enabled returns true if the bot is properly configured.
func (b *Bot) Enabled() bool {
	return b.token != "" && b.chatID != "" &&
		!strings.HasPrefix(b.token, "YOUR_") &&
		!strings.HasPrefix(b.chatID, "YOUR_")
}
