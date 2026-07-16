package webhooks

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type WebhookConfig struct {
	SlackWebhookURL  string `json:"slack_webhook_url"`
	DiscordWebhookURL string `json:"discord_webhook_url"`
}

type Dispatcher struct {
	config *WebhookConfig
	client *http.Client
}

func NewDispatcher(config *WebhookConfig) *Dispatcher {
	return &Dispatcher{
		config: config,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

type SlackMessage struct {
	Text        string `json:"text"`
	Username    string `json:"username,omitempty"`
	IconEmoji   string `json:"icon_emoji,omitempty"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
}

type SlackAttachment struct {
	Color  string `json:"color"`
	Title  string `json:"title"`
	Text   string `json:"text"`
	Fields []SlackField `json:"fields"`
}

type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

type DiscordMessage struct {
	Content    string          `json:"content"`
	Username   string          `json:"username,omitempty"`
	Embeds     []DiscordEmbed `json:"embeds,omitempty"`
}

type DiscordEmbed struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Color       int    `json:"color"`
	Timestamp   string `json:"timestamp"`
}

func (d *Dispatcher) SendAlert(title, message, severity, source string) {
	if d.config.SlackWebhookURL != "" {
		d.sendSlack(title, message, severity, source)
	}
	if d.config.DiscordWebhookURL != "" {
		d.sendDiscord(title, message, severity, source)
	}
}

func (d *Dispatcher) sendSlack(title, message, severity, source string) {
	color := "good"
	switch severity {
	case "critical":
		color = "danger"
	case "high":
		color = "warning"
	case "medium":
		color = "#ffcc00"
	}

	msg := SlackMessage{
		Username:  "TRAKSHYA-WAF",
		IconEmoji: ":shield:",
		Attachments: []SlackAttachment{{
			Color: color,
			Title: title,
			Text:  message,
			Fields: []SlackField{
				{Title: "Severity", Value: severity, Short: true},
				{Title: "Source", Value: source, Short: true},
			},
		}},
	}

	payload, _ := json.Marshal(msg)
	resp, err := d.client.Post(d.config.SlackWebhookURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("Slack webhook error: %v", err)
		return
	}
	defer resp.Body.Close()
}

func (d *Dispatcher) sendDiscord(title, message, severity, source string) {
	color := 0x00FF00
	switch severity {
	case "critical":
		color = 0xFF0000
	case "high":
		color = 0xFFA500
	case "medium":
		color = 0xFFCC00
	}

	msg := DiscordMessage{
		Username: "TRAKSHYA-WAF",
		Embeds: []DiscordEmbed{{
			Title:       title,
			Description: message,
			Color:       color,
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
		}},
	}

	payload, _ := json.Marshal(msg)
	resp, err := d.client.Post(d.config.DiscordWebhookURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("Discord webhook error: %v", err)
		return
	}
	defer resp.Body.Close()
}

func (d *Dispatcher) IsConfigured() bool {
	return d.config.SlackWebhookURL != "" || d.config.DiscordWebhookURL != ""
}
