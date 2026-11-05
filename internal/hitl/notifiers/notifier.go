package notifiers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type NotificationPayload struct {
	RequestID      string   `json:"request_id"`
	AgentID        string   `json:"agent_id"`
	TaskID         string   `json:"task_id"`
	Service        string   `json:"service"`
	Action         string   `json:"action"`
	Reason         string   `json:"reason"`
	PayloadSummary string   `json:"payload_summary"`
	ApprovalURL    string   `json:"approval_url"`
	Approvers      []string `json:"approvers"`
}

type Dispatcher struct {
	telegramBot  string
	telegramChat string
	discordHook  string
	slackHook    string
	client       *http.Client
}

func NewDispatcher(tgBot, tgChat, discord, slack string) *Dispatcher {
	return &Dispatcher{
		telegramBot:  tgBot,
		telegramChat: tgChat,
		discordHook:  discord,
		slackHook:    slack,
		client:       &http.Client{Timeout: 8 * time.Second},
	}
}

func (d *Dispatcher) Dispatch(p *NotificationPayload) {
	go func() {
		if d.telegramBot != "" && d.telegramChat != "" {
			if err := d.sendTelegram(p); err != nil {
				log.Printf("[notifier] telegram send failed: %v", err)
			}
		}
		if d.discordHook != "" {
			if err := d.sendDiscord(p); err != nil {
				log.Printf("[notifier] discord send failed: %v", err)
			}
		}
		if d.slackHook != "" {
			if err := d.sendSlack(p); err != nil {
				log.Printf("[notifier] slack send failed: %v", err)
			}
		}
	}()
}

func (d *Dispatcher) sendTelegram(p *NotificationPayload) error {
	msg := fmt.Sprintf(
		"🚨 *Aegis HITL Escalation Required*\n\n"+
			"*Agent:* `%s`\n"+
			"*Service:* `%s`\n"+
			"*Action:* `%s`\n"+
			"*Reason:* %s\n\n"+
			"*Payload:* ```json\n%s\n```\n\n"+
			"👉 [Review & Approve with Passkey](%s)",
		p.AgentID, p.Service, p.Action, p.Reason, p.PayloadSummary, p.ApprovalURL,
	)

	body, _ := json.Marshal(map[string]interface{}{
		"chat_id":    d.telegramChat,
		"text":       msg,
		"parse_mode": "Markdown",
		"reply_markup": map[string]interface{}{
			"inline_keyboard": [][]map[string]string{
				{
					{"text": "✅ Approve / Review", "url": p.ApprovalURL},
				},
			},
		},
	})

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", d.telegramBot)
	resp, err := d.client.Post(apiURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (d *Dispatcher) sendDiscord(p *NotificationPayload) error {
	embed := map[string]interface{}{
		"title":       "🛡️ Aegis HITL Action Escalation",
		"description": fmt.Sprintf("**Agent:** `%s`\n**Service:** `%s`\n**Action:** `%s`", p.AgentID, p.Service, p.Action),
		"color":       16711680, // Red/Alert
		"fields": []map[string]interface{}{
			{"name": "Agent Reason", "value": p.Reason, "inline": false},
			{"name": "Payload Preview", "value": "```json\n" + p.PayloadSummary + "\n```", "inline": false},
			{"name": "Action Required", "value": fmt.Sprintf("[Click here to sign off with Passkey](%s)", p.ApprovalURL), "inline": false},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	body, _ := json.Marshal(map[string]interface{}{
		"content": "⚠️ **Aegis Approval Request**",
		"embeds":  []interface{}{embed},
	})

	resp, err := d.client.Post(d.discordHook, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (d *Dispatcher) sendSlack(p *NotificationPayload) error {
	body, _ := json.Marshal(map[string]interface{}{
		"blocks": []interface{}{
			map[string]interface{}{
				"type": "header",
				"text": map[string]string{"type": "plain_text", "text": "🛡️ Aegis HITL Action Escalation"},
			},
			map[string]interface{}{
				"type": "section",
				"fields": []map[string]string{
					{"type": "mrkdwn", "text": fmt.Sprintf("*Agent:*\n`%s`", p.AgentID)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Service:*\n`%s`", p.Service)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Action:*\n`%s`", p.Action)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Task ID:*\n`%s`", p.TaskID)},
				},
			},
			map[string]interface{}{
				"type": "section",
				"text": map[string]string{"type": "mrkdwn", "text": fmt.Sprintf("*Reason:* %s", p.Reason)},
			},
			map[string]interface{}{
				"type": "actions",
				"elements": []interface{}{
					map[string]interface{}{
						"type":  "button",
						"text":  map[string]string{"type": "plain_text", "text": "Review & Sign with Passkey"},
						"url":   p.ApprovalURL,
						"style": "primary",
					},
				},
			},
		},
	})

	resp, err := d.client.Post(d.slackHook, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
