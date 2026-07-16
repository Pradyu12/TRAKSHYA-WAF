package siem

import (
	"time"

	"github.com/trakshya/trakshya-api/pkg/models"
)

type ShellActivityRule struct{}

func (r *ShellActivityRule) Name() string {
	return "suspicious_shell_activity"
}

func (r *ShellActivityRule) Evaluate(events []models.Incident) *models.Incident {
	for _, ev := range events {
		if ev.AttackType == "command_injection" {
			return &models.Incident{
				Type:       "siem_alert",
				AttackType: "shell_activity",
				ClientIP:   ev.ClientIP,
				Severity:   "critical",
				Message:    "Suspicious shell command execution detected",
				Source:     "siem",
				Timestamp:  time.Now(),
			}
		}
	}
	return nil
}
