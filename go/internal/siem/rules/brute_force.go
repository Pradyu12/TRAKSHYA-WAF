package siem

import (
	"time"

	"github.com/trakshya/trakshya-api/pkg/models"
)

type BruteForceRule struct{}

func (r *BruteForceRule) Name() string {
	return "brute_force_detection"
}

func (r *BruteForceRule) Evaluate(events []models.Incident) *models.Incident {
	ipCounts := make(map[string]int)
	for _, ev := range events {
		if ev.Type == "attack_blocked" && ev.ClientIP != "" {
			ipCounts[ev.ClientIP]++
		}
	}

	for ip, count := range ipCounts {
		if count >= 10 {
			return &models.Incident{
				Type:      "siem_alert",
				AttackType: "brute_force",
				ClientIP:  ip,
				Severity:  "critical",
				Message:   "Brute force attack detected",
				Source:    "siem",
				Timestamp: time.Now(),
			}
		}
	}
	return nil
}
