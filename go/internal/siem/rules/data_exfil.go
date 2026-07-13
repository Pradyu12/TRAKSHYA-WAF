package siem

import (
	"time"

	"github.com/kalki-waf/kalki-api/pkg/models"
)

type DataExfilRule struct{}

func (r *DataExfilRule) Name() string {
	return "data_exfiltration_detection"
}

func (r *DataExfilRule) Evaluate(events []models.Incident) *models.Incident {
	ipLargeRequests := make(map[string]int64)
	for _, ev := range events {
		if ev.Type == "request" {
			ipLargeRequests[ev.ClientIP]++
		}
	}

	for ip, count := range ipLargeRequests {
		if count >= 50 {
			return &models.Incident{
				Type:       "siem_alert",
				AttackType: "data_exfiltration",
				ClientIP:   ip,
				Severity:   "high",
				Message:    "Possible data exfiltration - high request volume from single IP",
				Source:     "siem",
				Timestamp:  time.Now(),
			}
		}
	}
	return nil
}
