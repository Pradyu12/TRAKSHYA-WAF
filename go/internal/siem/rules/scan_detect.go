package siem

import (
	"time"

	"github.com/kalki-waf/kalki-api/pkg/models"
)

type RapidScanRule struct{}

func (r *RapidScanRule) Name() string {
	return "rapid_scan_detection"
}

func (r *RapidScanRule) Evaluate(events []models.Incident) *models.Incident {
	windowStart := time.Now().Add(-10 * time.Second)
	var recentEvents int

	for _, ev := range events {
		if ev.Timestamp.After(windowStart) {
			recentEvents++
		}
	}

	if recentEvents >= 20 {
		return &models.Incident{
			Type:       "siem_alert",
			AttackType: "rapid_scan",
			Severity:   "high",
			Message:    "Rapid scan detected - unusually high request rate",
			Source:     "siem",
			Timestamp:  time.Now(),
		}
	}
	return nil
}
