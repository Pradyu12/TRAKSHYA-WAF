package siem

import (
	"time"

	"github.com/kalki-waf/kalki-api/pkg/models"
)

type XssWaveRule struct{}

func (r *XssWaveRule) Name() string {
	return "xss_wave_detection"
}

func (r *XssWaveRule) Evaluate(events []models.Incident) *models.Incident {
	count := 0
	for _, ev := range events {
		if ev.AttackType == "xss" {
			count++
		}
	}

	if count >= 5 {
		return &models.Incident{
			Type:       "siem_alert",
			AttackType: "xss_wave",
			Severity:   "high",
			Message:    "XSS attack wave detected across multiple vectors",
			Source:     "siem",
			Timestamp:  time.Now(),
		}
	}
	return nil
}
