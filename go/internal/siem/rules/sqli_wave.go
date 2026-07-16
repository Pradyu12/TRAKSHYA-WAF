package siem

import (
	"time"

	"github.com/trakshya/trakshya-api/pkg/models"
)

type SqlInjectionWaveRule struct{}

func (r *SqlInjectionWaveRule) Name() string {
	return "sqli_wave_detection"
}

func (r *SqlInjectionWaveRule) Evaluate(events []models.Incident) *models.Incident {
	count := 0
	for _, ev := range events {
		if ev.AttackType == "sql_injection" {
			count++
		}
	}

	if count >= 5 {
		return &models.Incident{
			Type:       "siem_alert",
			AttackType: "sqli_wave",
			Severity:   "critical",
			Message:    "SQL injection attack wave detected",
			Source:     "siem",
			Timestamp:  time.Now(),
		}
	}
	return nil
}
