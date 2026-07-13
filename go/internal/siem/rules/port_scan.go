package siem

import (
	"time"

	"github.com/kalki-waf/kalki-api/pkg/models"
)

type PortScanRule struct{}

func (r *PortScanRule) Name() string {
	return "port_scan_detection"
}

func (r *PortScanRule) Evaluate(events []models.Incident) *models.Incident {
	ipTargets := make(map[string]map[string]bool)
	for _, ev := range events {
		if ev.Type == "connection" && ev.ClientIP != "" {
			if ipTargets[ev.ClientIP] == nil {
				ipTargets[ev.ClientIP] = make(map[string]bool)
			}
			ipTargets[ev.ClientIP][ev.Path] = true
		}
	}

	for ip, targets := range ipTargets {
		if len(targets) >= 15 {
			return &models.Incident{
				Type:      "siem_alert",
				AttackType: "port_scan",
				ClientIP:  ip,
				Severity:  "high",
				Message:   "Port scan detected",
				Source:    "siem",
				Timestamp: time.Now(),
			}
		}
	}
	return nil
}
