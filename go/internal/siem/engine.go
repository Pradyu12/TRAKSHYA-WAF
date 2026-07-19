package siem

import (
	"log"
	"sync"
	"time"

	"github.com/trakshya/trakshya-api/internal/api"
	"github.com/trakshya/trakshya-api/pkg/models"
)

type CorrelationRule interface {
	Name() string
	Evaluate(events []models.Incident) *models.Incident
}

type bruteForceRule struct{}

func (r *bruteForceRule) Name() string { return "brute_force_detection" }
func (r *bruteForceRule) Evaluate(events []models.Incident) *models.Incident {
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

type portScanRule struct{}

func (r *portScanRule) Name() string { return "port_scan_detection" }
func (r *portScanRule) Evaluate(events []models.Incident) *models.Incident {
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

type xssWaveRule struct{}

func (r *xssWaveRule) Name() string { return "xss_wave_detection" }
func (r *xssWaveRule) Evaluate(events []models.Incident) *models.Incident {
	count := 0
	for _, ev := range events {
		if ev.AttackType == "xss" {
			count++
		}
	}
	if count >= 5 {
		return &models.Incident{
			Type:      "siem_alert",
			AttackType: "xss_wave",
			Severity:  "high",
			Message:   "XSS attack wave detected across multiple vectors",
			Source:    "siem",
			Timestamp: time.Now(),
		}
	}
	return nil
}

type sqlInjectionWaveRule struct{}

func (r *sqlInjectionWaveRule) Name() string { return "sqli_wave_detection" }
func (r *sqlInjectionWaveRule) Evaluate(events []models.Incident) *models.Incident {
	count := 0
	for _, ev := range events {
		if ev.AttackType == "sql_injection" {
			count++
		}
	}
	if count >= 5 {
		return &models.Incident{
			Type:      "siem_alert",
			AttackType: "sqli_wave",
			Severity:  "critical",
			Message:   "SQL injection attack wave detected",
			Source:    "siem",
			Timestamp: time.Now(),
		}
	}
	return nil
}

type rapidScanRule struct{}

func (r *rapidScanRule) Name() string { return "rapid_scan_detection" }
func (r *rapidScanRule) Evaluate(events []models.Incident) *models.Incident {
	windowStart := time.Now().Add(-10 * time.Second)
	var recentEvents int
	for _, ev := range events {
		if ev.Timestamp.After(windowStart) {
			recentEvents++
		}
	}
	if recentEvents >= 20 {
		return &models.Incident{
			Type:      "siem_alert",
			AttackType: "rapid_scan",
			Severity:  "high",
			Message:   "Rapid scan detected - unusually high request rate",
			Source:    "siem",
			Timestamp: time.Now(),
		}
	}
	return nil
}

type shellActivityRule struct{}

func (r *shellActivityRule) Name() string { return "suspicious_shell_activity" }
func (r *shellActivityRule) Evaluate(events []models.Incident) *models.Incident {
	for _, ev := range events {
		if ev.AttackType == "command_injection" {
			return &models.Incident{
				Type:      "siem_alert",
				AttackType: "shell_activity",
				ClientIP:   ev.ClientIP,
				Severity:  "critical",
				Message:   "Suspicious shell command execution detected",
				Source:    "siem",
				Timestamp: time.Now(),
			}
		}
	}
	return nil
}

type dataExfilRule struct{}

func (r *dataExfilRule) Name() string { return "data_exfiltration_detection" }
func (r *dataExfilRule) Evaluate(events []models.Incident) *models.Incident {
	ipLargeRequests := make(map[string]int64)
	for _, ev := range events {
		if ev.Type == "request" {
			ipLargeRequests[ev.ClientIP]++
		}
	}
	for ip, count := range ipLargeRequests {
		if count >= 50 {
			return &models.Incident{
				Type:      "siem_alert",
				AttackType: "data_exfiltration",
				ClientIP:   ip,
				Severity:  "high",
				Message:   "Possible data exfiltration - high request volume from single IP",
				Source:    "siem",
				Timestamp: time.Now(),
			}
		}
	}
	return nil
}

type CorrelationEngine struct {
	mu       sync.RWMutex
	rules    []CorrelationRule
	events   []models.Incident
	window   time.Duration
	maxEvents int
}

func NewCorrelationEngine(window time.Duration, maxEvents int) *CorrelationEngine {
	return &CorrelationEngine{
		rules: []CorrelationRule{
			&bruteForceRule{},
			&portScanRule{},
			&xssWaveRule{},
			&sqlInjectionWaveRule{},
			&rapidScanRule{},
			&shellActivityRule{},
			&dataExfilRule{},
		},
		window:    window,
		maxEvents: maxEvents,
	}
}

func (e *CorrelationEngine) Ingest(event models.Incident) *models.Incident {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.events = append(e.events, event)
	cutoff := time.Now().Add(-e.window)
	var filtered []models.Incident
	for _, ev := range e.events {
		if ev.Timestamp.After(cutoff) {
			filtered = append(filtered, ev)
		}
	}
	e.events = filtered

	if len(e.events) > e.maxEvents {
		e.events = e.events[len(e.events)-e.maxEvents:]
	}

	for _, rule := range e.rules {
		if alert := rule.Evaluate(e.events); alert != nil {
			log.Printf("SIEM alert: %s - %s", alert.Type, alert.Message)
			return alert
		}
	}

	return nil
}

func (e *CorrelationEngine) Start(a *api.Server) {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			e.mu.Lock()
			cutoff := time.Now().Add(-e.window)
			var filtered []models.Incident
			for _, ev := range e.events {
				if ev.Timestamp.After(cutoff) {
					filtered = append(filtered, ev)
				}
			}
			e.events = filtered
			e.mu.Unlock()
		}
	}()
}
