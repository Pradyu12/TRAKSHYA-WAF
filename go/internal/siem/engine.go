package siem

import (
	"log"
	"sync"
	"time"

	"github.com/trakshya/trakshya-api/internal/api"
	"github.com/trakshya/trakshya-api/pkg/models"
	_ "github.com/trakshya/trakshya-api/internal/siem/rules"
)

type CorrelationEngine struct {
	mu       sync.RWMutex
	rules    []CorrelationRule
	events   []models.Incident
	window   time.Duration
	maxEvents int
}

type CorrelationRule interface {
	Name() string
	Evaluate(events []models.Incident) *models.Incident
}

func NewCorrelationEngine(window time.Duration, maxEvents int) *CorrelationEngine {
	return &CorrelationEngine{
		rules: []CorrelationRule{
			&BruteForceRule{},
			&PortScanRule{},
			&XssWaveRule{},
			&SqlInjectionWaveRule{},
			&RapidScanRule{},
			&ShellActivityRule{},
			&DataExfilRule{},
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
