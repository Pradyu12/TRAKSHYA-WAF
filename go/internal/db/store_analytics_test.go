package db

import (
	"testing"
	"time"

	"github.com/trakshya/trakshya-api/pkg/models"
)

func TestAnalyticsQueries(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/analytics.duckdb"

	store, err := NewStore(dbPath, func(incident *models.Incident) {})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	events := []RawEvent{
		{Timestamp: now, SourceIP: "1.1.1.1", Method: "GET", Host: "example.com", Path: "/", StatusCode: 200, Blocked: false, AttackType: "", RuleName: "", Action: "allow", BytesSent: 100, BytesReceived: 0, LatencyMs: 10, UserAgent: "ua1"},
		{Timestamp: now, SourceIP: "2.2.2.2", Method: "POST", Host: "example.com", Path: "/login", StatusCode: 403, Blocked: true, AttackType: "brute_force", RuleName: "auth", Action: "block", BytesSent: 50, BytesReceived: 0, LatencyMs: 20, UserAgent: "ua2"},
		{Timestamp: now, SourceIP: "1.1.1.1", Method: "GET", Host: "example.com", Path: "/admin", StatusCode: 200, Blocked: false, AttackType: "sqli", RuleName: "sqli-rule", Action: "allow", BytesSent: 200000000, BytesReceived: 0, LatencyMs: 30, UserAgent: "ua1"},
	}
	for _, e := range events {
		store.Ingest(e)
	}
	store.drainBuffer()

	stats, err := store.GetEventStats()
	if err != nil {
		t.Fatalf("GetEventStats: %v", err)
	}
	if stats.TotalEvents != 3 {
		t.Fatalf("total events = %d, want 3", stats.TotalEvents)
	}
	if stats.BlockedEvents != 1 {
		t.Fatalf("blocked events = %d, want 1", stats.BlockedEvents)
	}
	if len(stats.ByAttackType) != 2 {
		t.Fatalf("by_attack_type len = %d, want 2", len(stats.ByAttackType))
	}

	attackers, err := store.GetTopAttackers(5)
	if err != nil {
		t.Fatalf("GetTopAttackers: %v", err)
	}
	if len(attackers) != 2 {
		t.Fatalf("top attackers len = %d, want 2", len(attackers))
	}

	countries, err := store.GetCountryStats()
	if err != nil {
		t.Fatalf("GetCountryStats: %v", err)
	}
	if len(countries) != 0 {
		t.Fatalf("countries len = %d, want 0", len(countries))
	}

	rules, err := store.GetRuleTriggers()
	if err != nil {
		t.Fatalf("GetRuleTriggers: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("rule triggers len = %d, want 2", len(rules))
	}

	deleted, err := store.PruneOldEvents(0)
	if err != nil {
		t.Fatalf("PruneOldEvents: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("pruned = %d, want 0", deleted)
	}
}

func TestAnalyticsLiveUpdates(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/analytics.duckdb"

	received := 0
	store, err := NewStore(dbPath, func(incident *models.Incident) {
		received++
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	for i := 0; i < 6; i++ {
		store.Ingest(RawEvent{
			Timestamp:  now,
			SourceIP:   "10.0.0.1",
			Method:     "GET",
			Host:       "a.com",
			Path:       "/x",
			StatusCode: 200,
			Blocked:    false,
			AttackType: "xss",
			RuleName:   "xss-1",
			Action:     "allow",
			BytesSent:  10000000,
			LatencyMs:  1,
			UserAgent:  "ua",
		})
	}
	store.drainBuffer()

	incidents := store.RunCorrelationRules()
	if len(incidents) == 0 {
		t.Fatal("expected correlation incident")
	}
	found := false
	for _, inc := range incidents {
		if inc.AttackType == "xss_wave" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected xss_wave incident, got: %v", incidents)
	}
	if received != 1 {
		t.Fatalf("onIncident callbacks = %d, want 1", received)
	}
}
