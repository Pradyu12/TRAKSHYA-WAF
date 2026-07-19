package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/trakshya/trakshya-api/pkg/models"
)

func boolInt(v bool) int {
	if v { return 1 }
	return 0
}

type Postgres struct {
	db *sql.DB
}

func NewPostgres(databaseURL string) (*Postgres, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres database: %w", err)
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping postgres: %w", err)
	}
	return &Postgres{db: db}, nil
}

func (s *Postgres) Close() error { return s.db.Close() }
func (s *Postgres) IsHealthy() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.db.PingContext(ctx) == nil
}
func (s *Postgres) GetDB() *sql.DB { return s.db }

func (s *Postgres) RunMigrations() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS incidents (
			id TEXT PRIMARY KEY,
			incident_type TEXT NOT NULL,
			rule_id TEXT,
			attack_type TEXT,
			client_ip TEXT NOT NULL,
			path TEXT,
			method TEXT,
			severity TEXT NOT NULL,
			message TEXT,
			source TEXT,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			acknowledged INTEGER DEFAULT 0,
			acked_at TIMESTAMP,
			acked_by TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS rules (
			id TEXT PRIMARY KEY,
			pattern TEXT NOT NULL,
			severity TEXT NOT NULL,
			category TEXT NOT NULL,
			description TEXT,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS blacklist (
			id TEXT PRIMARY KEY,
			ip TEXT NOT NULL UNIQUE,
			reason TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP
		)`,
	}
	for _, m := range stmts {
		if _, err := s.db.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}
	return nil
}

func (s *Postgres) CreateIncident(inc *models.Incident) error {
	_, err := s.db.Exec(
		`INSERT INTO incidents (id, incident_type, rule_id, attack_type, client_ip, path, method, severity, message, source, timestamp, acknowledged)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		inc.ID, inc.Type, inc.RuleID, inc.AttackType, inc.ClientIP, inc.Path, inc.Method, inc.Severity, inc.Message, inc.Source, inc.Timestamp, 0,
	)
	return err
}

func (s *Postgres) ListIncidents() ([]models.Incident, error) {
	rows, err := s.db.Query(
		`SELECT id, incident_type, rule_id, attack_type, client_ip, path, method, severity, message, source, timestamp, acknowledged
		FROM incidents ORDER BY timestamp DESC LIMIT 100`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.Incident
	for rows.Next() {
		var inc models.Incident
		if err := rows.Scan(&inc.ID, &inc.Type, &inc.RuleID, &inc.AttackType, &inc.ClientIP, &inc.Path, &inc.Method, &inc.Severity, &inc.Message, &inc.Source, &inc.Timestamp, &inc.Acknowledged); err != nil {
			return nil, err
		}
		out = append(out, inc)
	}
	return out, nil
}

func (s *Postgres) AcknowledgeIncident(id string) error {
	result, err := s.db.Exec("UPDATE incidents SET acknowledged = 1, acked_at = NOW(), acked_by = 'api' WHERE id = $1", id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("incident not found: %s", id)
	}
	return nil
}

func (s *Postgres) CreateAgent(agent *models.Agent) error {
	_, err := s.db.Exec(`INSERT INTO system_config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, "agent:"+agent.ID, agent.Name)
	return err
}

func (s *Postgres) ListAgents() ([]models.Agent, error) {
	return nil, fmt.Errorf("not implemented for postgres schema")
}

func (s *Postgres) CreateRule(r *models.Rule) error {
	_, err := s.db.Exec(
		`INSERT INTO rules (id, pattern, severity, category, description, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
		r.RuleID, r.Pattern, r.Severity, r.Category, r.Description, boolInt(r.IsActive),
	)
	return err
}

func (s *Postgres) ListRules() ([]models.Rule, error) {
	rows, err := s.db.Query(`SELECT id, pattern, severity, category, description, enabled, created_at, updated_at FROM rules ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []models.Rule
	for rows.Next() {
		var r models.Rule
		var enabled int
		if err := rows.Scan(&r.RuleID, &r.Pattern, &r.Severity, &r.Category, &r.Description, &enabled, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.IsActive = enabled != 0
		r.BlocksCount = 0
		rules = append(rules, r)
	}
	return rules, nil
}

func (s *Postgres) ToggleRule(id string, isActive bool) error {
	result, err := s.db.Exec("UPDATE rules SET enabled = $1, updated_at = NOW() WHERE id = $2", boolInt(isActive), id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("rule not found: %s", id)
	}
	return nil
}

func (s *Postgres) DeleteRule(id string) error {
	result, err := s.db.Exec("DELETE FROM rules WHERE id = $1", id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("rule not found: %s", id)
	}
	return nil
}

func (s *Postgres) CreateBlacklistEntry(entry *models.BlacklistEntry) error {
	_, err := s.db.Exec("INSERT INTO blacklist (id, ip, reason) VALUES ($1, $2, $3) ON CONFLICT (ip) DO UPDATE SET reason = EXCLUDED.reason", entry.ID, entry.IPAddress, entry.Reason)
	return err
}

func (s *Postgres) ListBlacklist() ([]models.BlacklistEntry, error) {
	rows, err := s.db.Query("SELECT id, ip, reason, created_at FROM blacklist ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []models.BlacklistEntry
	for rows.Next() {
		var e models.BlacklistEntry
		if err := rows.Scan(&e.ID, &e.IPAddress, &e.Reason, &e.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (s *Postgres) DeleteBlacklistEntry(ip string) error {
	result, err := s.db.Exec("DELETE FROM blacklist WHERE ip = $1", ip)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("blacklist entry not found: %s", ip)
	}
	return nil
}

func (s *Postgres) GetSIEMStats() (*models.SIEMStats, error) {
	stats := &models.SIEMStats{BySeverity: make(map[string]int), ByType: make(map[string]int)}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM incidents").Scan(&stats.Total); err != nil {
		return nil, err
	}
	rows, err := s.db.Query("SELECT severity, COUNT(*) as cnt FROM incidents GROUP BY severity")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var cnt int
			if err := rows.Scan(&sev, &cnt); err != nil {
				continue
			}
			stats.BySeverity[sev] = cnt
		}
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM incidents WHERE acknowledged = 0").Scan(&stats.Unacknowledged); err != nil {
		return nil, err
	}
	return stats, nil
}

func (s *Postgres) GetSIEMAlerts(limit int) ([]models.SIEMAlert, error) {
	rows, err := s.db.Query(`SELECT id, rule_id, severity, message, client_ip, path, timestamp, acknowledged FROM incidents ORDER BY timestamp DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []models.SIEMAlert
	for rows.Next() {
		var a models.SIEMAlert
		var ts sql.NullTime
		var acked int
		if err := rows.Scan(&a.ID, &a.RuleName, &a.Severity, &a.Description, &a.SourceIP, &a.Path, &ts, &acked); err != nil {
			return nil, err
		}
		if ts.Valid {
			a.Timestamp = ts.Time.Format(time.RFC3339)
		}
		a.Acked = acked != 0
		alerts = append(alerts, a)
	}
	return alerts, nil
}

func (s *Postgres) AckSIEMAlert(id int) error {
	_, err := s.db.Exec("UPDATE incidents SET acknowledged = 1, acked_at = NOW(), acked_by = 'siem' WHERE id = $1", id)
	return err
}

func (s *Postgres) GetDashboardStats() (*models.DashboardStats, error) {
	stats := &models.DashboardStats{}
	s.db.QueryRow("SELECT COUNT(*) FROM incidents").Scan(&stats.TotalRequests)
	s.db.QueryRow("SELECT COUNT(*) FROM incidents WHERE severity IN ('critical', 'high')").Scan(&stats.BlockedRequests)
	s.db.QueryRow("SELECT COUNT(DISTINCT client_ip) FROM incidents WHERE timestamp > NOW() - INTERVAL '1 hour'").Scan(&stats.ActiveIPs)
	s.db.QueryRow("SELECT COUNT(*) FROM incidents WHERE timestamp > CURRENT_TIMESTAMP - INTERVAL '1 day'").Scan(&stats.IncidentsToday)
	s.db.QueryRow("SELECT COUNT(*) FROM system_config").Scan(&stats.AgentsOnline)
	s.db.QueryRow("SELECT COUNT(*) FROM rules WHERE enabled = 1").Scan(&stats.RuleCount)

	rows, err := s.db.Query(`SELECT attack_type, COUNT(*) as cnt FROM incidents WHERE attack_type != '' GROUP BY attack_type ORDER BY cnt DESC LIMIT 10`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ac models.AttackCount
			if err := rows.Scan(&ac.AttackType, &ac.Count); err != nil {
				continue
			}
			stats.TopAttacks = append(stats.TopAttacks, ac)
		}
	}
	incidents, _ := s.ListIncidents()
	if len(incidents) > 10 {
		incidents = incidents[:10]
	}
	stats.RecentIncidents = incidents
	return stats, nil
}

func (s *Postgres) GetGeoData() (*models.GeoStats, error) {
	rows, err := s.db.Query(`SELECT client_ip, COUNT(*) as cnt, MAX(timestamp) as last_seen FROM incidents WHERE client_ip != '' GROUP BY client_ip ORDER BY cnt DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := &models.GeoStats{Locations: []models.GeoLocation{}}
	for rows.Next() {
		var ip string
		var count int
		var lastSeen sql.NullTime
		if err := rows.Scan(&ip, &count, &lastSeen); err != nil {
			continue
		}
		stats.Locations = append(stats.Locations, models.GeoLocation{
			IP:       ip,
			Count:    count,
			LastSeen: lastSeen.Time.Format(time.RFC3339),
		})
	}
	stats.TotalIPs = len(stats.Locations)
	return stats, nil
}
