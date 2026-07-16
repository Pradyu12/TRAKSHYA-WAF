package db

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
	"github.com/trakshya/trakshya-api/pkg/models"
)

type SQLite struct {
	db *sql.DB
}

func NewSQLite(path string) (*SQLite, error) {
	db, err := sql.Open("sqlite3", fmt.Sprintf("%s?_journal_mode=WAL&_busy_timeout=5000", path))
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	return &SQLite{db: db}, nil
}

func (s *SQLite) Close() error {
	return s.db.Close()
}

func (s *SQLite) RunMigrations() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS incidents (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			rule_id TEXT,
			attack_type TEXT,
			client_ip TEXT,
			path TEXT,
			method TEXT,
			severity TEXT,
			message TEXT,
			source TEXT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			acknowledged INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS agents (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			ip TEXT,
			version TEXT,
			status TEXT DEFAULT 'active',
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			tags TEXT DEFAULT '[]'
		)`,
		`CREATE TABLE IF NOT EXISTS rules (
			rule_id TEXT PRIMARY KEY,
			identifier TEXT NOT NULL,
			pattern TEXT NOT NULL,
			category TEXT DEFAULT 'Custom',
			severity TEXT DEFAULT 'Medium',
			description TEXT DEFAULT '',
			action TEXT DEFAULT 'Drop',
			is_active INTEGER DEFAULT 1,
			blocks_count INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS blacklist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip_address TEXT NOT NULL UNIQUE,
			reason TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS metrics (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			value REAL NOT NULL,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_incidents_type ON incidents(type)`,
		`CREATE INDEX IF NOT EXISTS idx_blacklist_ip ON blacklist(ip_address)`,
	}

	for _, m := range migrations {
		if _, err := s.db.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}

	return nil
}

func (s *SQLite) CreateIncident(inc *models.Incident) error {
	query := `INSERT INTO incidents (id, type, rule_id, attack_type, client_ip, path, method, severity, message, source, timestamp, acknowledged)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, inc.ID, inc.Type, inc.RuleID, inc.AttackType, inc.ClientIP,
		inc.Path, inc.Method, inc.Severity, inc.Message, inc.Source, inc.Timestamp, inc.Acknowledged)
	return err
}

func (s *SQLite) ListIncidents() ([]models.Incident, error) {
	query := `SELECT id, type, rule_id, attack_type, client_ip, path, method, severity, message, source, timestamp, acknowledged
		FROM incidents ORDER BY timestamp DESC LIMIT 100`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var incidents []models.Incident
	for rows.Next() {
		var inc models.Incident
		if err := rows.Scan(&inc.ID, &inc.Type, &inc.RuleID, &inc.AttackType, &inc.ClientIP,
			&inc.Path, &inc.Method, &inc.Severity, &inc.Message, &inc.Source, &inc.Timestamp, &inc.Acknowledged); err != nil {
			return nil, err
		}
		incidents = append(incidents, inc)
	}
	return incidents, nil
}

func (s *SQLite) AcknowledgeIncident(id string) error {
	result, err := s.db.Exec("UPDATE incidents SET acknowledged = 1 WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("incident not found: %s", id)
	}
	return nil
}

func (s *SQLite) CreateAgent(agent *models.Agent) error {
	query := `INSERT INTO agents (id, name, ip, version, status, last_seen, tags) VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, agent.ID, agent.Name, agent.IP, agent.Version, agent.Status, agent.LastSeen, "[]")
	return err
}

func (s *SQLite) ListAgents() ([]models.Agent, error) {
	rows, err := s.db.Query("SELECT id, name, ip, version, status, last_seen FROM agents ORDER BY last_seen DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []models.Agent
	for rows.Next() {
		var a models.Agent
		if err := rows.Scan(&a.ID, &a.Name, &a.IP, &a.Version, &a.Status, &a.LastSeen); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, nil
}

// Rules CRUD
func (s *SQLite) CreateRule(r *models.Rule) error {
	query := `INSERT INTO rules (rule_id, identifier, pattern, category, severity, description, action, is_active, blocks_count, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, r.RuleID, r.Identifier, r.Pattern, r.Category, r.Severity,
		r.Description, r.Action, boolToInt(r.IsActive), r.BlocksCount, r.CreatedAt)
	return err
}

func (s *SQLite) ListRules() ([]models.Rule, error) {
	rows, err := s.db.Query(`SELECT rule_id, identifier, pattern, category, severity, description, action, is_active, blocks_count, created_at
		FROM rules ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []models.Rule
	for rows.Next() {
		var r models.Rule
		var isActive int
		if err := rows.Scan(&r.RuleID, &r.Identifier, &r.Pattern, &r.Category, &r.Severity,
			&r.Description, &r.Action, &isActive, &r.BlocksCount, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.IsActive = isActive == 1
		rules = append(rules, r)
	}
	return rules, nil
}

func (s *SQLite) ToggleRule(id string, isActive bool) error {
	result, err := s.db.Exec("UPDATE rules SET is_active = ? WHERE rule_id = ?", boolToInt(isActive), id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("rule not found: %s", id)
	}
	return nil
}

func (s *SQLite) DeleteRule(id string) error {
	result, err := s.db.Exec("DELETE FROM rules WHERE rule_id = ?", id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("rule not found: %s", id)
	}
	return nil
}

// Blacklist CRUD
func (s *SQLite) CreateBlacklistEntry(entry *models.BlacklistEntry) error {
	_, err := s.db.Exec("INSERT INTO blacklist (ip_address, reason) VALUES (?, ?)", entry.IPAddress, entry.Reason)
	return err
}

func (s *SQLite) ListBlacklist() ([]models.BlacklistEntry, error) {
	rows, err := s.db.Query("SELECT id, ip_address, reason, created_at FROM blacklist ORDER BY created_at DESC")
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

func (s *SQLite) DeleteBlacklistEntry(ip string) error {
	result, err := s.db.Exec("DELETE FROM blacklist WHERE ip_address = ?", ip)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("blacklist entry not found: %s", ip)
	}
	return nil
}

// SIEM queries (backed by incidents table)
func (s *SQLite) GetSIEMStats() (*models.SIEMStats, error) {
	stats := &models.SIEMStats{
		BySeverity: make(map[string]int),
		ByType:     make(map[string]int),
	}

	s.db.QueryRow("SELECT COUNT(*) FROM incidents").Scan(&stats.Total)

	rows, err := s.db.Query("SELECT severity, COUNT(*) as cnt FROM incidents GROUP BY severity")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var cnt int
			rows.Scan(&sev, &cnt)
			stats.BySeverity[sev] = cnt
		}
	}

	rows2, err := s.db.Query("SELECT attack_type, COUNT(*) as cnt FROM incidents WHERE attack_type != '' GROUP BY attack_type")
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var t string
			var cnt int
			rows2.Scan(&t, &cnt)
			stats.ByType[t] = cnt
		}
	}

	s.db.QueryRow("SELECT COUNT(*) FROM incidents WHERE acknowledged = 0").Scan(&stats.Unacknowledged)

	return stats, nil
}

func (s *SQLite) GetSIEMAlerts(limit int) ([]models.SIEMAlert, error) {
	query := `SELECT rowid, rule_id, severity, message, client_ip, path, timestamp, acknowledged
		FROM incidents ORDER BY timestamp DESC LIMIT ?`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []models.SIEMAlert
	for rows.Next() {
		var a models.SIEMAlert
		var ts string
		var acked int
		if err := rows.Scan(&a.ID, &a.RuleName, &a.Severity, &a.Description, &a.SourceIP, &a.Path, &ts, &acked); err != nil {
			return nil, err
		}
		a.Timestamp = ts
		a.Acked = acked == 1
		alerts = append(alerts, a)
	}
	return alerts, nil
}

func (s *SQLite) AckSIEMAlert(id int) error {
	result, err := s.db.Exec("UPDATE incidents SET acknowledged = 1 WHERE rowid = ?", id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("alert not found: %d", id)
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *SQLite) GetDashboardStats() (*models.DashboardStats, error) {
	stats := &models.DashboardStats{}

	s.db.QueryRow("SELECT COUNT(*) FROM incidents").Scan(&stats.TotalRequests)
	s.db.QueryRow("SELECT COUNT(*) FROM incidents WHERE severity IN ('critical', 'high')").Scan(&stats.BlockedRequests)
	s.db.QueryRow("SELECT COUNT(DISTINCT client_ip) FROM incidents WHERE timestamp > datetime('now', '-1 hour')").Scan(&stats.ActiveIPs)
	s.db.QueryRow("SELECT COUNT(*) FROM incidents WHERE timestamp > datetime('now', 'start of day')").Scan(&stats.IncidentsToday)
	s.db.QueryRow("SELECT COUNT(*) FROM agents WHERE status = 'active'").Scan(&stats.AgentsOnline)
	s.db.QueryRow("SELECT COUNT(*) FROM rules WHERE is_active = 1").Scan(&stats.RuleCount)

	rows, err := s.db.Query(`SELECT attack_type, COUNT(*) as cnt FROM incidents 
		WHERE attack_type != '' GROUP BY attack_type ORDER BY cnt DESC LIMIT 10`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ac models.AttackCount
			rows.Scan(&ac.AttackType, &ac.Count)
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

func (s *SQLite) GetGeoData() (*models.GeoStats, error) {
	rows, err := s.db.Query(`SELECT client_ip, COUNT(*) as cnt, MAX(timestamp) as last_seen
		FROM incidents WHERE client_ip != '' GROUP BY client_ip ORDER BY cnt DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := &models.GeoStats{}

	for rows.Next() {
		var ip string
		var count int
		var lastSeen string
		if err := rows.Scan(&ip, &count, &lastSeen); err != nil {
			continue
		}
		gl := models.GeoLocation{
			IP:       ip,
			Count:    count,
			LastSeen: lastSeen,
		}
		stats.Locations = append(stats.Locations, gl)
	}
	if stats.Locations == nil {
		stats.Locations = []models.GeoLocation{}
	}

	stats.TotalIPs = len(stats.Locations)
	return stats, nil
}

func (s *SQLite) IsHealthy() bool {
	return s.db.Ping() == nil
}

func (s *SQLite) GetDB() *sql.DB {
	return s.db
}
