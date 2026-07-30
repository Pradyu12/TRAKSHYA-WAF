//go:build !cgo

package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	_ "modernc.org/sqlite"
	"github.com/trakshya/trakshya-api/pkg/models"
)

type RawEvent struct {
	Timestamp     time.Time
	SourceIP      string
	DestinationIP string
	Method        string
	Host          string
	Path          string
	Query         string
	StatusCode    int
	Country       string
	AttackType    string
	RuleName      string
	Action        string
	Blocked       bool
	BytesSent     int64
	BytesReceived int64
	LatencyMs     int
	UserAgent     string
}

func boolInt(v bool) int {
	if v { return 1 }
	return 0
}

type Store struct {
	db         *sql.DB
	writeCh    chan RawEvent
	flushMu    sync.Mutex
	flushTimer *time.Ticker
	flushSize  int
	onIncident func(*models.Incident)
	closed     bool
	closeMu    sync.Mutex
}

func NewStore(dbPath string, onIncident func(*models.Incident)) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping sqlite: %w", err)
	}

	s := &Store{
		db:         db,
		writeCh:    make(chan RawEvent, 8192),
		flushSize:  1000,
		onIncident: onIncident,
	}

	if err := s.runMigrations(); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	s.flushTimer = time.NewTicker(1 * time.Second)
	go s.flushLoop()

	return s, nil
}

func (s *Store) Close() {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return
	}
	s.closed = true
	s.closeMu.Unlock()

	s.flushTimer.Stop()
	s.drainBuffer()
	s.db.Close()
}

func (s *Store) IsHealthy() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.db.PingContext(ctx) == nil
}

func (s *Store) GetDB() *sql.DB { return s.db }

func (s *Store) runMigrations() error {
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
			timestamp TEXT DEFAULT (datetime('now')),
			acknowledged INTEGER DEFAULT 0,
			acked_at TEXT,
			acked_by TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS rules (
			id TEXT PRIMARY KEY,
			pattern TEXT NOT NULL,
			severity TEXT NOT NULL,
			category TEXT NOT NULL,
			description TEXT,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at TEXT DEFAULT (datetime('now')),
			updated_at TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS blacklist (
			id TEXT PRIMARY KEY,
			ip TEXT NOT NULL UNIQUE,
			reason TEXT,
			created_at TEXT DEFAULT (datetime('now')),
			expires_at TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS system_config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS request_stats (
			client_ip TEXT PRIMARY KEY,
			request_count INTEGER NOT NULL DEFAULT 0,
			blocked_count INTEGER NOT NULL DEFAULT 0,
			last_seen TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS vulnerabilities (
			id TEXT PRIMARY KEY,
			package_name TEXT NOT NULL,
			installed_version TEXT NOT NULL,
			available_version TEXT,
			severity TEXT NOT NULL,
			cve_id TEXT,
			description TEXT,
			created_at TEXT DEFAULT (datetime('now')),
			updated_at TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS vuln_scans (
			id TEXT PRIMARY KEY,
			status TEXT DEFAULT 'running',
			target TEXT NOT NULL,
			started_at TEXT,
			completed_at TEXT,
			total_pkgs INTEGER DEFAULT 0,
			total_cves INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS vuln_findings (
			id TEXT PRIMARY KEY,
			scan_id TEXT NOT NULL,
			package TEXT,
			installed_version TEXT,
			available_version TEXT,
			severity TEXT,
			cve TEXT,
			description TEXT,
			category TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS vapt_scans (
			id TEXT PRIMARY KEY,
			status TEXT DEFAULT 'running',
			target TEXT NOT NULL,
			started_at TEXT,
			completed_at TEXT,
			total_probes INTEGER DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS vapt_findings (
			id TEXT PRIMARY KEY,
			scan_id TEXT NOT NULL,
			category TEXT,
			severity TEXT,
			title TEXT,
			description TEXT,
			evidence TEXT,
			remediation TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS raw_events (
			timestamp      TEXT NOT NULL,
			source_ip      TEXT NOT NULL,
			destination_ip TEXT NOT NULL DEFAULT '',
			method         TEXT NOT NULL DEFAULT '',
			host           TEXT NOT NULL DEFAULT '',
			path           TEXT NOT NULL DEFAULT '',
			query          TEXT NOT NULL DEFAULT '',
			status_code    INTEGER NOT NULL DEFAULT 0,
			country        TEXT NOT NULL DEFAULT '',
			attack_type    TEXT NOT NULL DEFAULT '',
			rule_name      TEXT NOT NULL DEFAULT '',
			action         TEXT NOT NULL DEFAULT '',
			blocked        INTEGER NOT NULL DEFAULT 0,
			bytes_sent     INTEGER NOT NULL DEFAULT 0,
			bytes_received INTEGER NOT NULL DEFAULT 0,
			latency_ms     INTEGER NOT NULL DEFAULT 0,
			user_agent     TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_incidents_client_ip ON incidents(client_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_incidents_attack_type ON incidents(attack_type)`,
		`CREATE INDEX IF NOT EXISTS idx_incidents_acknowledged ON incidents(acknowledged)`,
		`CREATE INDEX IF NOT EXISTS idx_rules_category ON rules(category)`,
		`CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled)`,
		`CREATE INDEX IF NOT EXISTS idx_blacklist_ip ON blacklist(ip)`,
		`CREATE INDEX IF NOT EXISTS idx_blacklist_expires ON blacklist(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_request_stats_last_seen ON request_stats(last_seen)`,
		`CREATE INDEX IF NOT EXISTS idx_vulns_package ON vulnerabilities(package_name)`,
		`CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_findings_scan ON vuln_findings(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_findings_severity ON vuln_findings(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_vapt_findings_scan ON vapt_findings(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vapt_findings_severity ON vapt_findings(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_re_ts ON raw_events(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_re_ip_ts ON raw_events(source_ip, timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_re_attack ON raw_events(attack_type, timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_re_blocked ON raw_events(blocked, timestamp)`,
	}
	for _, m := range stmts {
		if _, err := s.db.Exec(m); err != nil {
			return fmt.Errorf("migration failed: %w\nStatement: %s", err, m)
		}
	}
	if err := s.seedDefaults(); err != nil {
		return err
	}
	return nil
}

func (s *Store) seedDefaults() error {
	seeds := []string{
		`INSERT INTO rules (id, pattern, severity, category, description, enabled) VALUES
			('SQLI-001', '(\\bunion\\b.*\\bselect\\b|\\bdrop\\b.*\\btable\\b)', 'critical', 'sqli', 'SQL Injection', 1),
			('XSS-001', '(<script|javascript:|onerror=|onload=)', 'high', 'xss', 'Cross-Site Scripting', 1),
			('TRAV-001', '(\\.\\./|\\.\\.\\\\|%2e%2e)', 'high', 'path_traversal', 'Path Traversal', 1),
			('CMDI-001', '(;\\s*(cat|ls|rm|sh|bash)|\\$\\()', 'critical', 'cmd_injection', 'Command Injection', 1),
			('RFI-001', '(include=|require=|file=.*http)', 'medium', 'rfi', 'Remote File Inclusion', 1),
			('LFI-001', '(\\.\\./etc/passwd|/proc/self)', 'high', 'lfi', 'Local File Inclusion', 1),
			('SCANNER-001', '(wp-admin|phpmyadmin|/manager)', 'low', 'scanner', 'Scanner Detection', 1),
			('BRUTE-001', '(/api/auth/login.*POST)', 'medium', 'brute_force', 'Brute Force', 1)
		ON CONFLICT (id) DO NOTHING`,
		`INSERT INTO system_config (key, value) VALUES
			('posture', 'monitor'),
			('rate_limit_enabled', '1'),
			('circuit_breaker_enabled', '1'),
			('geoip_enabled', '0'),
			('jwt_enabled', '0'),
			('proxy_port', '8080'),
			('upstream_url', 'http://localhost:3000'),
			('management_api_url', 'http://localhost:8000')
		ON CONFLICT (key) DO NOTHING`,
	}
	for _, m := range seeds {
		if _, err := s.db.Exec(m); err != nil {
			return fmt.Errorf("seed failed: %w", err)
		}
	}
	return nil
}

// ── Incident CRUD ───────────────────────────────────────────────────────────

func (s *Store) CreateIncident(inc *models.Incident) error {
	_, err := s.db.Exec(
		`INSERT INTO incidents (id, incident_type, rule_id, attack_type, client_ip, path, method, severity, message, source, timestamp, acknowledged)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		inc.ID, inc.Type, inc.RuleID, inc.AttackType, inc.ClientIP, inc.Path, inc.Method, inc.Severity, inc.Message, inc.Source, inc.Timestamp.Format(time.RFC3339), 0,
	)
	return err
}

func (s *Store) ListIncidents() ([]models.Incident, error) {
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
		var tsStr string
		if err := rows.Scan(&inc.ID, &inc.Type, &inc.RuleID, &inc.AttackType, &inc.ClientIP, &inc.Path, &inc.Method, &inc.Severity, &inc.Message, &inc.Source, &tsStr, &inc.Acknowledged); err != nil {
			return nil, err
		}
		inc.Timestamp, _ = time.Parse(time.RFC3339, tsStr)
		out = append(out, inc)
	}
	return out, nil
}

func (s *Store) AcknowledgeIncident(id string) error {
	result, err := s.db.Exec("UPDATE incidents SET acknowledged = 1, acked_at = datetime('now'), acked_by = 'api' WHERE id = $1", id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("incident not found: %s", id)
	}
	return nil
}

// ── Agent CRUD ──────────────────────────────────────────────────────────────

func (s *Store) CreateAgent(agent *models.Agent) error {
	_, err := s.db.Exec(`INSERT INTO system_config (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, "agent:"+agent.ID, agent.Name)
	return err
}

func (s *Store) ListAgents() ([]models.Agent, error) {
	rows, err := s.db.Query(`SELECT key, value FROM system_config WHERE key LIKE 'agent:%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []models.Agent
	for rows.Next() {
		var key, name string
		if err := rows.Scan(&key, &name); err != nil {
			continue
		}
		agentID := key[len("agent:"):]
		agents = append(agents, models.Agent{
			ID:     agentID,
			Name:   name,
			Status: "unknown",
		})
	}
	return agents, nil
}

// ── Rule CRUD ───────────────────────────────────────────────────────────────

func (s *Store) CreateRule(r *models.Rule) error {
	_, err := s.db.Exec(
		`INSERT INTO rules (id, pattern, severity, category, description, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, datetime('now'), datetime('now'))`,
		r.RuleID, r.Pattern, r.Severity, r.Category, r.Description, boolInt(r.IsActive),
	)
	return err
}

func (s *Store) ListRules() ([]models.Rule, error) {
	rows, err := s.db.Query(`SELECT id, pattern, severity, category, description, enabled, created_at FROM rules ORDER BY created_at DESC`)
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

func (s *Store) ToggleRule(id string, isActive bool) error {
	result, err := s.db.Exec("UPDATE rules SET enabled = $1, updated_at = datetime('now') WHERE id = $2", boolInt(isActive), id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("rule not found: %s", id)
	}
	return nil
}

func (s *Store) DeleteRule(id string) error {
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

// ── Blacklist CRUD ──────────────────────────────────────────────────────────

func (s *Store) CreateBlacklistEntry(entry *models.BlacklistEntry) error {
	_, err := s.db.Exec("INSERT INTO blacklist (id, ip, reason) VALUES ($1, $2, $3) ON CONFLICT (ip) DO UPDATE SET reason = excluded.reason", entry.ID, entry.IPAddress, entry.Reason)
	return err
}

func (s *Store) ListBlacklist() ([]models.BlacklistEntry, error) {
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

func (s *Store) DeleteBlacklistEntry(ip string) error {
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

// ── SIEM ────────────────────────────────────────────────────────────────────

func (s *Store) GetSIEMStats() (*models.SIEMStats, error) {
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

func (s *Store) GetSIEMAlerts(limit int) ([]models.SIEMAlert, error) {
	rows, err := s.db.Query(`SELECT id, rule_id, severity, message, client_ip, path, timestamp, acknowledged FROM incidents ORDER BY timestamp DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []models.SIEMAlert
	for rows.Next() {
		var a models.SIEMAlert
		var tsStr string
		var acked int
		if err := rows.Scan(&a.ID, &a.RuleName, &a.Severity, &a.Description, &a.SourceIP, &a.Path, &tsStr, &acked); err != nil {
			return nil, err
		}
		a.Timestamp = tsStr
		a.Acked = acked != 0
		alerts = append(alerts, a)
	}
	return alerts, nil
}

func (s *Store) AckSIEMAlert(id string) error {
	result, err := s.db.Exec("UPDATE incidents SET acknowledged = 1, acked_at = datetime('now'), acked_by = 'siem' WHERE id = $1", id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("alert not found: %s", id)
	}
	return nil
}

// ── Dashboard ───────────────────────────────────────────────────────────────

func (s *Store) GetDashboardStats() (*models.DashboardStats, error) {
	stats := &models.DashboardStats{}
	if err := s.db.QueryRow("SELECT COALESCE(SUM(request_count), 0) FROM request_stats").Scan(&stats.TotalRequests); err != nil {
		log.Printf("dashboard stats request_count: %v", err)
	}
	if err := s.db.QueryRow("SELECT COALESCE(SUM(blocked_count), 0) FROM request_stats").Scan(&stats.BlockedRequests); err != nil {
		log.Printf("dashboard stats blocked_count: %v", err)
	}
	if err := s.db.QueryRow("SELECT COUNT(DISTINCT client_ip) FROM request_stats WHERE last_seen > datetime('now', '-1 hour')").Scan(&stats.ActiveIPs); err != nil {
		log.Printf("dashboard stats active_ips: %v", err)
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM incidents WHERE timestamp > datetime('now', '-1 day')").Scan(&stats.IncidentsToday); err != nil {
		log.Printf("dashboard stats incidents_today: %v", err)
	}
	agents, _ := s.ListAgents()
	stats.AgentsOnline = len(agents)
	var posture string
	if err := s.db.QueryRow("SELECT value FROM system_config WHERE key = 'posture'").Scan(&posture); err == nil && posture != "" {
		stats.Posture = models.Posture(posture)
	} else {
		stats.Posture = models.PostureMonitor
	}
	if err := s.db.QueryRow("SELECT COUNT(*) FROM rules WHERE enabled = 1").Scan(&stats.RuleCount); err != nil {
		log.Printf("dashboard stats rule_count: %v", err)
	}

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

// ── Geo ─────────────────────────────────────────────────────────────────────

func (s *Store) GetGeoData() (*models.GeoStats, error) {
	rows, err := s.db.Query(`SELECT client_ip, request_count as cnt, last_seen FROM request_stats WHERE client_ip != '' ORDER BY request_count DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := &models.GeoStats{Locations: []models.GeoLocation{}}
	for rows.Next() {
		var ip string
		var count int
		var lastSeenStr sql.NullString
		if err := rows.Scan(&ip, &count, &lastSeenStr); err != nil {
			continue
		}
		loc := models.GeoLocation{
			IP:       ip,
			Count:    count,
		}
		if lastSeenStr.Valid {
			loc.LastSeen = lastSeenStr.String
		}
		stats.Locations = append(stats.Locations, loc)
	}
	stats.TotalIPs = len(stats.Locations)
	return stats, nil
}

// ── Vulnerability Scanning ──────────────────────────────────────────────────

func (s *Store) CreateVulnScan(scan *models.VulnScan) error {
	query := `INSERT INTO vuln_scans (id, status, target, started_at, completed_at, total_pkgs, total_cves)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	completedAt := ""
	if scan.CompletedAt != nil {
		completedAt = scan.CompletedAt.Format(time.RFC3339)
	}
	_, err := s.db.Exec(query, scan.ID, scan.Status, scan.Target, scan.StartedAt.Format(time.RFC3339), completedAt, scan.TotalPkgs, scan.TotalCVEs)
	return err
}

func (s *Store) UpdateVulnScan(scan *models.VulnScan) error {
	query := `UPDATE vuln_scans SET status=$1, completed_at=$2, total_pkgs=$3, total_cves=$4 WHERE id=$5`
	completedAt := ""
	if scan.CompletedAt != nil {
		completedAt = scan.CompletedAt.Format(time.RFC3339)
	}
	result, err := s.db.Exec(query, scan.Status, completedAt, scan.TotalPkgs, scan.TotalCVEs, scan.ID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("scan not found: %s", scan.ID)
	}
	return nil
}

func (s *Store) GetVulnScan(id string) (*models.VulnScan, error) {
	var scan models.VulnScan
	var startedAt, completedAt string
	query := `SELECT id, status, target, started_at, completed_at, total_pkgs, total_cves FROM vuln_scans WHERE id=$1`
	err := s.db.QueryRow(query, id).Scan(&scan.ID, &scan.Status, &scan.Target, &startedAt, &completedAt, &scan.TotalPkgs, &scan.TotalCVEs)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	scan.StartedAt, _ = time.Parse(time.RFC3339, startedAt)
	if completedAt != "" {
		t, _ := time.Parse(time.RFC3339, completedAt)
		scan.CompletedAt = &t
	}
	scan.Findings, _ = s.ListVulnFindings(id)
	return &scan, nil
}

func (s *Store) ListVulnScans(limit int) ([]models.VulnScan, error) {
	if limit <= 0 {
		limit = 20
	}
	query := `SELECT id, status, target, started_at, completed_at, total_pkgs, total_cves FROM vuln_scans ORDER BY started_at DESC LIMIT $1`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []models.VulnScan
	for rows.Next() {
		var scan models.VulnScan
		var startedAt, completedAt string
		if err := rows.Scan(&scan.ID, &scan.Status, &scan.Target, &startedAt, &completedAt, &scan.TotalPkgs, &scan.TotalCVEs); err != nil {
			return nil, err
		}
		scan.StartedAt, _ = time.Parse(time.RFC3339, startedAt)
		if completedAt != "" {
			t, _ := time.Parse(time.RFC3339, completedAt)
			scan.CompletedAt = &t
		}
		scans = append(scans, scan)
	}
	if scans == nil {
		scans = []models.VulnScan{}
	}
	return scans, nil
}

func (s *Store) CreateVulnFinding(f *models.VulnFinding) error {
	query := `INSERT INTO vuln_findings (id, scan_id, package, installed_version, available_version, severity, cve, description, category)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := s.db.Exec(query, f.ID, f.ScanID, f.Package, f.Installed, f.Available, f.Severity, f.CVE, f.Description, f.Category)
	return err
}

func (s *Store) ListVulnFindings(scanID string) ([]models.VulnFinding, error) {
	query := `SELECT id, scan_id, package, installed_version, available_version, severity, cve, description, category
		FROM vuln_findings WHERE scan_id=$1 ORDER BY
		CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`
	rows, err := s.db.Query(query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []models.VulnFinding
	for rows.Next() {
		var f models.VulnFinding
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Package, &f.Installed, &f.Available, &f.Severity, &f.CVE, &f.Description, &f.Category); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	if findings == nil {
		findings = []models.VulnFinding{}
	}
	return findings, nil
}

func (s *Store) ListAllVulnFindings() ([]models.VulnFinding, error) {
	query := `SELECT f.id, f.scan_id, f.package, f.installed_version, f.available_version, f.severity, f.cve, f.description, f.category
		FROM vuln_findings f
		INNER JOIN vuln_scans sc ON f.scan_id = sc.id
		WHERE sc.id = (SELECT id FROM vuln_scans ORDER BY started_at DESC LIMIT 1)
		ORDER BY
		CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []models.VulnFinding
	for rows.Next() {
		var f models.VulnFinding
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Package, &f.Installed, &f.Available, &f.Severity, &f.CVE, &f.Description, &f.Category); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	if findings == nil {
		findings = []models.VulnFinding{}
	}
	return findings, nil
}

func (s *Store) GetVulnStats() (*models.VulnStats, error) {
	stats := &models.VulnStats{
		BySeverity: make(map[string]int),
	}

	lastScanQuery := `SELECT id, status, started_at, total_pkgs, total_cves FROM vuln_scans ORDER BY started_at DESC LIMIT 1`
	var lastScanID, lastStatus, lastStartedStr string
	var lastPkgs, lastCVEs int
	err := s.db.QueryRow(lastScanQuery).Scan(&lastScanID, &lastStatus, &lastStartedStr, &lastPkgs, &lastCVEs)
	if err == nil {
		stats.LastScanStatus = lastStatus
		stats.TotalPackages = lastPkgs
		stats.TotalCVEs = lastCVEs
		if lastStartedStr != "" {
			t, _ := time.Parse(time.RFC3339, lastStartedStr)
			stats.LastScanTime = &t
		}
	}

	sevQuery := `SELECT severity, COUNT(*) FROM vuln_findings
		WHERE scan_id = (SELECT id FROM vuln_scans ORDER BY started_at DESC LIMIT 1)
		GROUP BY severity`
	rows, err := s.db.Query(sevQuery)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var cnt int
			if err := rows.Scan(&sev, &cnt); err == nil {
				stats.BySeverity[sev] = cnt
			}
		}
	}

	total := 0
	for _, c := range stats.BySeverity {
		total += c
	}
	stats.TotalCVEs = total

	if total > 0 {
		scoreMap := map[string]float64{"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
		sum := 0.0
		for sev, c := range stats.BySeverity {
			sum += scoreMap[sev] * float64(c)
		}
		stats.AvgCVSS = sum / float64(total)
	}

	return stats, nil
}

// ── VAPT Scanning ───────────────────────────────────────────────────────────

func (s *Store) CreateVaptScan(scan *models.VaptScan) error {
	query := `INSERT INTO vapt_scans (id, status, target, started_at, completed_at, total_probes)
		VALUES ($1, $2, $3, $4, $5, $6)`
	completedAt := ""
	if scan.CompletedAt != nil {
		completedAt = scan.CompletedAt.Format(time.RFC3339)
	}
	_, err := s.db.Exec(query, scan.ID, scan.Status, scan.Target, scan.StartedAt.Format(time.RFC3339), completedAt, scan.TotalProbes)
	return err
}

func (s *Store) UpdateVaptScan(scan *models.VaptScan) error {
	query := `UPDATE vapt_scans SET status=$1, completed_at=$2, total_probes=$3 WHERE id=$4`
	completedAt := ""
	if scan.CompletedAt != nil {
		completedAt = scan.CompletedAt.Format(time.RFC3339)
	}
	result, err := s.db.Exec(query, scan.Status, completedAt, scan.TotalProbes, scan.ID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("vapt scan not found: %s", scan.ID)
	}
	return nil
}

func (s *Store) GetVaptScan(id string) (*models.VaptScan, error) {
	var scan models.VaptScan
	var startedAt, completedAt string
	query := `SELECT id, status, target, started_at, completed_at, total_probes FROM vapt_scans WHERE id=$1`
	err := s.db.QueryRow(query, id).Scan(&scan.ID, &scan.Status, &scan.Target, &startedAt, &completedAt, &scan.TotalProbes)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	scan.StartedAt, _ = time.Parse(time.RFC3339, startedAt)
	if completedAt != "" {
		t, _ := time.Parse(time.RFC3339, completedAt)
		scan.CompletedAt = &t
	}
	scan.Findings, _ = s.ListVaptFindings(id)
	return &scan, nil
}

func (s *Store) ListVaptScans(limit int) ([]models.VaptScan, error) {
	if limit <= 0 {
		limit = 20
	}
	query := `SELECT id, status, target, started_at, completed_at, total_probes FROM vapt_scans ORDER BY started_at DESC LIMIT $1`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []models.VaptScan
	for rows.Next() {
		var scan models.VaptScan
		var startedAt, completedAt string
		if err := rows.Scan(&scan.ID, &scan.Status, &scan.Target, &startedAt, &completedAt, &scan.TotalProbes); err != nil {
			return nil, err
		}
		scan.StartedAt, _ = time.Parse(time.RFC3339, startedAt)
		if completedAt != "" {
			t, _ := time.Parse(time.RFC3339, completedAt)
			scan.CompletedAt = &t
		}
		scans = append(scans, scan)
	}
	if scans == nil {
		scans = []models.VaptScan{}
	}
	return scans, nil
}

func (s *Store) CreateVaptFinding(f *models.VaptFinding) error {
	query := `INSERT INTO vapt_findings (id, scan_id, category, severity, title, description, evidence, remediation)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := s.db.Exec(query, f.ID, f.ScanID, f.Category, f.Severity, f.Title, f.Description, f.Evidence, f.Remediation)
	return err
}

func (s *Store) ListVaptFindings(scanID string) ([]models.VaptFinding, error) {
	query := `SELECT id, scan_id, category, severity, title, description, evidence, remediation
		FROM vapt_findings WHERE scan_id=$1 ORDER BY
		CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`
	rows, err := s.db.Query(query, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []models.VaptFinding
	for rows.Next() {
		var f models.VaptFinding
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Category, &f.Severity, &f.Title, &f.Description, &f.Evidence, &f.Remediation); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	if findings == nil {
		findings = []models.VaptFinding{}
	}
	return findings, nil
}

func (s *Store) ListAllVaptFindings() ([]models.VaptFinding, error) {
	query := `SELECT f.id, f.scan_id, f.category, f.severity, f.title, f.description, f.evidence, f.remediation
		FROM vapt_findings f
		INNER JOIN vapt_scans sc ON f.scan_id = sc.id
		WHERE sc.id = (SELECT id FROM vapt_scans ORDER BY started_at DESC LIMIT 1)
		ORDER BY
		CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []models.VaptFinding
	for rows.Next() {
		var f models.VaptFinding
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Category, &f.Severity, &f.Title, &f.Description, &f.Evidence, &f.Remediation); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	if findings == nil {
		findings = []models.VaptFinding{}
	}
	return findings, nil
}

func (s *Store) GetVaptStats() (*models.VaptStats, error) {
	stats := &models.VaptStats{BySeverity: make(map[string]int)}

	lastScanQuery := `SELECT id, status, started_at, total_probes FROM vapt_scans ORDER BY started_at DESC LIMIT 1`
	var lastScanID, lastStatus, lastStartedStr string
	var lastProbes int
	err := s.db.QueryRow(lastScanQuery).Scan(&lastScanID, &lastStatus, &lastStartedStr, &lastProbes)
	if err == nil {
		stats.LastScanStatus = lastStatus
		stats.TotalProbes = lastProbes
		if lastStartedStr != "" {
			t, _ := time.Parse(time.RFC3339, lastStartedStr)
			stats.LastScanTime = &t
		}
	}

	sevQuery := `SELECT severity, COUNT(*) FROM vapt_findings
		WHERE scan_id = (SELECT id FROM vapt_scans ORDER BY started_at DESC LIMIT 1)
		GROUP BY severity`
	rows, err := s.db.Query(sevQuery)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var cnt int
			if err := rows.Scan(&sev, &cnt); err == nil {
				stats.BySeverity[sev] = cnt
			}
		}
	}

	total := 0
	for _, c := range stats.BySeverity {
		total += c
	}
	stats.TotalFindings = total

	if total > 0 {
		scoreMap := map[string]float64{"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
		sum := 0.0
		for sev, c := range stats.BySeverity {
			sum += scoreMap[sev] * float64(c)
		}
		stats.AvgCVSS = sum / float64(total)
	}

	return stats, nil
}

// ── Buffered ingestion pipeline ─────────────────────────────────────────────

func (s *Store) Ingest(evt RawEvent) {
	select {
	case s.writeCh <- evt:
	default:
		log.Printf("WARN: sqlite write buffer full, dropping event from %s", evt.SourceIP)
	}
}

func (s *Store) RecordRequest(clientIP string, blocked bool) {
	blockedVal := 0
	if blocked {
		blockedVal = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO request_stats (client_ip, request_count, blocked_count, last_seen)
		 VALUES ($1, 1, $2, datetime('now'))
		 ON CONFLICT(client_ip) DO UPDATE SET
		     request_count = request_stats.request_count + 1,
		     blocked_count = request_stats.blocked_count + $3,
		     last_seen = datetime('now')`,
		clientIP, blockedVal, blockedVal,
	)
	if err != nil {
		log.Printf("WARN: failed to record request stats: %v", err)
	}
}

func (s *Store) flushLoop() {
	for range s.flushTimer.C {
		s.drainBuffer()
	}
}

func (s *Store) drainBuffer() {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()

	batch := make([]RawEvent, 0, s.flushSize)
	for len(batch) < s.flushSize {
		select {
		case evt := <-s.writeCh:
			batch = append(batch, evt)
		default:
			goto flush
		}
	}
flush:
	if len(batch) == 0 {
		return
	}
	if err := s.writeBatch(batch); err != nil {
		log.Printf("ERROR: sqlite batch write failed: %v", err)
	}
}

func (s *Store) writeBatch(batch []RawEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO raw_events
		(timestamp, source_ip, destination_ip, method, host, path, query, status_code, country,
		 attack_type, rule_name, action, blocked, bytes_sent, bytes_received, latency_ms, user_agent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for _, e := range batch {
		if _, err := stmt.ExecContext(ctx,
			e.Timestamp.Format(time.RFC3339), e.SourceIP, e.DestinationIP, e.Method, e.Host, e.Path, e.Query,
			e.StatusCode, e.Country, e.AttackType, e.RuleName, e.Action, boolInt(e.Blocked),
			e.BytesSent, e.BytesReceived, e.LatencyMs, e.UserAgent,
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("exec insert: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// ── Sliding-Window Correlation Rules ────────────────────────────────────────

func (s *Store) RunCorrelationRules() []models.Incident {
	var incidents []models.Incident

	checks := []struct {
		name string
		sql  string
		fn   func(*sql.Row) (models.Incident, bool, error)
	}{
		{"brute_force", bruteForceSQL, scanBruteForce},
		{"port_scan", portScanSQL, scanPortScan},
		{"xss_wave", xssWaveSQL, scanXssWave},
		{"sqli_wave", sqliWaveSQL, scanSqlWave},
		{"rapid_scan", rapidScanSQL, scanRapidScan},
		{"data_exfil", dataExfilSQL, scanDataExfil},
		{"geo_anomaly", geoAnomalySQL, scanGeoAnomaly},
		{"beaconing", beaconingSQL, scanBeaconing},
	}

	for _, c := range checks {
		row := s.db.QueryRow(c.sql)
		inc, found, err := c.fn(row)
		if err != nil {
			log.Printf("SIEM correlation error [%s]: %v", c.name, err)
			continue
		}
		if found {
			inc.ID = fmt.Sprintf("siem-%s-%d", c.name, time.Now().UnixNano())
			s.CreateIncident(&inc)
			incidents = append(incidents, inc)
			if s.onIncident != nil {
				s.onIncident(&inc)
			}
		}
	}

	return incidents
}

const bruteForceSQL = `
	SELECT source_ip, COUNT(*) AS cnt
	FROM   raw_events
	WHERE  blocked = 1
	  AND  timestamp >= datetime('now', '-5 minutes')
	GROUP  BY source_ip
	HAVING COUNT(*) >= 10
	ORDER  BY cnt DESC
	LIMIT  1
`

func scanBruteForce(row *sql.Row) (models.Incident, bool, error) {
	var ip string
	var cnt int
	if err := row.Scan(&ip, &cnt); err != nil {
		if err == sql.ErrNoRows {
			return models.Incident{}, false, nil
		}
		return models.Incident{}, false, err
	}
	return models.Incident{
		Type:       "siem_alert",
		AttackType: "brute_force",
		ClientIP:   ip,
		Severity:   "critical",
		Message:    fmt.Sprintf("Brute force: %d blocked requests from %s in 5m", cnt, ip),
		Source:     "sqlite-siem",
		Timestamp:  time.Now(),
	}, true, nil
}

const portScanSQL = `
	SELECT source_ip, COUNT(DISTINCT path) AS paths
	FROM   raw_events
	WHERE  timestamp >= datetime('now', '-10 minutes')
	GROUP  BY source_ip
	HAVING COUNT(DISTINCT path) >= 15
	ORDER  BY paths DESC
	LIMIT  1
`

func scanPortScan(row *sql.Row) (models.Incident, bool, error) {
	var ip string
	var paths int
	if err := row.Scan(&ip, &paths); err != nil {
		if err == sql.ErrNoRows {
			return models.Incident{}, false, nil
		}
		return models.Incident{}, false, err
	}
	return models.Incident{
		Type:       "siem_alert",
		AttackType: "port_scan",
		ClientIP:   ip,
		Severity:   "high",
		Message:    fmt.Sprintf("Port scan: %d distinct paths probed from %s in 10m", paths, ip),
		Source:     "sqlite-siem",
		Timestamp:  time.Now(),
	}, true, nil
}

const xssWaveSQL = `
	SELECT COUNT(*) AS cnt
	FROM   raw_events
	WHERE  attack_type = 'xss'
	  AND  timestamp >= datetime('now', '-5 minutes')
`

func scanXssWave(row *sql.Row) (models.Incident, bool, error) {
	var cnt int
	if err := row.Scan(&cnt); err != nil {
		if err == sql.ErrNoRows {
			return models.Incident{}, false, nil
		}
		return models.Incident{}, false, err
	}
	if cnt < 5 {
		return models.Incident{}, false, nil
	}
	return models.Incident{
		Type:       "siem_alert",
		AttackType: "xss_wave",
		Severity:   "high",
		Message:    fmt.Sprintf("XSS wave: %d XSS attacks detected across all sources in 5m", cnt),
		Source:     "sqlite-siem",
		Timestamp:  time.Now(),
	}, true, nil
}

const sqliWaveSQL = `
	SELECT COUNT(*) AS cnt
	FROM   raw_events
	WHERE  attack_type = 'sql_injection'
	  AND  timestamp >= datetime('now', '-5 minutes')
`

func scanSqlWave(row *sql.Row) (models.Incident, bool, error) {
	var cnt int
	if err := row.Scan(&cnt); err != nil {
		if err == sql.ErrNoRows {
			return models.Incident{}, false, nil
		}
		return models.Incident{}, false, err
	}
	if cnt < 5 {
		return models.Incident{}, false, nil
	}
	return models.Incident{
		Type:       "siem_alert",
		AttackType: "sqli_wave",
		Severity:   "critical",
		Message:    fmt.Sprintf("SQLi wave: %d injection attacks detected in 5m", cnt),
		Source:     "sqlite-siem",
		Timestamp:  time.Now(),
	}, true, nil
}

const rapidScanSQL = `
	SELECT source_ip, COUNT(*) AS cnt
	FROM   raw_events
	WHERE  timestamp >= datetime('now', '-10 seconds')
	GROUP  BY source_ip
	HAVING COUNT(*) >= 20
	ORDER  BY cnt DESC
	LIMIT  1
`

func scanRapidScan(row *sql.Row) (models.Incident, bool, error) {
	var ip string
	var cnt int
	if err := row.Scan(&ip, &cnt); err != nil {
		if err == sql.ErrNoRows {
			return models.Incident{}, false, nil
		}
		return models.Incident{}, false, err
	}
	return models.Incident{
		Type:       "siem_alert",
		AttackType: "rapid_scan",
		ClientIP:   ip,
		Severity:   "high",
		Message:    fmt.Sprintf("Rapid scan: %d requests from %s in 10s", cnt, ip),
		Source:     "sqlite-siem",
		Timestamp:  time.Now(),
	}, true, nil
}

const dataExfilSQL = `
	SELECT source_ip, SUM(bytes_sent) AS total_sent
	FROM   raw_events
	WHERE  blocked = 0
	  AND  status_code BETWEEN 200 AND 299
	  AND  timestamp >= datetime('now', '-1 hour')
	GROUP  BY source_ip
	HAVING SUM(bytes_sent) >= 100000000
	ORDER  BY total_sent DESC
	LIMIT  1
`

func scanDataExfil(row *sql.Row) (models.Incident, bool, error) {
	var ip string
	var total int64
	if err := row.Scan(&ip, &total); err != nil {
		if err == sql.ErrNoRows {
			return models.Incident{}, false, nil
		}
		return models.Incident{}, false, err
	}
	mb := float64(total) / (1024 * 1024)
	return models.Incident{
		Type:       "siem_alert",
		AttackType: "data_exfiltration",
		ClientIP:   ip,
		Severity:   "high",
		Message:    fmt.Sprintf("Possible exfiltration: %.2f MB sent from %s in 1h", mb, ip),
		Source:     "sqlite-siem",
		Timestamp:  time.Now(),
	}, true, nil
}

const geoAnomalySQL = `
	SELECT source_ip, COUNT(DISTINCT country) AS countries
	FROM   raw_events
	WHERE  timestamp >= datetime('now', '-30 minutes')
	  AND  country != ''
	GROUP  BY source_ip
	HAVING COUNT(DISTINCT country) >= 3
	ORDER  BY countries DESC
	LIMIT  1
`

func scanGeoAnomaly(row *sql.Row) (models.Incident, bool, error) {
	var ip string
	var countries int
	if err := row.Scan(&ip, &countries); err != nil {
		if err == sql.ErrNoRows {
			return models.Incident{}, false, nil
		}
		return models.Incident{}, false, err
	}
	return models.Incident{
		Type:       "siem_alert",
		AttackType: "geo_anomaly",
		ClientIP:   ip,
		Severity:   "medium",
		Message:    fmt.Sprintf("Geo anomaly: %s observed from %d distinct countries in 30m", ip, countries),
		Source:     "sqlite-siem",
		Timestamp:  time.Now(),
	}, true, nil
}

const beaconingSQL = `
	WITH grouped AS (
		SELECT source_ip, host,
			   COUNT(*) AS cnt,
			   MIN(timestamp) AS first_seen,
			   MAX(timestamp) AS last_seen
		FROM   raw_events
		WHERE  timestamp >= datetime('now', '-10 minutes')
		GROUP  BY source_ip, host
		HAVING COUNT(*) >= 12
	)
	SELECT source_ip, host, cnt
	FROM   grouped
	ORDER  BY cnt DESC
	LIMIT  1
`

func scanBeaconing(row *sql.Row) (models.Incident, bool, error) {
	var ip, host string
	var cnt int
	if err := row.Scan(&ip, &host, &cnt); err != nil {
		if err == sql.ErrNoRows {
			return models.Incident{}, false, nil
		}
		return models.Incident{}, false, err
	}
	return models.Incident{
		Type:       "siem_alert",
		AttackType: "beaconing",
		ClientIP:   ip,
		Severity:   "medium",
		Message:    fmt.Sprintf("Beaconing: %d periodic requests from %s to %s in 10m", cnt, ip, host),
		Source:     "sqlite-siem",
		Timestamp:  time.Now(),
		Path:       host,
	}, true, nil
}

// ── Analytics queries ───────────────────────────────────────────────────────

type AttackCount struct {
	AttackType string `json:"attack_type"`
	Count      int64  `json:"count"`
}

type EventStats struct {
	TotalEvents    int64            `json:"total_events"`
	BlockedEvents  int64            `json:"blocked_events"`
	UniqueIPs      int64            `json:"unique_ips"`
	EventsLastHour int64            `json:"events_last_hour"`
	BySeverity     map[string]int64 `json:"by_severity"`
	ByAttackType   []AttackCount    `json:"by_attack_type"`
	Timeline       []TimeBucket     `json:"timeline"`
}

type TimeBucket struct {
	Time  string `json:"time"`
	Count int64  `json:"count"`
}

func (s *Store) GetEventStats() (*EventStats, error) {
	stats := &EventStats{
		BySeverity: make(map[string]int64),
	}

	_ = s.db.QueryRow(`SELECT COUNT(*) FROM raw_events`).Scan(&stats.TotalEvents)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM raw_events WHERE blocked = 1`).Scan(&stats.BlockedEvents)
	_ = s.db.QueryRow(`SELECT COUNT(DISTINCT source_ip) FROM raw_events`).Scan(&stats.UniqueIPs)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM raw_events WHERE timestamp >= datetime('now', '-1 hour')`).Scan(&stats.EventsLastHour)

	aRows, err := s.db.Query(`
		SELECT attack_type, COUNT(*) AS cnt
		FROM   raw_events
		WHERE  attack_type != ''
		GROUP  BY attack_type
		ORDER  BY cnt DESC
		LIMIT  10
	`)
	if err == nil {
		defer aRows.Close()
		for aRows.Next() {
			var ac AttackCount
			if aRows.Scan(&ac.AttackType, &ac.Count) == nil {
				stats.ByAttackType = append(stats.ByAttackType, ac)
			}
		}
	}

	tRows, err := s.db.Query(`
		SELECT strftime('%Y-%m-%d %H:%M:00', timestamp) AS minute, COUNT(*) AS cnt
		FROM   raw_events
		WHERE  timestamp >= datetime('now', '-1 hour')
		GROUP  BY strftime('%Y-%m-%d %H:%M:00', timestamp)
		ORDER  BY minute
	`)
	if err == nil {
		defer tRows.Close()
		for tRows.Next() {
			var tb TimeBucket
			if tRows.Scan(&tb.Time, &tb.Count) == nil {
				stats.Timeline = append(stats.Timeline, tb)
			}
		}
	}

	return stats, nil
}

func (s *Store) GetTopAttackers(limit int) ([]AttackCount, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.db.Query(`
		SELECT source_ip, COUNT(*) AS cnt
		FROM   raw_events
		GROUP  BY source_ip
		ORDER  BY cnt DESC
		LIMIT  $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AttackCount
	for rows.Next() {
		var ip string
		var cnt int64
		if err := rows.Scan(&ip, &cnt); err != nil {
			continue
		}
		out = append(out, AttackCount{AttackType: ip, Count: cnt})
	}
	if out == nil {
		out = []AttackCount{}
	}
	return out, nil
}

func (s *Store) GetTimeline() ([]TimeBucket, error) {
	rows, err := s.db.Query(`
		SELECT strftime('%Y-%m-%d %H:%M:00', timestamp) AS minute, COUNT(*) AS cnt
		FROM   raw_events
		WHERE  timestamp >= datetime('now', '-1 hour')
		GROUP  BY strftime('%Y-%m-%d %H:%M:00', timestamp)
		ORDER  BY minute
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TimeBucket
	for rows.Next() {
		var tb TimeBucket
		if err := rows.Scan(&tb.Time, &tb.Count); err != nil {
			continue
		}
		out = append(out, tb)
	}
	if out == nil {
		out = []TimeBucket{}
	}
	return out, nil
}

func (s *Store) GetCountryStats() ([]AttackCount, error) {
	rows, err := s.db.Query(`
		SELECT country, COUNT(*) AS cnt
		FROM   raw_events
		WHERE  country != ''
		GROUP  BY country
		ORDER  BY cnt DESC
		LIMIT  20
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AttackCount
	for rows.Next() {
		var c AttackCount
		if err := rows.Scan(&c.AttackType, &c.Count); err != nil {
			continue
		}
		out = append(out, c)
	}
	if out == nil {
		out = []AttackCount{}
	}
	return out, nil
}

func (s *Store) GetRuleTriggers() ([]AttackCount, error) {
	rows, err := s.db.Query(`
		SELECT rule_name, COUNT(*) AS cnt
		FROM   raw_events
		WHERE  rule_name != ''
		GROUP  BY rule_name
		ORDER  BY cnt DESC
		LIMIT  20
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AttackCount
	for rows.Next() {
		var r AttackCount
		if err := rows.Scan(&r.AttackType, &r.Count); err != nil {
			continue
		}
		out = append(out, r)
	}
	if out == nil {
		out = []AttackCount{}
	}
	return out, nil
}

func (s *Store) PruneOldEvents(retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		retentionDays = 30
	}

	res, err := s.db.Exec(fmt.Sprintf(`
		DELETE FROM raw_events
		WHERE timestamp < datetime('now', '-%d days')
	`, retentionDays))
	if err != nil {
		return 0, fmt.Errorf("prune events delete: %w", err)
	}
	deleted, _ := res.RowsAffected()

	if _, err := s.db.Exec(`PRAGMA optimize`); err != nil {
		log.Printf("WARN: sqlite optimize failed: %v", err)
	}
	return deleted, nil
}

func (s *Store) GetRecentEvents(limit int) ([]RawEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`
		SELECT timestamp, source_ip, destination_ip, method, host, path, query,
		       status_code, country, attack_type, rule_name, action, blocked,
		       bytes_sent, bytes_received, latency_ms, user_agent
		FROM   raw_events
		ORDER  BY timestamp DESC
		LIMIT  $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []RawEvent
	for rows.Next() {
		var e RawEvent
		var tsStr string
		if err := rows.Scan(
			&tsStr, &e.SourceIP, &e.DestinationIP, &e.Method, &e.Host,
			&e.Path, &e.Query, &e.StatusCode, &e.Country, &e.AttackType,
			&e.RuleName, &e.Action, &e.Blocked, &e.BytesSent, &e.BytesReceived,
			&e.LatencyMs, &e.UserAgent,
		); err != nil {
			continue
		}
		e.Timestamp, _ = time.Parse(time.RFC3339, tsStr)
		if e.Timestamp.IsZero() {
			e.Timestamp, _ = time.Parse("2006-01-02 15:04:05", tsStr)
		}
		events = append(events, e)
	}
	if events == nil {
		events = []RawEvent{}
	}
	return events, nil
}
