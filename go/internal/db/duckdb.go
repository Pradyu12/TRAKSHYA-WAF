package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	_ "github.com/marcboeker/go-duckdb"
	"github.com/trakshya/trakshya-api/pkg/models"
)

// ── Raw event stored in DuckDB (high-volume, columnar) ──────────────────────

type RawEvent struct {
	Timestamp   time.Time
	SourceIP    string
	Method      string
	Path        string
	Query       string
	StatusCode  int
	Blocked     bool
	AttackType  string
	RuleMatched string
	Severity    string
	ResponseMs  float64
	UserAgent   string
}

// ── DuckDB handle (single-writer, concurrent reader model) ──────────────────

type DuckDB struct {
	db         *sql.DB           // primary write connection (exclusive)
	roDB       *sql.DB           // read-only pool for dashboard queries
	writeCh    chan RawEvent      // buffered ingestion channel
	flushMu    sync.Mutex
	flushTimer *time.Ticker
	flushSize  int
	onIncident func(*models.Incident) // callback: when correlation fires, write to PostgreSQL
}

// NewDuckDB opens/creates the embedded DuckDB file and sets up the schema.
// onIncident is called when a correlation rule fires — the caller writes
// the resulting Incident to PostgreSQL via the existing Postgres store.
func NewDuckDB(dbPath string, onIncident func(*models.Incident)) (*DuckDB, error) {
	// Primary write connection (single-writer — DuckDB constraint)
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		return nil, fmt.Errorf("duckdb open: %w", err)
	}
	db.SetMaxOpenConns(1) // enforce single writer

	// Read-only connection for concurrent dashboard/analytics queries
	roDB, err := sql.Open("duckdb", dbPath+"?access_mode=READ_ONLY")
	if err != nil {
		return nil, fmt.Errorf("duckdb open read-only: %w", err)
	}
	roDB.SetMaxOpenConns(4)

	if err := runDuckDBMigrations(db); err != nil {
		return nil, fmt.Errorf("duckdb migrations: %w", err)
	}

	d := &DuckDB{
		db:         db,
		roDB:       roDB,
		writeCh:    make(chan RawEvent, 8192),
		flushSize:  1000,
		onIncident: onIncident,
	}

	// Background flush goroutine: every 1s or when buffer hits flushSize
	d.flushTimer = time.NewTicker(1 * time.Second)
	go d.flushLoop()

	return d, nil
}

func (d *DuckDB) Close() {
	d.flushTimer.Stop()
	d.drainBuffer()
	d.db.Close()
	d.roDB.Close()
}

// ── Schema ──────────────────────────────────────────────────────────────────

func runDuckDBMigrations(db *sql.DB) error {
	stmts := []string{
		// Main events table — partitioned-friendly columnar layout
		`CREATE TABLE IF NOT EXISTS raw_events (
			timestamp    TIMESTAMPTZ NOT NULL,
			source_ip    VARCHAR NOT NULL,
			method       VARCHAR NOT NULL DEFAULT '',
			path         VARCHAR NOT NULL DEFAULT '',
			query        VARCHAR NOT NULL DEFAULT '',
			status_code  INTEGER NOT NULL DEFAULT 0,
			blocked      BOOLEAN NOT NULL DEFAULT false,
			attack_type  VARCHAR NOT NULL DEFAULT '',
			rule_matched VARCHAR NOT NULL DEFAULT '',
			severity     VARCHAR NOT NULL DEFAULT '',
			response_ms  DOUBLE NOT NULL DEFAULT 0,
			user_agent   VARCHAR NOT NULL DEFAULT ''
		)`,
		// Partition-aligned indexes for time-range scans
		`CREATE INDEX IF NOT EXISTS idx_re_ts ON raw_events(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_re_ip_ts ON raw_events(source_ip, timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_re_attack ON raw_events(attack_type, timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_re_blocked ON raw_events(blocked, timestamp)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("exec %q: %w", s[:40], err)
		}
	}
	return nil
}

// ── Buffered ingestion pipeline ─────────────────────────────────────────────

// Ingest is called from the hot path (Rust proxy event forwarding or
// Go API incident recording). It is non-blocking — events queue in
// a buffered channel and flush in batches to DuckDB.
func (d *DuckDB) Ingest(evt RawEvent) {
	select {
	case d.writeCh <- evt:
	default:
		log.Printf("WARN: duckdb write buffer full, dropping event from %s", evt.SourceIP)
	}
}

func (d *DuckDB) flushLoop() {
	for range d.flushTimer.C {
		d.drainBuffer()
	}
}

func (d *DuckDB) drainBuffer() {
	d.flushMu.Lock()
	defer d.flushMu.Unlock()

	batch := make([]RawEvent, 0, d.flushSize)
	for len(batch) < d.flushSize {
		select {
		case evt := <-d.writeCh:
			batch = append(batch, evt)
		default:
			goto flush
		}
	}
flush:
	if len(batch) == 0 {
		return
	}
	if err := d.writeBatch(batch); err != nil {
		log.Printf("ERROR: duckdb batch write failed: %v", err)
	}
}

// writeBatch uses DuckDB's Appender for high-throughput bulk inserts.
func (d *DuckDB) writeBatch(batch []RawEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO raw_events
		(timestamp, source_ip, method, path, query, status_code, blocked,
		 attack_type, rule_matched, severity, response_ms, user_agent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for _, e := range batch {
		if _, err := stmt.ExecContext(ctx,
			e.Timestamp, e.SourceIP, e.Method, e.Path, e.Query,
			e.StatusCode, e.Blocked, e.AttackType, e.RuleMatched,
			e.Severity, e.ResponseMs, e.UserAgent,
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

// ── 7 Sliding-Window Correlation Rules (SQL) ────────────────────────────────
// Each returns incidents that should be written to PostgreSQL.

func (d *DuckDB) RunCorrelationRules() []models.Incident {
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
	}

	for _, c := range checks {
		row := d.roDB.QueryRow(c.sql)
		inc, found, err := c.fn(row)
		if err != nil {
			log.Printf("SIEM correlation error [%s]: %v", c.name, err)
			continue
		}
		if found {
			incidents = append(incidents, inc)
			if d.onIncident != nil {
				d.onIncident(&inc)
			}
		}
	}

	return incidents
}

// ── Rule 1: Brute Force Detection ───────────────────────────────────────────
// ≥10 blocked requests from same IP in last 5 minutes

const bruteForceSQL = `
	SELECT source_ip, COUNT(*) AS cnt
	FROM   raw_events
	WHERE  blocked = true
	  AND  timestamp >= now() - INTERVAL '5 minutes'
	GROUP  BY source_ip
	HAVING COUNT(*) >= 10
	ORDER  BY cnt DESC
	LIMIT  1
`

func scanBruteForce(row *sql.Row) (models.Incident, bool, error) {
	var ip string
	var cnt int
	if err := row.Scan(&ip, &cnt); err != nil {
		return models.Incident{}, false, err
	}
	return models.Incident{
		Type:       "siem_alert",
		AttackType: "brute_force",
		ClientIP:   ip,
		Severity:   "critical",
		Message:    fmt.Sprintf("Brute force: %d blocked requests from %s in 5m", cnt, ip),
		Source:     "duckdb-siem",
		Timestamp:  time.Now(),
	}, true, nil
}

// ── Rule 2: Port Scan Detection ─────────────────────────────────────────────
// ≥15 distinct paths from same IP in last 10 minutes

const portScanSQL = `
	SELECT source_ip, COUNT(DISTINCT path) AS paths
	FROM   raw_events
	WHERE  timestamp >= now() - INTERVAL '10 minutes'
	GROUP  BY source_ip
	HAVING COUNT(DISTINCT path) >= 15
	ORDER  BY paths DESC
	LIMIT  1
`

func scanPortScan(row *sql.Row) (models.Incident, bool, error) {
	var ip string
	var paths int
	if err := row.Scan(&ip, &paths); err != nil {
		return models.Incident{}, false, err
	}
	return models.Incident{
		Type:       "siem_alert",
		AttackType: "port_scan",
		ClientIP:   ip,
		Severity:   "high",
		Message:    fmt.Sprintf("Port scan: %d distinct paths probed from %s in 10m", paths, ip),
		Source:     "duckdb-siem",
		Timestamp:  time.Now(),
	}, true, nil
}

// ── Rule 3: XSS Wave Detection ──────────────────────────────────────────────
// ≥5 XSS attacks across all IPs in last 5 minutes

const xssWaveSQL = `
	SELECT COUNT(*) AS cnt
	FROM   raw_events
	WHERE  attack_type = 'xss'
	  AND  timestamp >= now() - INTERVAL '5 minutes'
`

func scanXssWave(row *sql.Row) (models.Incident, bool, error) {
	var cnt int
	if err := row.Scan(&cnt); err != nil {
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
		Source:     "duckdb-siem",
		Timestamp:  time.Now(),
	}, true, nil
}

// ── Rule 4: SQL Injection Wave Detection ────────────────────────────────────
// ≥5 SQLi attacks across all IPs in last 5 minutes

const sqliWaveSQL = `
	SELECT COUNT(*) AS cnt
	FROM   raw_events
	WHERE  attack_type = 'sql_injection'
	  AND  timestamp >= now() - INTERVAL '5 minutes'
`

func scanSqlWave(row *sql.Row) (models.Incident, bool, error) {
	var cnt int
	if err := row.Scan(&cnt); err != nil {
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
		Source:     "duckdb-siem",
		Timestamp:  time.Now(),
	}, true, nil
}

// ── Rule 5: Rapid Scan Detection ────────────────────────────────────────────
// ≥20 requests from same IP in last 10 seconds

const rapidScanSQL = `
	SELECT source_ip, COUNT(*) AS cnt
	FROM   raw_events
	WHERE  timestamp >= now() - INTERVAL '10 seconds'
	GROUP  BY source_ip
	HAVING COUNT(*) >= 20
	ORDER  BY cnt DESC
	LIMIT  1
`

func scanRapidScan(row *sql.Row) (models.Incident, bool, error) {
	var ip string
	var cnt int
	if err := row.Scan(&ip, &cnt); err != nil {
		return models.Incident{}, false, err
	}
	return models.Incident{
		Type:       "siem_alert",
		AttackType: "rapid_scan",
		ClientIP:   ip,
		Severity:   "high",
		Message:    fmt.Sprintf("Rapid scan: %d requests from %s in 10s", cnt, ip),
		Source:     "duckdb-siem",
		Timestamp:  time.Now(),
	}, true, nil
}

// ── Rule 6: Data Exfiltration Detection ─────────────────────────────────────
// ≥50 successful requests from same IP in last 1 hour (large outbound)

const dataExfilSQL = `
	SELECT source_ip, COUNT(*) AS cnt
	FROM   raw_events
	WHERE  blocked = false
	  AND  status_code BETWEEN 200 AND 299
	  AND  timestamp >= now() - INTERVAL '1 hour'
	GROUP  BY source_ip
	HAVING COUNT(*) >= 50
	ORDER  BY cnt DESC
	LIMIT  1
`

func scanDataExfil(row *sql.Row) (models.Incident, bool, error) {
	var ip string
	var cnt int
	if err := row.Scan(&ip, &cnt); err != nil {
		return models.Incident{}, false, err
	}
	return models.Incident{
		Type:       "siem_alert",
		AttackType: "data_exfiltration",
		ClientIP:   ip,
		Severity:   "high",
		Message:    fmt.Sprintf("Possible exfiltration: %d successful requests from %s in 1h", cnt, ip),
		Source:     "duckdb-siem",
		Timestamp:  time.Now(),
	}, true, nil
}

// ── Rule 7: Geo Anomaly Detection ───────────────────────────────────────────
// Same IP hitting from 3+ distinct User-Agent strings in 10 minutes
// (fingerprint inconsistency = likely spoofed/botnet traffic)

const geoAnomalySQL = `
	SELECT source_ip, COUNT(DISTINCT user_agent) AS agents
	FROM   raw_events
	WHERE  timestamp >= now() - INTERVAL '10 minutes'
	  AND  user_agent != ''
	GROUP  BY source_ip
	HAVING COUNT(DISTINCT user_agent) >= 3
	ORDER  BY agents DESC
	LIMIT  1
`

func scanGeoAnomaly(row *sql.Row) (models.Incident, bool, error) {
	var ip string
	var agents int
	if err := row.Scan(&ip, &agents); err != nil {
		return models.Incident{}, false, err
	}
	return models.Incident{
		Type:       "siem_alert",
		AttackType: "geo_anomaly",
		ClientIP:   ip,
		Severity:   "medium",
		Message:    fmt.Sprintf("Geo anomaly: %s using %d distinct user-agents in 10m (possible spoofing)", ip, agents),
		Source:     "duckdb-siem",
		Timestamp:  time.Now(),
	}, true, nil
}

// ── Dashboard / Analytics queries (read-only, concurrent-safe) ──────────────

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

func (d *DuckDB) GetEventStats() (*EventStats, error) {
	stats := &EventStats{
		BySeverity: make(map[string]int64),
	}

	_ = d.roDB.QueryRow(`SELECT COUNT(*) FROM raw_events`).Scan(&stats.TotalEvents)
	_ = d.roDB.QueryRow(`SELECT COUNT(*) FROM raw_events WHERE blocked = true`).Scan(&stats.BlockedEvents)
	_ = d.roDB.QueryRow(`SELECT COUNT(DISTINCT source_ip) FROM raw_events`).Scan(&stats.UniqueIPs)
	_ = d.roDB.QueryRow(`SELECT COUNT(*) FROM raw_events WHERE timestamp >= now() - INTERVAL '1 hour'`).Scan(&stats.EventsLastHour)

	// Severity breakdown
	rows, err := d.roDB.Query(`
		SELECT severity, COUNT(*) AS cnt
		FROM   raw_events
		WHERE  severity != ''
		GROUP  BY severity
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var cnt int64
			if rows.Scan(&sev, &cnt) == nil {
				stats.BySeverity[sev] = cnt
			}
		}
	}

	// Top attack types
	aRows, err := d.roDB.Query(`
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

	// Minute-level timeline (last hour)
	tRows, err := d.roDB.Query(`
		SELECT date_trunc('minute', timestamp) AS minute, COUNT(*) AS cnt
		FROM   raw_events
		WHERE  timestamp >= now() - INTERVAL '1 hour'
		GROUP  BY date_trunc('minute', timestamp)
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
