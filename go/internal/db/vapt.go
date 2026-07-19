package db

import (
	"database/sql"
	"fmt"

	"github.com/trakshya/trakshya-api/pkg/models"
)

func (s *Postgres) RunVaptMigrations() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS vapt_scans (
			id TEXT PRIMARY KEY,
			status TEXT DEFAULT 'running',
			target TEXT NOT NULL,
			started_at TIMESTAMP,
			completed_at TIMESTAMP,
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
			remediation TEXT,
			FOREIGN KEY(scan_id) REFERENCES vapt_scans(id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vapt_findings_scan ON vapt_findings(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vapt_findings_severity ON vapt_findings(severity)`,
	}

	for _, m := range migrations {
		if _, err := s.db.Exec(m); err != nil {
			return fmt.Errorf("vapt migration failed: %w", err)
		}
	}
	return nil
}

func (s *Postgres) CreateVaptScan(scan *models.VaptScan) error {
	query := `INSERT INTO vapt_scans (id, status, target, started_at, completed_at, total_probes)
		VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := s.db.Exec(query, scan.ID, scan.Status, scan.Target, scan.StartedAt, scan.CompletedAt, scan.TotalProbes)
	return err
}

func (s *Postgres) UpdateVaptScan(scan *models.VaptScan) error {
	query := `UPDATE vapt_scans SET status=$1, completed_at=$2, total_probes=$3 WHERE id=$4`
	result, err := s.db.Exec(query, scan.Status, scan.CompletedAt, scan.TotalProbes, scan.ID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("vapt scan not found: %s", scan.ID)
	}
	return nil
}

func (s *Postgres) GetVaptScan(id string) (*models.VaptScan, error) {
	var scan models.VaptScan
	query := `SELECT id, status, target, started_at, completed_at, total_probes FROM vapt_scans WHERE id=$1`
	err := s.db.QueryRow(query, id).Scan(&scan.ID, &scan.Status, &scan.Target, &scan.StartedAt, &scan.CompletedAt, &scan.TotalProbes)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	scan.Findings, _ = s.ListVaptFindings(id)
	return &scan, nil
}

func (s *Postgres) ListVaptScans(limit int) ([]models.VaptScan, error) {
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
		if err := rows.Scan(&scan.ID, &scan.Status, &scan.Target, &scan.StartedAt, &scan.CompletedAt, &scan.TotalProbes); err != nil {
			return nil, err
		}
		scans = append(scans, scan)
	}
	if scans == nil {
		scans = []models.VaptScan{}
	}
	return scans, nil
}

func (s *Postgres) CreateVaptFinding(f *models.VaptFinding) error {
	query := `INSERT INTO vapt_findings (id, scan_id, category, severity, title, description, evidence, remediation)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := s.db.Exec(query, f.ID, f.ScanID, f.Category, f.Severity, f.Title, f.Description, f.Evidence, f.Remediation)
	return err
}

func (s *Postgres) ListVaptFindings(scanID string) ([]models.VaptFinding, error) {
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

func (s *Postgres) ListAllVaptFindings() ([]models.VaptFinding, error) {
	query := `SELECT f.id, f.scan_id, f.category, f.severity, f.title, f.description, f.evidence, f.remediation
		FROM vapt_findings f
		INNER JOIN vapt_scans s ON f.scan_id = s.id
		WHERE s.id = (SELECT id FROM vapt_scans ORDER BY started_at DESC LIMIT 1)
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

func (s *Postgres) GetVaptStats() (*models.VaptStats, error) {
	stats := &models.VaptStats{BySeverity: make(map[string]int)}

	lastScanQuery := `SELECT id, status, started_at, total_probes FROM vapt_scans ORDER BY started_at DESC LIMIT 1`
	var lastScanID, lastStatus string
	var lastStarted sql.NullTime
	var lastProbes int
	err := s.db.QueryRow(lastScanQuery).Scan(&lastScanID, &lastStatus, &lastStarted, &lastProbes)
	if err == nil {
		stats.LastScanStatus = lastStatus
		stats.TotalProbes = lastProbes
		if lastStarted.Valid {
			stats.LastScanTime = &lastStarted.Time
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
