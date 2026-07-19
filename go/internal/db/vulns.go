package db

import (
	"database/sql"
	"fmt"

	"github.com/trakshya/trakshya-api/pkg/models"
)

func (s *Postgres) RunVulnMigrations() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS vuln_scans (
			id TEXT PRIMARY KEY,
			status TEXT DEFAULT 'running',
			target TEXT NOT NULL,
			started_at TIMESTAMP,
			completed_at TIMESTAMP,
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
			category TEXT,
			FOREIGN KEY(scan_id) REFERENCES vuln_scans(id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_findings_scan ON vuln_findings(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vuln_findings_severity ON vuln_findings(severity)`,
	}

	for _, m := range migrations {
		if _, err := s.db.Exec(m); err != nil {
			return fmt.Errorf("vuln migration failed: %w", err)
		}
	}
	return nil
}

func (s *Postgres) CreateVulnScan(scan *models.VulnScan) error {
	query := `INSERT INTO vuln_scans (id, status, target, started_at, completed_at, total_pkgs, total_cves)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := s.db.Exec(query, scan.ID, scan.Status, scan.Target, scan.StartedAt, scan.CompletedAt, scan.TotalPkgs, scan.TotalCVEs)
	return err
}

func (s *Postgres) UpdateVulnScan(scan *models.VulnScan) error {
	query := `UPDATE vuln_scans SET status=$1, completed_at=$2, total_pkgs=$3, total_cves=$4 WHERE id=$5`
	result, err := s.db.Exec(query, scan.Status, scan.CompletedAt, scan.TotalPkgs, scan.TotalCVEs, scan.ID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("scan not found: %s", scan.ID)
	}
	return nil
}

func (s *Postgres) GetVulnScan(id string) (*models.VulnScan, error) {
	var scan models.VulnScan
	query := `SELECT id, status, target, started_at, completed_at, total_pkgs, total_cves FROM vuln_scans WHERE id=$1`
	err := s.db.QueryRow(query, id).Scan(&scan.ID, &scan.Status, &scan.Target, &scan.StartedAt, &scan.CompletedAt, &scan.TotalPkgs, &scan.TotalCVEs)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	scan.Findings, _ = s.ListVulnFindings(id)
	return &scan, nil
}

func (s *Postgres) ListVulnScans(limit int) ([]models.VulnScan, error) {
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
		if err := rows.Scan(&scan.ID, &scan.Status, &scan.Target, &scan.StartedAt, &scan.CompletedAt, &scan.TotalPkgs, &scan.TotalCVEs); err != nil {
			return nil, err
		}
		scans = append(scans, scan)
	}
	if scans == nil {
		scans = []models.VulnScan{}
	}
	return scans, nil
}

func (s *Postgres) CreateVulnFinding(f *models.VulnFinding) error {
	query := `INSERT INTO vuln_findings (id, scan_id, package, installed_version, available_version, severity, cve, description, category)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := s.db.Exec(query, f.ID, f.ScanID, f.Package, f.Installed, f.Available, f.Severity, f.CVE, f.Description, f.Category)
	return err
}

func (s *Postgres) ListVulnFindings(scanID string) ([]models.VulnFinding, error) {
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

func (s *Postgres) ListAllVulnFindings() ([]models.VulnFinding, error) {
	query := `SELECT f.id, f.scan_id, f.package, f.installed_version, f.available_version, f.severity, f.cve, f.description, f.category
		FROM vuln_findings f
		INNER JOIN vuln_scans s ON f.scan_id = s.id
		WHERE s.id = (SELECT id FROM vuln_scans ORDER BY started_at DESC LIMIT 1)
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

func (s *Postgres) GetVulnStats() (*models.VulnStats, error) {
	stats := &models.VulnStats{
		BySeverity: make(map[string]int),
	}

	lastScanQuery := `SELECT id, status, started_at, total_pkgs, total_cves FROM vuln_scans ORDER BY started_at DESC LIMIT 1`
	var lastScanID, lastStatus string
	var lastStarted sql.NullTime
	var lastPkgs, lastCVEs int
	err := s.db.QueryRow(lastScanQuery).Scan(&lastScanID, &lastStatus, &lastStarted, &lastPkgs, &lastCVEs)
	if err == nil {
		stats.LastScanStatus = lastStatus
		stats.TotalPackages = lastPkgs
		stats.TotalCVEs = lastCVEs
		if lastStarted.Valid {
			stats.LastScanTime = &lastStarted.Time
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
