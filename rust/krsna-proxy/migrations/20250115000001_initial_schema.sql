-- Initial schema for TRAKSHYA WAF dashboard

-- Incidents table - stores all security events
CREATE TABLE IF NOT EXISTS incidents (
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
    timestamp DATETIME NOT NULL DEFAULT (datetime('now')),
    acknowledged INTEGER NOT NULL DEFAULT 0,
    acked_at DATETIME,
    acked_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_client_ip ON incidents(client_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_attack_type ON incidents(attack_type);
CREATE INDEX IF NOT EXISTS idx_incidents_acknowledged ON incidents(acknowledged);

-- Rules table - WAF security rules
CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    pattern TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- Blacklist table - IP blacklist
CREATE TABLE IF NOT EXISTS blacklist (
    id TEXT PRIMARY KEY,
    ip TEXT NOT NULL UNIQUE,
    reason TEXT,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    expires_at DATETIME
);

-- Request stats table - aggregated request metrics per IP
CREATE TABLE IF NOT EXISTS request_stats (
    client_ip TEXT PRIMARY KEY,
    request_count INTEGER NOT NULL DEFAULT 0,
    blocked_count INTEGER NOT NULL DEFAULT 0,
    last_seen DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- Vulnerabilities table - package vulnerability tracking
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    package_name TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    available_version TEXT,
    severity TEXT NOT NULL,
    cve_id TEXT,
    description TEXT,
    created_at DATETIME NOT NULL DEFAULT (datetime('now')),
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_vulns_package ON vulnerabilities(package_name);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);

-- System config table - key-value configuration storage
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- Insert default rules
INSERT OR IGNORE INTO rules (id, pattern, severity, category, description, enabled, created_at, updated_at) VALUES
('SQLI-001', '(\\bunion\\b.*\\bselect\\b|\\bdrop\\b.*\\btable\\b)', 'critical', 'sqli', 'SQL Injection', 1, datetime('now'), datetime('now')),
('XSS-001', '(<script|javascript:|onerror=|onload=)', 'high', 'xss', 'Cross-Site Scripting', 1, datetime('now'), datetime('now')),
('TRAV-001', '(\\.\\./|\\.\\.\\\\|%2e%2e)', 'high', 'path_traversal', 'Path Traversal', 1, datetime('now'), datetime('now')),
('CMDI-001', '(;\\s*(cat|ls|rm|sh|bash)|`.*`|\\$\\()', 'critical', 'cmd_injection', 'Command Injection', 1, datetime('now'), datetime('now')),
('RFI-001', '(include=|require=|file=.*http)', 'medium', 'rfi', 'Remote File Inclusion', 1, datetime('now'), datetime('now')),
('LFI-001', '(\\.\\./etc/passwd|/proc/self)', 'high', 'lfi', 'Local File Inclusion', 1, datetime('now'), datetime('now')),
('SCANNER-001', '(wp-admin|phpmyadmin|/manager)', 'low', 'scanner', 'Scanner Detection', 1, datetime('now'), datetime('now')),
('BRUTE-001', '(/api/auth/login.*POST)', 'medium', 'brute_force', 'Brute Force', 1, datetime('now'), datetime('now'));

-- Insert default vulnerabilities for demo
INSERT OR IGNORE INTO vulnerabilities (id, package_name, installed_version, available_version, severity, cve_id, description) VALUES
('v1', 'openssl', '3.0.10', '3.0.13', 'critical', 'CVE-2024-0727', 'Critical security update for openssl'),
('v2', 'libssl3', '3.0.10', '3.0.13', 'critical', 'CVE-2024-2511', 'Critical security update for libssl3'),
('v3', 'curl', '7.88.1', '8.4.0', 'high', 'CVE-2024-2004', 'Security update available for curl'),
('v4', 'systemd', '252.19', '252.22', 'high', 'CVE-2024-2883', 'Security update available for systemd'),
('v5', 'sudo', '1.9.13', '1.9.15', 'high', 'CVE-2024-2883', 'Security update available for sudo'),
('v6', 'bash', '5.2.15', '5.2.21', 'medium', 'CVE-2024-2883', 'Package bash has an update available');
