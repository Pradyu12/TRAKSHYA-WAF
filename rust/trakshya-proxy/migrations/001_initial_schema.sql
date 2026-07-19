-- Initial schema for TRAKSHYA WAF dashboard
-- Run with: sqlx migrate run

-- Incidents table - stores all security events
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    incident_type TEXT NOT NULL,           -- 'attack_blocked', 'siem_alert', 'rate_limit', 'geo_block'
    rule_id TEXT,
    attack_type TEXT,                      -- 'sql_injection', 'xss', 'path_traversal', etc.
    client_ip TEXT NOT NULL,
    path TEXT,
    method TEXT,
    severity TEXT NOT NULL,                -- 'critical', 'high', 'medium', 'low', 'info'
    message TEXT,
    source TEXT,                           -- 'trakshya-proxy', 'trakshya-systemd', 'manual'
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    acked_at TIMESTAMP,
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
    severity TEXT NOT NULL,                -- 'critical', 'high', 'medium', 'low'
    category TEXT NOT NULL,                -- 'sqli', 'xss', 'path_traversal', 'cmd_injection', 'scanner', 'rfi', 'lfi', 'brute_force'
    description TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_rules_category ON rules(category);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);

-- Blacklist table - blocked IPs
CREATE TABLE IF NOT EXISTS blacklist (
    id TEXT PRIMARY KEY,
    ip TEXT NOT NULL UNIQUE,
    reason TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_blacklist_ip ON blacklist(ip);
CREATE INDEX IF NOT EXISTS idx_blacklist_expires ON blacklist(expires_at);

-- Request statistics - aggregated per IP
CREATE TABLE IF NOT EXISTS request_stats (
    client_ip TEXT PRIMARY KEY,
    request_count INTEGER NOT NULL DEFAULT 0,
    blocked_count INTEGER NOT NULL DEFAULT 0,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_request_stats_last_seen ON request_stats(last_seen);

-- Vulnerabilities table - package vulnerabilities
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    package_name TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    available_version TEXT,
    severity TEXT NOT NULL,                -- 'critical', 'high', 'medium', 'low'
    cve_id TEXT,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vulns_package ON vulnerabilities(package_name);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id);

-- System config table - key-value settings
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Insert default config values
INSERT INTO system_config (key, value) VALUES
    ('posture', 'monitor'),
    ('rate_limit_enabled', '1'),
    ('circuit_breaker_enabled', '1'),
    ('geoip_enabled', '0'),
    ('jwt_enabled', '0'),
    ('proxy_port', '8080'),
    ('upstream_url', 'http://localhost:3000'),
    ('management_api_url', 'http://localhost:8000')
ON CONFLICT (key) DO NOTHING;

-- Insert sample vulnerabilities for demo
INSERT INTO vulnerabilities (id, package_name, installed_version, available_version, severity, cve_id, description) VALUES
    ('v1', 'openssl', '3.0.10', '3.0.13', 'critical', 'CVE-2024-0727', 'Critical security update for openssl'),
    ('v2', 'libssl3', '3.0.10', '3.0.13', 'critical', 'CVE-2024-2511', 'Critical security update for libssl3'),
    ('v3', 'curl', '7.88.1', '8.4.0', 'high', 'CVE-2024-2004', 'Security update available for curl'),
    ('v4', 'systemd', '252.19', '252.22', 'high', 'CVE-2024-2883', 'Security update available for systemd'),
    ('v5', 'sudo', '1.9.13', '1.9.15', 'high', 'CVE-2024-2883', 'Security update available for sudo'),
    ('v6', 'bash', '5.2.15', '5.2.21', 'medium', 'CVE-2024-2883', 'Package bash has an update available')
ON CONFLICT (id) DO NOTHING;

-- Insert default rules
INSERT INTO rules (id, pattern, severity, category, description, enabled) VALUES
    ('SQLI-001', '(\\bunion\\b.*\\bselect\\b|\\bdrop\\b.*\\btable\\b)', 'critical', 'sqli', 'SQL Injection', 1),
    ('XSS-001', '(<script|javascript:|onerror=|onload=)', 'high', 'xss', 'Cross-Site Scripting', 1),
    ('TRAV-001', '(\\.\\./|\\.\\.\\|%2e%2e)', 'high', 'path_traversal', 'Path Traversal', 1),
    ('CMDI-001', '(;\\s*(cat|ls|rm|sh|bash)|`.*`|\\$\\()', 'critical', 'cmd_injection', 'Command Injection', 1),
    ('RFI-001', '(include=|require=|file=.*http)', 'medium', 'rfi', 'Remote File Inclusion', 1),
    ('LFI-001', '(\\.\\./etc/passwd|/proc/self)', 'high', 'lfi', 'Local File Inclusion', 1),
    ('SCANNER-001', '(wp-admin|phpmyadmin|/manager)', 'low', 'scanner', 'Scanner Detection', 1),
    ('BRUTE-001', '(/api/auth/login.*POST)', 'medium', 'brute_force', 'Brute Force', 1)
ON CONFLICT (id) DO NOTHING;
