-- TRAKSHYA-WAF PostgreSQL initialization
-- This script runs automatically when the postgres container starts for the first time

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Incidents table
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
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acknowledged INTEGER DEFAULT 0,
    acked_at TIMESTAMP,
    acked_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_client_ip ON incidents(client_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_attack_type ON incidents(attack_type);
CREATE INDEX IF NOT EXISTS idx_incidents_acknowledged ON incidents(acknowledged);

-- Rules table
CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    pattern TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_rules_category ON rules(category);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);

-- Blacklist table
CREATE TABLE IF NOT EXISTS blacklist (
    id TEXT PRIMARY KEY,
    ip TEXT NOT NULL UNIQUE,
    reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_blacklist_ip ON blacklist(ip);
CREATE INDEX IF NOT EXISTS idx_blacklist_expires ON blacklist(expires_at);

-- Request statistics
CREATE TABLE IF NOT EXISTS request_stats (
    client_ip TEXT PRIMARY KEY,
    request_count INTEGER NOT NULL DEFAULT 0,
    blocked_count INTEGER NOT NULL DEFAULT 0,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_request_stats_last_seen ON request_stats(last_seen);

-- Vulnerabilities table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    package_name TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    available_version TEXT,
    severity TEXT NOT NULL,
    cve_id TEXT,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vulns_package ON vulnerabilities(package_name);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id);

-- System config
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seed data
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

INSERT INTO rules (id, pattern, severity, category, description, enabled) VALUES
    ('SQLI-001', '(\bunion\b.*\bselect\b|\bdrop\b.*\btable\b)', 'critical', 'sqli', 'SQL Injection', 1),
    ('XSS-001', '(<script|javascript:|onerror=|onload=)', 'high', 'xss', 'Cross-Site Scripting', 1),
    ('TRAV-001', '(\.\./|\.\.\|%2e%2e)', 'high', 'path_traversal', 'Path Traversal', 1),
    ('CMDI-001', '(;\s*(cat|ls|rm|sh|bash)|`.*`|\$\(\))', 'critical', 'cmd_injection', 'Command Injection', 1),
    ('RFI-001', '(include=|require=|file=.*http)', 'medium', 'rfi', 'Remote File Inclusion', 1),
    ('LFI-001', '(\.\./etc/passwd|/proc/self)', 'high', 'lfi', 'Local File Inclusion', 1),
    ('SCANNER-001', '(wp-admin|phpmyadmin|/manager)', 'low', 'scanner', 'Scanner Detection', 1),
    ('BRUTE-001', '(/api/auth/login.*POST)', 'medium', 'brute_force', 'Brute Force', 1)
ON CONFLICT (id) DO NOTHING;
