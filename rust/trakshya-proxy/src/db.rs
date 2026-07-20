use anyhow::Result;
use chrono::{DateTime, Utc};
use duckdb::{params, Connection};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub incident_type: String,
    pub rule_id: String,
    pub attack_type: String,
    pub client_ip: String,
    pub path: String,
    pub method: String,
    pub severity: String,
    pub message: String,
    pub source: String,
    pub timestamp: DateTime<Utc>,
    pub acknowledged: bool,
    pub acked_at: Option<DateTime<Utc>>,
    pub acked_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub pattern: String,
    pub severity: String,
    pub category: String,
    pub description: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistEntry {
    pub id: String,
    pub ip: String,
    pub reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    pub total_requests: i64,
    pub blocked_requests: i64,
    pub active_ips: i64,
    pub incidents_today: i64,
    pub posture: String,
    pub uptime_seconds: i64,
    pub top_attacks: Vec<AttackCount>,
    pub recent_incidents: Vec<Incident>,
    pub agents_online: i64,
    pub rule_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackCount {
    pub attack_type: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoData {
    pub total_ips: i64,
    pub total_countries: i64,
    pub locations: Vec<GeoLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country_code: String,
    pub country_name: Option<String>,
    pub count: i64,
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SIEMAStats {
    pub total: i64,
    pub by_severity: SeverityCounts,
    pub unacknowledged: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnStats {
    pub total_cves: i64,
    pub avg_cvss: f64,
    pub total_packages: i64,
    pub by_severity: SeverityCounts,
    pub last_scan_status: String,
}

pub fn init_db(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
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
        CREATE TABLE IF NOT EXISTS blacklist (
            id TEXT PRIMARY KEY,
            ip TEXT NOT NULL UNIQUE,
            reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS request_stats (
            client_ip TEXT PRIMARY KEY,
            request_count INTEGER NOT NULL DEFAULT 0,
            blocked_count INTEGER NOT NULL DEFAULT 0,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
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
        CREATE TABLE IF NOT EXISTS system_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )?;
    Ok(())
}

pub fn record_incident(conn: &Connection, incident: &Incident) -> Result<()> {
    conn.execute(
        "INSERT INTO incidents (id, incident_type, rule_id, attack_type, client_ip, path, method, severity, message, source, timestamp, acknowledged)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        params![
            incident.id,
            incident.incident_type,
            incident.rule_id,
            incident.attack_type,
            incident.client_ip,
            incident.path,
            incident.method,
            incident.severity,
            incident.message,
            incident.source,
            incident.timestamp.to_rfc3339(),
            incident.acknowledged as i64,
        ],
    )?;
    Ok(())
}

pub fn record_request(conn: &Connection, client_ip: &str, blocked: bool) -> Result<()> {
    let blocked_val = if blocked { 1 } else { 0 };
    conn.execute(
        "INSERT INTO request_stats (client_ip, request_count, blocked_count, last_seen)
         VALUES ($1, 1, $2, CURRENT_TIMESTAMP)
         ON CONFLICT(client_ip) DO UPDATE SET
             request_count = request_stats.request_count + 1,
             blocked_count = request_stats.blocked_count + $3,
             last_seen = CURRENT_TIMESTAMP",
        params![client_ip, blocked_val, blocked_val],
    )?;
    Ok(())
}

pub fn get_dashboard_stats(
    conn: &Connection,
    posture: &str,
    rule_count: i64,
    uptime: i64,
) -> Result<DashboardStats> {
    let total_requests: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(request_count), 0) FROM request_stats",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let blocked_requests: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(blocked_count), 0) FROM request_stats",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let active_ips: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM request_stats WHERE last_seen > NOW() - INTERVAL '5 minutes'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let incidents_today: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM incidents WHERE timestamp > NOW() - INTERVAL '1 day'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let mut top_attacks = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT attack_type, COUNT(*) as count FROM incidents WHERE timestamp > NOW() - INTERVAL '1 day' GROUP BY attack_type ORDER BY count DESC LIMIT 10",
    ) {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok(AttackCount {
                attack_type: row.get(0)?,
                count: row.get(1)?,
            })
        }) {
            for r in rows.flatten() {
                top_attacks.push(r);
            }
        }
    }

    let mut recent_incidents = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        "SELECT id, incident_type, rule_id, attack_type, client_ip, path, method, severity, message, source, timestamp, acknowledged FROM incidents ORDER BY timestamp DESC LIMIT 20",
    ) {
        if let Ok(rows) = stmt.query_map([], |row| {
            let ts_str: String = row.get(10)?;
            let ts = DateTime::parse_from_rfc3339(&ts_str)
                .unwrap_or_default()
                .with_timezone(&Utc);
            Ok(Incident {
                id: row.get(0)?,
                incident_type: row.get(1)?,
                rule_id: row.get(2)?,
                attack_type: row.get(3)?,
                client_ip: row.get(4)?,
                path: row.get(5)?,
                method: row.get(6)?,
                severity: row.get(7)?,
                message: row.get(8)?,
                source: row.get(9)?,
                timestamp: ts,
                acknowledged: row.get::<_, i64>(11)? != 0,
                acked_at: None,
                acked_by: None,
            })
        }) {
            for r in rows.flatten() {
                recent_incidents.push(r);
            }
        }
    }

    Ok(DashboardStats {
        total_requests,
        blocked_requests,
        active_ips,
        incidents_today,
        posture: posture.to_string(),
        uptime_seconds: uptime,
        top_attacks,
        recent_incidents,
        agents_online: 3,
        rule_count,
    })
}

pub fn get_geo_data(conn: &Connection) -> Result<GeoData> {
    let total_ips: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT client_ip) FROM incidents WHERE timestamp > NOW() - INTERVAL '1 day'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let country_coords = [
        ("US", 40.7128, -74.0060),
        ("DE", 52.5200, 13.4050),
        ("IN", 28.6139, 77.2090),
        ("RU", 55.7558, 37.6173),
        ("CN", 39.9042, 116.4074),
        ("BR", -15.7942, -47.8825),
        ("GB", 51.5074, -0.1278),
        ("FR", 48.8566, 2.3522),
        ("JP", 35.6762, 139.6503),
        ("AU", -33.8688, 151.2093),
    ];

    let mut locations = Vec::new();
    if let Ok(mut stmt) = conn.prepare(
        r#"
        SELECT
            CASE
                WHEN client_ip LIKE '192.168.%' THEN 'US'
                WHEN client_ip LIKE '10.0.%' THEN 'DE'
                WHEN client_ip LIKE '172.16.%' THEN 'IN'
                WHEN client_ip LIKE '203.0.113.%' THEN 'RU'
                WHEN client_ip LIKE '198.51.100.%' THEN 'CN'
                WHEN client_ip LIKE '45.33.32.%' THEN 'BR'
                WHEN client_ip LIKE '104.236.228.%' THEN 'GB'
                WHEN client_ip LIKE '185.220.101.%' THEN 'FR'
                ELSE 'XX'
            END as country_code,
            COUNT(*) as count
        FROM incidents
        WHERE timestamp > NOW() - INTERVAL '1 day'
        GROUP BY country_code
        "#,
    ) {
        if let Ok(rows) = stmt.query_map([], |row| {
            let code: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            Ok((code, count))
        }) {
            for r in rows.flatten() {
                let (code, count) = r;
                if let Some((_, lat, lng)) = country_coords.iter().find(|(c, _, _)| *c == code.as_str()) {
                    locations.push(GeoLocation {
                        country_code: code,
                        country_name: None,
                        count,
                        latitude: *lat,
                        longitude: *lng,
                    });
                }
            }
        }
    }

    let total_countries = locations.len() as i64;
    Ok(GeoData {
        total_ips,
        total_countries,
        locations,
    })
}

pub fn get_siem_stats(conn: &Connection) -> Result<SIEMAStats> {
    let total: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM incidents WHERE timestamp > NOW() - INTERVAL '7 days'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let critical: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM incidents WHERE severity = 'critical' AND timestamp > NOW() - INTERVAL '7 days'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let high: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM incidents WHERE severity = 'high' AND timestamp > NOW() - INTERVAL '7 days'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let medium: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM incidents WHERE severity = 'medium' AND timestamp > NOW() - INTERVAL '7 days'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let low: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM incidents WHERE severity = 'low' AND timestamp > NOW() - INTERVAL '7 days'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let unacknowledged: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM incidents WHERE acknowledged = 0 AND timestamp > NOW() - INTERVAL '7 days'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    Ok(SIEMAStats {
        total,
        by_severity: SeverityCounts {
            critical,
            high,
            medium,
            low,
        },
        unacknowledged,
    })
}

pub fn get_siem_alerts(conn: &Connection, limit: i64, offset: i64) -> Result<Vec<Incident>> {
    let mut stmt = conn.prepare(
        "SELECT id, incident_type, rule_id, attack_type, client_ip, path, method, severity, message, source, timestamp, acknowledged FROM incidents WHERE timestamp > NOW() - INTERVAL '7 days' ORDER BY timestamp DESC LIMIT $1 OFFSET $2",
    )?;

    let rows = stmt.query_map(params![limit, offset], |row| {
        let ts_str: String = row.get(10)?;
        let ts = DateTime::parse_from_rfc3339(&ts_str)
            .unwrap_or_default()
            .with_timezone(&Utc);
        Ok(Incident {
            id: row.get(0)?,
            incident_type: row.get(1)?,
            rule_id: row.get(2)?,
            attack_type: row.get(3)?,
            client_ip: row.get(4)?,
            path: row.get(5)?,
            method: row.get(6)?,
            severity: row.get(7)?,
            message: row.get(8)?,
            source: row.get(9)?,
            timestamp: ts,
            acknowledged: row.get::<_, i64>(11)? != 0,
            acked_at: None,
            acked_by: None,
        })
    })?;

    Ok(rows.filter_map(|r| r.ok()).collect())
}

pub fn get_rules(conn: &Connection, enabled: Option<bool>) -> Result<Vec<Rule>> {
    let mut stmt = if let Some(enabled_val) = enabled {
        conn.prepare("SELECT id, pattern, severity, category, description, enabled, created_at, updated_at FROM rules WHERE enabled = $1 ORDER BY id")?
    } else {
        conn.prepare("SELECT id, pattern, severity, category, description, enabled, created_at, updated_at FROM rules ORDER BY id")?
    };

    let params: Vec<Box<dyn duckdb::types::ToSql>> = if let Some(v) = enabled {
        vec![Box::new(v as i64)]
    } else {
        vec![]
    };

    let param_refs: Vec<&dyn duckdb::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    let rows = stmt.query_map(param_refs.as_slice(), |row| {
        let created_str: String = row.get(6)?;
        let updated_str: String = row.get(7)?;
        Ok(Rule {
            id: row.get(0)?,
            pattern: row.get(1)?,
            severity: row.get(2)?,
            category: row.get(3)?,
            description: row.get(4)?,
            enabled: row.get::<_, i64>(5)? != 0,
            created_at: DateTime::parse_from_rfc3339(&created_str)
                .unwrap_or_default()
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&updated_str)
                .unwrap_or_default()
                .with_timezone(&Utc),
        })
    })?;

    Ok(rows.filter_map(|r| r.ok()).collect())
}

pub fn create_rule(conn: &Connection, rule: &Rule) -> Result<()> {
    conn.execute(
        "INSERT INTO rules (id, pattern, severity, category, description, enabled, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        params![
            rule.id,
            rule.pattern,
            rule.severity,
            rule.category,
            rule.description,
            rule.enabled as i64,
            rule.created_at.to_rfc3339(),
            rule.updated_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

pub fn delete_rule(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM rules WHERE id = $1", params![id])?;
    Ok(())
}

pub fn get_blacklist(conn: &Connection) -> Result<Vec<BlacklistEntry>> {
    let mut stmt = conn.prepare(
        "SELECT id, ip, reason, created_at, expires_at FROM blacklist WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP ORDER BY created_at DESC",
    )?;

    let rows = stmt.query_map([], |row| {
        let created_str: String = row.get(3)?;
        let expires_str: Option<String> = row.get(4)?;
        Ok(BlacklistEntry {
            id: row.get(0)?,
            ip: row.get(1)?,
            reason: row.get(2)?,
            created_at: DateTime::parse_from_rfc3339(&created_str)
                .unwrap_or_default()
                .with_timezone(&Utc),
            expires_at: expires_str.and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            }),
        })
    })?;

    Ok(rows.filter_map(|r| r.ok()).collect())
}

pub fn add_to_blacklist(conn: &Connection, ip: &str, reason: Option<&str>) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO blacklist (id, ip, reason) VALUES ($1, $2, $3) ON CONFLICT(ip) DO NOTHING",
        params![id, ip, reason],
    )?;
    Ok(())
}

pub fn remove_from_blacklist(conn: &Connection, ip: &str) -> Result<()> {
    conn.execute("DELETE FROM blacklist WHERE ip = $1", params![ip])?;
    Ok(())
}

pub fn get_vuln_stats(conn: &Connection) -> Result<VulnStats> {
    let total_cves: i64 = conn
        .query_row("SELECT COUNT(*) FROM vulnerabilities", [], |row| {
            row.get(0)
        })
        .unwrap_or(0);

    let avg_cvss: f64 = conn
        .query_row(
            "SELECT COALESCE(AVG(CASE severity WHEN 'critical' THEN 9.5 WHEN 'high' THEN 7.5 WHEN 'medium' THEN 5.0 WHEN 'low' THEN 2.5 ELSE 0 END), 0) FROM vulnerabilities",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0.0);

    let total_packages: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT package_name) FROM vulnerabilities",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let critical: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'critical'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let high: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'high'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let medium: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'medium'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let low: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'low'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    Ok(VulnStats {
        total_cves,
        avg_cvss,
        total_packages,
        by_severity: SeverityCounts {
            critical,
            high,
            medium,
            low,
        },
        last_scan_status: "completed".to_string(),
    })
}

pub fn get_vulnerabilities(conn: &Connection) -> Result<Vec<serde_json::Value>> {
    let mut stmt = conn.prepare(
        "SELECT id, package_name, installed_version, available_version, severity, cve_id, description FROM vulnerabilities ORDER BY
            CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
            package_name",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(serde_json::json!({
            "id": row.get::<_, String>(0)?,
            "package": row.get::<_, String>(1)?,
            "installed_version": row.get::<_, String>(2)?,
            "available_version": row.get::<_, String>(3)?,
            "severity": row.get::<_, String>(4)?,
            "cve": row.get::<_, String>(5)?,
            "description": row.get::<_, String>(6)?,
        }))
    })?;

    Ok(rows.filter_map(|r| r.ok()).collect())
}

pub fn update_config(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO system_config (key, value) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP",
        params![key, value],
    )?;
    Ok(())
}

pub fn get_rule_count(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM rules", [], |row| row.get(0))
        .unwrap_or(0)
}
