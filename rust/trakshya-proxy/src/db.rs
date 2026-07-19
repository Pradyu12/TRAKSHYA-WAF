use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::time::Duration;
use uuid::Uuid;

pub type DbPool = PgPool;

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

pub async fn init_pool(database_url: &str) -> Result<DbPool> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(30))
        .connect(database_url)
        .await?;

    sqlx::migrate!(".//migrations").run(&pool).await?;

    Ok(pool)
}

pub async fn record_incident(pool: &DbPool, incident: &Incident) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO incidents (id, incident_type, rule_id, attack_type, client_ip, path, method, severity, message, source, timestamp, acknowledged)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#
    )
    .bind(&incident.id)
    .bind(&incident.incident_type)
    .bind(&incident.rule_id)
    .bind(&incident.attack_type)
    .bind(&incident.client_ip)
    .bind(&incident.path)
    .bind(&incident.method)
    .bind(&incident.severity)
    .bind(&incident.message)
    .bind(&incident.source)
    .bind(incident.timestamp.to_rfc3339())
    .bind(incident.acknowledged)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn record_request(pool: &DbPool, client_ip: &str, blocked: bool) -> Result<()> {
    let blocked_val = if blocked { 1 } else { 0 };

    sqlx::query(
        r#"
        INSERT INTO request_stats (client_ip, request_count, blocked_count, last_seen)
        VALUES ($1, 1, $2, CURRENT_TIMESTAMP)
        ON CONFLICT(client_ip) DO UPDATE SET
            request_count = request_stats.request_count + 1,
            blocked_count = request_stats.blocked_count + $3,
            last_seen = CURRENT_TIMESTAMP
        "#,
    )
    .bind(client_ip)
    .bind(blocked_val)
    .bind(blocked_val)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_dashboard_stats(
    pool: &DbPool,
    posture: &str,
    rule_count: i64,
    uptime: i64,
) -> Result<DashboardStats> {
    let total_requests: i64 =
        sqlx::query_scalar("SELECT COALESCE(SUM(request_count), 0) FROM request_stats")
            .fetch_one(pool)
            .await?;

    let blocked_requests: i64 =
        sqlx::query_scalar("SELECT COALESCE(SUM(blocked_count), 0) FROM request_stats")
            .fetch_one(pool)
            .await?;

    let active_ips: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM request_stats WHERE last_seen > NOW() - INTERVAL '5 minutes'",
    )
    .fetch_one(pool)
    .await?;

    let incidents_today: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM incidents WHERE timestamp > NOW() - INTERVAL '1 day'",
    )
    .fetch_one(pool)
    .await?;

    let top_attacks_rows = sqlx::query(
        "SELECT attack_type, COUNT(*) as count FROM incidents WHERE timestamp > NOW() - INTERVAL '1 day' GROUP BY attack_type ORDER BY count DESC LIMIT 10"
    )
    .fetch_all(pool)
    .await?;

    let top_attacks = top_attacks_rows
        .into_iter()
        .map(|r| AttackCount {
            attack_type: r.get("attack_type"),
            count: r.get("count"),
        })
        .collect();

    let recent_incidents_rows = sqlx::query(
        "SELECT id, incident_type, rule_id, attack_type, client_ip, path, method, severity, message, source, timestamp, acknowledged FROM incidents ORDER BY timestamp DESC LIMIT 20"
    )
    .fetch_all(pool)
    .await?;

    let recent_incidents = recent_incidents_rows
        .into_iter()
        .map(|r| Incident {
            id: r.get("id"),
            incident_type: r.get("incident_type"),
            rule_id: r.get("rule_id"),
            attack_type: r.get("attack_type"),
            client_ip: r.get("client_ip"),
            path: r.get("path"),
            method: r.get("method"),
            severity: r.get("severity"),
            message: r.get("message"),
            source: r.get("source"),
            timestamp: DateTime::parse_from_rfc3339(&r.get::<String, _>("timestamp"))
                .unwrap()
                .with_timezone(&Utc),
            acknowledged: r.get::<i64, _>("acknowledged") != 0,
            acked_at: None,
            acked_by: None,
        })
        .collect();

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

pub async fn get_geo_data(pool: &DbPool) -> Result<GeoData> {
    let total_ips: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT client_ip) FROM incidents WHERE timestamp > NOW() - INTERVAL '1 day'")
        .fetch_one(pool)
        .await?;

    let locations_rows = sqlx::query(
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
    )
    .fetch_all(pool)
    .await?;

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
    for row in locations_rows {
        let country_code: String = row.get("country_code");
        let count: i64 = row.get("count");

        if let Some((_, lat, lng)) = country_coords
            .iter()
            .find(|(c, _, _)| *c == country_code.as_str())
        {
            locations.push(GeoLocation {
                country_code,
                country_name: None,
                count,
                latitude: *lat,
                longitude: *lng,
            });
        }
    }

    let total_countries = locations.len() as i64;

    Ok(GeoData {
        total_ips,
        total_countries,
        locations,
    })
}

pub async fn get_siem_stats(pool: &DbPool) -> Result<SIEMAStats> {
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM incidents WHERE timestamp > NOW() - INTERVAL '7 days'",
    )
    .fetch_one(pool)
    .await?;

    let critical: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE severity = 'critical' AND timestamp > NOW() - INTERVAL '7 days'")
        .fetch_one(pool)
        .await?;

    let high: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE severity = 'high' AND timestamp > NOW() - INTERVAL '7 days'")
        .fetch_one(pool)
        .await?;

    let medium: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE severity = 'medium' AND timestamp > NOW() - INTERVAL '7 days'")
        .fetch_one(pool)
        .await?;

    let low: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE severity = 'low' AND timestamp > NOW() - INTERVAL '7 days'")
        .fetch_one(pool)
        .await?;

    let unacknowledged: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE acknowledged = 0 AND timestamp > NOW() - INTERVAL '7 days'")
        .fetch_one(pool)
        .await?;

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

pub async fn get_siem_alerts(pool: &DbPool, limit: i64, offset: i64) -> Result<Vec<Incident>> {
    let rows = sqlx::query(
        "SELECT id, incident_type, rule_id, attack_type, client_ip, path, method, severity, message, source, timestamp, acknowledged FROM incidents WHERE timestamp > NOW() - INTERVAL '7 days' ORDER BY timestamp DESC LIMIT $1 OFFSET $2"
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| Incident {
            id: r.get("id"),
            incident_type: r.get("incident_type"),
            rule_id: r.get("rule_id"),
            attack_type: r.get("attack_type"),
            client_ip: r.get("client_ip"),
            path: r.get("path"),
            method: r.get("method"),
            severity: r.get("severity"),
            message: r.get("message"),
            source: r.get("source"),
            timestamp: DateTime::parse_from_rfc3339(&r.get::<String, _>("timestamp"))
                .unwrap()
                .with_timezone(&Utc),
            acknowledged: r.get::<i64, _>("acknowledged") != 0,
            acked_at: None,
            acked_by: None,
        })
        .collect())
}

pub async fn get_rules(pool: &DbPool, enabled: Option<bool>) -> Result<Vec<Rule>> {
    let rows = if let Some(enabled_val) = enabled {
        sqlx::query("SELECT id, pattern, severity, category, description, enabled, created_at, updated_at FROM rules WHERE enabled = $1 ORDER BY id")
            .bind(enabled_val as i64)
            .fetch_all(pool)
            .await?
    } else {
        sqlx::query("SELECT id, pattern, severity, category, description, enabled, created_at, updated_at FROM rules ORDER BY id")
            .fetch_all(pool)
            .await?
    };

    Ok(rows
        .into_iter()
        .map(|r| Rule {
            id: r.get("id"),
            pattern: r.get("pattern"),
            severity: r.get("severity"),
            category: r.get("category"),
            description: r.get("description"),
            enabled: r.get::<i64, _>("enabled") != 0,
            created_at: DateTime::parse_from_rfc3339(&r.get::<String, _>("created_at"))
                .unwrap()
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&r.get::<String, _>("updated_at"))
                .unwrap()
                .with_timezone(&Utc),
        })
        .collect())
}

pub async fn create_rule(pool: &DbPool, rule: &Rule) -> Result<()> {
    sqlx::query(
        "INSERT INTO rules (id, pattern, severity, category, description, enabled, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    )
    .bind(&rule.id)
    .bind(&rule.pattern)
    .bind(&rule.severity)
    .bind(&rule.category)
    .bind(&rule.description)
    .bind(rule.enabled as i64)
    .bind(rule.created_at.to_rfc3339())
    .bind(rule.updated_at.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn delete_rule(pool: &DbPool, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM rules WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn get_blacklist(pool: &DbPool) -> Result<Vec<BlacklistEntry>> {
    let rows = sqlx::query("SELECT id, ip, reason, created_at, expires_at FROM blacklist WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP ORDER BY created_at DESC")
        .fetch_all(pool)
        .await?;

    Ok(rows
        .into_iter()
        .map(|r| BlacklistEntry {
            id: r.get("id"),
            ip: r.get("ip"),
            reason: r.get("reason"),
            created_at: DateTime::parse_from_rfc3339(&r.get::<String, _>("created_at"))
                .unwrap()
                .with_timezone(&Utc),
            expires_at: r.get::<Option<String>, _>("expires_at").map(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .unwrap()
                    .with_timezone(&Utc)
            }),
        })
        .collect())
}

pub async fn add_to_blacklist(pool: &DbPool, ip: &str, reason: Option<&str>) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO blacklist (id, ip, reason) VALUES ($1, $2, $3) ON CONFLICT(ip) DO NOTHING",
    )
    .bind(&id)
    .bind(ip)
    .bind(reason)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn remove_from_blacklist(pool: &DbPool, ip: &str) -> Result<()> {
    sqlx::query("DELETE FROM blacklist WHERE ip = $1")
        .bind(ip)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn get_vuln_stats(pool: &DbPool) -> Result<VulnStats> {
    let total_cves: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vulnerabilities")
        .fetch_one(pool)
        .await?;
    let avg_cvss: f64 = sqlx::query_scalar("SELECT COALESCE(AVG(CASE severity WHEN 'critical' THEN 9.5 WHEN 'high' THEN 7.5 WHEN 'medium' THEN 5.0 WHEN 'low' THEN 2.5 ELSE 0 END), 0) FROM vulnerabilities").fetch_one(pool).await?;
    let total_packages: i64 =
        sqlx::query_scalar("SELECT COUNT(DISTINCT package_name) FROM vulnerabilities")
            .fetch_one(pool)
            .await?;

    let critical: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'critical'")
            .fetch_one(pool)
            .await?;
    let high: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'high'")
            .fetch_one(pool)
            .await?;
    let medium: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'medium'")
            .fetch_one(pool)
            .await?;
    let low: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'low'")
            .fetch_one(pool)
            .await?;

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

pub async fn get_vulnerabilities(pool: &DbPool) -> Result<Vec<serde_json::Value>> {
    let rows = sqlx::query(
        "SELECT id, package_name, installed_version, available_version, severity, cve_id, description FROM vulnerabilities ORDER BY
            CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
            package_name"
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.get::<String, _>("id"),
                "package": r.get::<String, _>("package_name"),
                "installed_version": r.get::<String, _>("installed_version"),
                "available_version": r.get::<String, _>("available_version"),
                "severity": r.get::<String, _>("severity"),
                "cve": r.get::<String, _>("cve_id"),
                "description": r.get::<String, _>("description"),
            })
        })
        .collect())
}

pub async fn update_config(pool: &DbPool, key: &str, value: &str) -> Result<()> {
    sqlx::query("INSERT INTO system_config (key, value) VALUES ($1, $2) ON CONFLICT(key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP")
        .bind(key)
        .bind(value)
        .execute(pool)
        .await?;

    Ok(())
}
