use crate::config::AppState;
use crate::db::{
    DashboardStats, GeoData, Incident, Rule, SIEMAStats,
    VulnStats,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, Sse},
        IntoResponse, Response,
    },
    routing::{delete, get, post, put},
    Json, Router,
};
use chrono::Utc;
use futures_util::StreamExt;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;
use uuid::Uuid;

const API_KEY_HEADER: &str = "x-api-key";

pub fn mgmt_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/config", get(get_config).put(update_config))
        .route("/posture", get(get_posture).put(set_posture))
        .route("/stats", get(get_stats))
        .route("/reload-rules", post(reload_rules))
        .route("/dashboard/stats", get(get_dashboard_stats))
        .route("/geo", get(get_geo))
        .route("/siem/stats", get(get_siem_stats))
        .route("/siem/alerts", get(get_siem_alerts))
        .route("/rules", get(get_rules).post(create_rule))
        .route("/rules/:id", delete(delete_rule))
        .route("/rules/test", post(test_rule))
        .route("/blacklist", get(get_blacklist).post(add_blacklist))
        .route("/blacklist/:ip", delete(remove_blacklist))
        .route("/vulns/stats", get(get_vuln_stats))
        .route("/vulns", get(get_vulns))
        .route("/vulns/scan", post(run_vuln_scan))
        .route("/stream", get(sse_handler))
        .route("/simulate-attack", post(simulate_attack))
        .with_state(state)
}

#[derive(Serialize)]
struct ApiConfig {
    proxy_port: u16,
    upstream_url: String,
    management_api_url: String,
    posture: String,
    rate_limit_enabled: bool,
    circuit_breaker_enabled: bool,
    blocked_countries: Vec<String>,
    trusted_ips: Vec<String>,
    geoip_enabled: bool,
    jwt_enabled: bool,
}

#[derive(Deserialize)]
struct PostureUpdate {
    posture: String,
}

#[derive(Serialize)]
struct Stats {
    uptime_secs: u64,
    posture: String,
}

#[derive(Deserialize)]
struct ConfigUpdate {
    upstream_url: Option<String>,
    posture: Option<String>,
    rate_limit_enabled: Option<bool>,
    circuit_breaker_enabled: Option<bool>,
    blocked_countries: Option<Vec<String>>,
    trusted_ips: Option<Vec<String>>,
    geoip_enabled: Option<bool>,
    jwt_enabled: Option<bool>,
}

async fn get_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<ApiConfig>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    let cfg = state.config.read().await;
    Ok(Json(ApiConfig {
        proxy_port: cfg.proxy.port,
        upstream_url: cfg.proxy.upstream_url.clone(),
        management_api_url: cfg.proxy.management_api_url.clone(),
        posture: format!("{:?}", cfg.proxy.posture),
        rate_limit_enabled: cfg.rate_limiter.enabled,
        circuit_breaker_enabled: cfg.circuit_breaker.enabled,
        blocked_countries: cfg.geoip.blocked_countries.clone(),
        trusted_ips: cfg.trusted_ips.clone(),
        geoip_enabled: cfg.geoip.enabled,
        jwt_enabled: cfg.jwt.enabled,
    }))
}

async fn update_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(update): Json<ConfigUpdate>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    let mut cfg = state.config.write().await;
    if let Some(url) = update.upstream_url {
        cfg.proxy.upstream_url = url;
    }
    if let Some(p) = update.posture {
        cfg.proxy.posture = match p.to_lowercase().as_str() {
            "monitor" => crate::config::Posture::Monitor,
            "standard" => crate::config::Posture::Standard,
            "under_attack" | "underattack" => crate::config::Posture::UnderAttack,
            _ => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid posture"})),
                ))
            }
        };
    }
    if let Some(enabled) = update.rate_limit_enabled {
        cfg.rate_limiter.enabled = enabled;
    }
    if let Some(enabled) = update.circuit_breaker_enabled {
        cfg.circuit_breaker.enabled = enabled;
    }
    if let Some(countries) = update.blocked_countries {
        cfg.geoip.blocked_countries = countries;
    }
    if let Some(ips) = update.trusted_ips {
        cfg.trusted_ips = ips;
    }
    if let Some(enabled) = update.geoip_enabled {
        cfg.geoip.enabled = enabled;
    }
    if let Some(enabled) = update.jwt_enabled {
        cfg.jwt.enabled = enabled;
    }

    Ok(Json(
        serde_json::json!({"status": "ok", "message": "Configuration updated"}),
    ))
}

async fn get_posture(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    let cfg = state.config.read().await;
    Ok(Json(serde_json::json!({
        "posture": format!("{:?}", cfg.proxy.posture)
    })))
}

async fn set_posture(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(update): Json<PostureUpdate>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    let posture = match update.posture.to_lowercase().as_str() {
        "monitor" => crate::config::Posture::Monitor,
        "standard" => crate::config::Posture::Standard,
        "under_attack" | "underattack" => crate::config::Posture::UnderAttack,
        _ => {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": "Invalid posture. Use: monitor, standard, or under_attack"
            })));
        }
    };

    let mut cfg = state.config.write().await;
    cfg.proxy.posture = posture;

    Ok(Json(
        serde_json::json!({"status": "ok", "posture": format!("{:?}", posture)}),
    ))
}

async fn get_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Stats>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    let cfg = state.config.read().await;
    Ok(Json(Stats {
        uptime_secs: state.uptime_seconds(),
        posture: format!("{:?}", cfg.proxy.posture),
    }))
}

async fn reload_rules(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    Ok(Json(
        serde_json::json!({"status": "ok", "message": "Rules reloaded"}),
    ))
}

async fn get_dashboard_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<DashboardStats>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    let cfg = state.config.read().await;
    let state_clone = state.clone();
    let posture = format!("{:?}", cfg.proxy.posture);

    let stats = tokio::task::spawn_blocking(move || {
        let conn = state_clone.db_conn.lock().unwrap();
        let rule_count = crate::db::get_rule_count(&conn);
        crate::db::get_dashboard_stats(&conn, &posture, rule_count, state_clone.uptime_seconds() as i64)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;

    Ok(Json(stats))
}

async fn get_geo(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<GeoData>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    let state_clone = state.clone();
    let data = tokio::task::spawn_blocking(move || {
        let conn = state_clone.db_conn.lock().unwrap();
        crate::db::get_geo_data(&conn)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    Ok(Json(data))
}

async fn get_siem_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<SIEMAStats>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    let state_clone = state.clone();
    let stats = tokio::task::spawn_blocking(move || {
        let conn = state_clone.db_conn.lock().unwrap();
        crate::db::get_siem_stats(&conn)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    Ok(Json(stats))
}

async fn get_siem_alerts(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    let limit = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let offset = params
        .get("offset")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let state_clone = state.clone();
    let alerts = tokio::task::spawn_blocking(move || {
        let conn = state_clone.db_conn.lock().unwrap();
        crate::db::get_siem_alerts(&conn, limit, offset)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    Ok(Json(
        alerts
            .into_iter()
            .map(|a| {
                serde_json::json!({
                    "id": a.id,
                    "type": a.incident_type,
                    "rule_id": a.rule_id,
                    "attack_type": a.attack_type,
                    "client_ip": a.client_ip,
                    "path": a.path,
                    "method": a.method,
                    "severity": a.severity,
                    "message": a.message,
                    "source": a.source,
                    "timestamp": a.timestamp.to_rfc3339(),
                    "acknowledged": a.acknowledged
                })
            })
            .collect(),
    ))
}

async fn get_rules(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<Rule>>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    let state_clone = state.clone();
    let rules = tokio::task::spawn_blocking(move || {
        let conn = state_clone.db_conn.lock().unwrap();
        crate::db::get_rules(&conn, None)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    Ok(Json(rules))
}

#[derive(Deserialize)]
struct CreateRuleRequest {
    id: String,
    pattern: String,
    severity: String,
    category: String,
    description: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

async fn create_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateRuleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;

    if regex::Regex::new(&req.pattern).is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid regex pattern"})),
        ));
    }

    let result = state
        .gateway
        .create_rule(&req.pattern, &req.severity, &req.category, &req.description)
        .await;

    match result {
        Ok(json) => Ok(Json(json)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e})),
        )),
    }
}

async fn delete_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;

    match state.gateway.delete_rule(&id).await {
        Ok(()) => Ok(Json(
            serde_json::json!({"status": "ok", "message": "Rule deleted"}),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e})),
        )),
    }
}

#[derive(Deserialize)]
struct TestRuleRequest {
    pattern: String,
    payload: String,
}

async fn test_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<TestRuleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;

    let re = match regex::Regex::new(&req.pattern) {
        Ok(r) => r,
        Err(e) => {
            return Ok(Json(
                serde_json::json!({"error": format!("Invalid regex: {}", e)}),
            ))
        }
    };

    let matches = re
        .find_iter(&req.payload)
        .map(|m| m.as_str().to_string())
        .collect::<Vec<_>>();

    Ok(Json(serde_json::json!({
        "matches": matches,
        "blocked": !matches.is_empty()
    })))
}

async fn get_blacklist(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    let state_clone = state.clone();
    let list = tokio::task::spawn_blocking(move || {
        let conn = state_clone.db_conn.lock().unwrap();
        crate::db::get_blacklist(&conn)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    Ok(Json(
        list.into_iter()
            .map(|b| {
                serde_json::json!({
                    "id": b.id,
                    "ip": b.ip,
                    "reason": b.reason,
                    "created_at": b.created_at.to_rfc3339(),
                    "expires_at": b.expires_at.map(|d| d.to_rfc3339())
                })
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct AddBlacklistRequest {
    ip: String,
    #[serde(default)]
    reason: Option<String>,
}

async fn add_blacklist(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<AddBlacklistRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;

    match state
        .gateway
        .add_to_blacklist(&req.ip, req.reason.as_deref())
        .await
    {
        Ok(()) => Ok(Json(
            serde_json::json!({"status": "ok", "message": "IP added to blacklist"}),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e})),
        )),
    }
}

async fn remove_blacklist(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(ip): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;

    match state.gateway.remove_from_blacklist(&ip).await {
        Ok(()) => Ok(Json(
            serde_json::json!({"status": "ok", "message": "IP removed from blacklist"}),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e})),
        )),
    }
}

async fn get_vuln_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<VulnStats>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    let state_clone = state.clone();
    let stats = tokio::task::spawn_blocking(move || {
        let conn = state_clone.db_conn.lock().unwrap();
        crate::db::get_vuln_stats(&conn)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    Ok(Json(stats))
}

async fn get_vulns(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    let state_clone = state.clone();
    let vulns = tokio::task::spawn_blocking(move || {
        let conn = state_clone.db_conn.lock().unwrap();
        crate::db::get_vulnerabilities(&conn)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    Ok(Json(vulns))
}

async fn run_vuln_scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    Ok(Json(
        serde_json::json!({"status": "started", "scan_id": "scan-123"}),
    ))
}

async fn sse_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;

    let rx = state.broadcast_tx.subscribe();
    let stream = BroadcastStream::new(rx)
        .map(|msg| msg.map(|data| Event::default().json_data(data).unwrap()));

    Ok(Sse::new(stream)
        .keep_alive(
            axum::response::sse::KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keep-alive"),
        )
        .into_response())
}

#[derive(Deserialize)]
struct SimulateAttackRequest {
    attack_type: String,
    payload: String,
}

async fn simulate_attack(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SimulateAttackRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;

    let incident = Incident {
        id: Uuid::new_v4().to_string(),
        incident_type: "attack_blocked".to_string(),
        rule_id: "SIMULATED".to_string(),
        attack_type: req.attack_type,
        client_ip: "127.0.0.1".to_string(),
        path: "/api/test".to_string(),
        method: "GET".to_string(),
        severity: "high".to_string(),
        message: format!("Simulated {} attack", req.payload),
        source: "simulator".to_string(),
        timestamp: Utc::now(),
        acknowledged: false,
        acked_at: None,
        acked_by: None,
    };

    state.gateway.record_incident(
        &incident.incident_type,
        &incident.rule_id,
        &incident.attack_type,
        &incident.client_ip,
        &incident.path,
        &incident.method,
        &incident.severity,
        &incident.message,
        &incident.source,
    ).await;

    let _ = state.broadcast_tx.send(serde_json::json!({
        "type": "incident",
        "data": incident
    }));

    Ok(Json(
        serde_json::json!({"status": "ok", "message": "Attack simulated"}),
    ))
}

async fn check_auth(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let cfg = state.config.read().await;
    if cfg.api_key.is_empty() {
        return Ok(());
    }
    if let Some(key) = headers.get(API_KEY_HEADER) {
        if let Ok(key_str) = key.to_str() {
            if key_str == cfg.api_key {
                return Ok(());
            }
        }
    }
    Err((
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": "unauthorized: provide valid x-api-key header"})),
    ))
}
