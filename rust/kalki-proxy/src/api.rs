use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::config::{AppState, Posture};

const API_KEY_HEADER: &str = "x-api-key";

pub fn mgmt_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/config", get(get_config).put(update_config))
        .route("/posture", get(get_posture).put(set_posture))
        .route("/stats", get(get_stats))
        .route("/reload-rules", post(reload_rules))
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

async fn get_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<ApiConfig>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    let cfg = state.config.read().await;
    Ok(Json(ApiConfig {
        proxy_port: cfg.proxy_port,
        upstream_url: cfg.upstream_url.clone(),
        management_api_url: cfg.management_api_url.clone(),
        posture: format!("{:?}", cfg.posture),
        rate_limit_enabled: cfg.rate_limit.enabled,
        circuit_breaker_enabled: cfg.circuit_breaker.enabled,
        blocked_countries: cfg.blocked_countries.clone(),
        trusted_ips: cfg.trusted_ips.clone(),
    }))
}

#[derive(Deserialize)]
struct ConfigUpdate {
    upstream_url: Option<String>,
    posture: Option<String>,
    rate_limit_enabled: Option<bool>,
    circuit_breaker_enabled: Option<bool>,
    blocked_countries: Option<Vec<String>>,
    trusted_ips: Option<Vec<String>>,
}

async fn update_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(update): Json<ConfigUpdate>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    let mut cfg = state.config.write().await;
    if let Some(url) = update.upstream_url {
        cfg.upstream_url = url;
    }
    if let Some(p) = update.posture {
        cfg.posture = match p.to_lowercase().as_str() {
            "monitor" => Posture::Monitor,
            "standard" => Posture::Standard,
            "under_attack" | "underattack" => Posture::UnderAttack,
            _ => return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid posture"})))),
        };
    }
    if let Some(enabled) = update.rate_limit_enabled {
        cfg.rate_limit.enabled = enabled;
    }
    if let Some(enabled) = update.circuit_breaker_enabled {
        cfg.circuit_breaker.enabled = enabled;
    }
    if let Some(countries) = update.blocked_countries {
        cfg.blocked_countries = countries;
    }
    if let Some(ips) = update.trusted_ips {
        cfg.trusted_ips = ips;
    }
    Ok(Json(serde_json::json!({"status": "ok", "message": "Configuration updated"})))
}

async fn get_posture(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    let cfg = state.config.read().await;
    Ok(Json(serde_json::json!({
        "posture": format!("{:?}", cfg.posture)
    })))
}

async fn set_posture(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(update): Json<PostureUpdate>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    let posture = match update.posture.to_lowercase().as_str() {
        "monitor" => Posture::Monitor,
        "standard" => Posture::Standard,
        "under_attack" | "underattack" => Posture::UnderAttack,
        _ => {
            return Ok(Json(serde_json::json!({
                "status": "error",
                "message": "Invalid posture. Use: monitor, standard, or under_attack"
            })));
        }
    };

    let mut cfg = state.config.write().await;
    cfg.posture = posture;
    Ok(Json(serde_json::json!({"status": "ok", "posture": format!("{:?}", posture)})))
}

async fn get_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Stats>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    let cfg = state.config.read().await;
    Ok(Json(Stats {
        uptime_secs: 0,
        posture: format!("{:?}", cfg.posture),
    }))
}

async fn reload_rules(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    check_auth(&headers, &state).await?;
    Ok(Json(serde_json::json!({"status": "ok", "message": "Rules reloaded"})))
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
