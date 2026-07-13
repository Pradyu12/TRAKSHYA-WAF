use axum::{body::Body, extract::Request, response::Response};
use axum::http::StatusCode;
use bytes::Bytes;
use std::sync::Arc;
use crate::config::{AppState, Posture};

pub struct RequestInspector {
    state: Arc<AppState>,
}

impl RequestInspector {
    pub fn new(state: &Arc<AppState>) -> Self {
        Self { state: state.clone() }
    }

    pub async fn inspect(&self, uri_path: &str, query: &str, method: &str, body: &[u8], client_ip: &str) -> Result<(), Response> {
        let cfg = self.state.config.read().await;

        if cfg.trusted_ips.iter().any(|ip| ip == client_ip) {
            return Ok(());
        }

        if cfg.posture == Posture::UnderAttack && method != "GET" && method != "HEAD" {
            return Err(self.block_response("Under attack posture active"));
        }

        let body_str = String::from_utf8_lossy(body);

        let combined = format!(
            "{} {} {} {} {}",
            uri_path, query, body_str, method, client_ip
        );

        let rules_engine = kalki_rules::Engine::new();
        if let Some(rule) = rules_engine.check_attack(&combined) {
            tracing::warn!(
                "Blocked request: {} {} from {} - {}",
                method, uri_path, client_ip, rule.rule_id
            );

            let incident = serde_json::json!({
                "type": "attack_blocked",
                "rule_id": rule.rule_id,
                "attack_type": rule.attack_type,
                "client_ip": client_ip,
                "path": uri_path,
                "method": method,
                "severity": rule.severity,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            });

            tokio::spawn(report_incident(self.state.clone(), incident));

            return Err(self.block_response(&format!("Blocked: {}", rule.attack_type)));
        }

        if cfg.posture != Posture::Monitor && cfg.rate_limit.enabled {
            let limiter = kalki_rate_limiter::RateLimiter::new(
                cfg.rate_limit.requests_per_minute,
                cfg.rate_limit.burst_size,
            );
            if !limiter.allow(client_ip) {
                tracing::warn!("Rate limit exceeded for {}", client_ip);
                return Err(self.rate_limit_response());
            }
        }

        Ok(())
    }

    pub fn extract_client_ip(headers: &axum::http::HeaderMap) -> String {
        headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn block_response(&self, reason: &str) -> Response {
        let html = format!(
            r#"<!DOCTYPE html><html><head><title>Blocked</title>
<style>body{{font-family:sans-serif;background:#1a1a2e;color:#eee;display:flex;
justify-content:center;align-items:center;height:100vh;margin:0;text-align:center}}
h1{{color:#e94560}} .shield{{font-size:64px}}</style></head>
<body><div><div class="shield">&#x1f6e1;</div>
<h1>Request Blocked</h1><p>{}</p>
<p>Your request has been blocked by KALKI-WAF security policy.</p>
<small>Reference: {} | KALKI-WAF v1.0</small></div></body></html>"#,
            reason,
            chrono::Utc::now().timestamp()
        );
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("content-type", "text/html; charset=utf-8")
            .header("x-kalki-blocked", "true")
            .body(Body::from(html))
            .unwrap()
    }

    fn rate_limit_response(&self) -> Response {
        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("content-type", "application/json")
            .header("retry-after", "60")
            .body(Body::from(
                r#"{"error":"rate_limit_exceeded","message":"Too many requests"}"#
            ))
            .unwrap()
    }
}

async fn report_incident(state: Arc<AppState>, incident: serde_json::Value) {
    let url = format!("{}/api/incidents", state.config.read().await.management_api_url);
    match state.http_client.post(&url).json(&incident).send().await {
        Ok(_) => tracing::debug!("Incident reported to management API"),
        Err(e) => tracing::error!("Failed to report incident: {}", e),
    }
}
