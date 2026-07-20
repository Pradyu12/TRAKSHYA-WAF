use crate::config::{AppState, Posture};
use crate::db::Incident;
use axum::http::StatusCode;
use axum::{body::Body, response::Response};
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

pub struct RequestInspector {
    state: Arc<AppState>,
}

impl RequestInspector {
    pub fn new(state: &Arc<AppState>) -> Self {
        Self {
            state: state.clone(),
        }
    }

    pub async fn inspect(
        &self,
        uri_path: &str,
        query: &str,
        method: &str,
        body: &[u8],
        client_ip: &str,
    ) -> Result<(), Response> {
        let cfg = self.state.config.read().await;

        if cfg.trusted_ips.iter().any(|ip| ip == client_ip) {
            return Ok(());
        }

        if cfg.proxy.posture == Posture::UnderAttack && method != "GET" && method != "HEAD" {
            return Err(self.block_response("Under attack posture active"));
        }

        let body_str = String::from_utf8_lossy(body);

        let combined = format!(
            "{} {} {} {} {}",
            uri_path, query, body_str, method, client_ip
        );

        let rules_engine = trakshya_rules::Engine::new();
        if let Some(rule) = rules_engine.check_attack(&combined) {
            tracing::warn!(
                "Blocked request: {} {} from {} - {}",
                method,
                uri_path,
                client_ip,
                rule.rule_id
            );

            let incident = Incident {
                id: Uuid::new_v4().to_string(),
                incident_type: "attack_blocked".to_string(),
                rule_id: rule.rule_id.clone(),
                attack_type: rule.attack_type.clone(),
                client_ip: client_ip.to_string(),
                path: uri_path.to_string(),
                method: method.to_string(),
                severity: rule.severity.clone(),
                message: format!("Blocked: {}", rule.attack_type),
                source: "trakshya-proxy".to_string(),
                timestamp: Utc::now(),
                acknowledged: false,
                acked_at: None,
                acked_by: None,
            };

            // Record to Go API (sole DuckDB writer)
            let state_clone = self.state.clone();
            let incident_clone = incident.clone();
            let client_ip_owned = client_ip.to_string();
            tokio::spawn(async move {
                state_clone.gateway.record_incident(
                    &incident_clone.incident_type,
                    &incident_clone.rule_id,
                    &incident_clone.attack_type,
                    &incident_clone.client_ip,
                    &incident_clone.path,
                    &incident_clone.method,
                    &incident_clone.severity,
                    &incident_clone.message,
                    &incident_clone.source,
                ).await;
                state_clone.gateway.record_request(&client_ip_owned, true).await;

                // Broadcast to SSE clients
                let _ = state_clone.broadcast_tx.send(serde_json::json!({
                    "type": "incident",
                    "data": incident_clone
                }));
            });

            return Err(self.block_response(&format!("Blocked: {}", rule.attack_type)));
        }

        // Record successful request via Go API
        let state_clone = self.state.clone();
        let client_ip_owned = client_ip.to_string();
        let client_ip_for_rate_limit = client_ip_owned.clone();
        tokio::spawn(async move {
            state_clone.gateway.record_request(&client_ip_owned, false).await;
        });

        if cfg.proxy.posture != Posture::Monitor && cfg.rate_limiter.enabled {
            let limiter = trakshya_rate_limiter::RateLimiter::new(
                cfg.rate_limiter.requests_per_minute,
                cfg.rate_limiter.burst_size,
            );
            if !limiter.allow(&client_ip_for_rate_limit) {
                tracing::warn!("Rate limit exceeded for {}", client_ip);

                let incident = Incident {
                    id: Uuid::new_v4().to_string(),
                    incident_type: "rate_limit".to_string(),
                    rule_id: "RATE_LIMIT".to_string(),
                    attack_type: "rate_limit".to_string(),
                    client_ip: client_ip.to_string(),
                    path: uri_path.to_string(),
                    method: method.to_string(),
                    severity: "medium".to_string(),
                    message: "Rate limit exceeded".to_string(),
                    source: "trakshya-proxy".to_string(),
                    timestamp: Utc::now(),
                    acknowledged: false,
                    acked_at: None,
                    acked_by: None,
                };

                let state_clone = self.state.clone();
                let incident_clone = incident.clone();
                tokio::spawn(async move {
                    state_clone.gateway.record_incident(
                        &incident_clone.incident_type,
                        &incident_clone.rule_id,
                        &incident_clone.attack_type,
                        &incident_clone.client_ip,
                        &incident_clone.path,
                        &incident_clone.method,
                        &incident_clone.severity,
                        &incident_clone.message,
                        &incident_clone.source,
                    ).await;
                    let _ = state_clone.broadcast_tx.send(serde_json::json!({
                        "type": "incident",
                        "data": incident_clone
                    }));
                });

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
<p>Your request has been blocked by TRAKSHYA-WAF security policy.</p>
<small>Reference: {} | TRAKSHYA-WAF v1.0</small></div></body></html>"#,
            reason,
            Utc::now().timestamp()
        );
        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("content-type", "text/html; charset=utf-8")
            .header("x-trakshya-blocked", "true")
            .body(Body::from(html))
            .unwrap()
    }

    fn rate_limit_response(&self) -> Response {
        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("content-type", "application/json")
            .header("retry-after", "60")
            .body(Body::from(
                r#"{"error":"rate_limit_exceeded","message":"Too many requests"}"#,
            ))
            .unwrap()
    }
}
