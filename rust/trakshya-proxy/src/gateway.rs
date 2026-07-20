use reqwest::Client;
use tracing;

pub struct Gateway {
    client: Client,
    base_url: String,
    api_key: String,
}

impl Gateway {
    pub fn new(base_url: &str, api_key: &str) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
        }
    }

    pub async fn record_incident(
        &self,
        incident_type: &str,
        rule_id: &str,
        attack_type: &str,
        client_ip: &str,
        path: &str,
        method: &str,
        severity: &str,
        message: &str,
        source: &str,
    ) {
        let url = format!("{}/api/incidents", self.base_url);
        let body = serde_json::json!({
            "type": incident_type,
            "rule_id": rule_id,
            "attack_type": attack_type,
            "client_ip": client_ip,
            "path": path,
            "method": method,
            "severity": severity,
            "message": message,
            "source": source,
        });

        let resp = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .header("x-api-key", &self.api_key)
            .json(&body)
            .send()
            .await;

        if let Err(e) = resp {
            tracing::error!("Failed to record incident via Go API: {}", e);
        }
    }

    pub async fn record_request(&self, client_ip: &str, blocked: bool) {
        let url = format!("{}/api/analytics/request-stats", self.base_url);
        let body = serde_json::json!({
            "client_ip": client_ip,
            "blocked": blocked,
        });

        let resp = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .header("x-api-key", &self.api_key)
            .json(&body)
            .send()
            .await;

        if let Err(e) = resp {
            tracing::error!("Failed to record request via Go API: {}", e);
        }
    }

    pub async fn create_rule(
        &self,
        pattern: &str,
        severity: &str,
        category: &str,
        description: &str,
    ) -> Result<serde_json::Value, String> {
        let url = format!("{}/api/rules", self.base_url);
        let body = serde_json::json!({
            "identifier": "custom",
            "pattern": pattern,
            "severity": severity,
            "category": category,
            "description": description,
        });

        let resp = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .header("x-api-key", &self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let status = resp.status();
        let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        if status.is_success() {
            Ok(json)
        } else {
            Err(format!("Go API returned {}: {}", status, json))
        }
    }

    pub async fn delete_rule(&self, id: &str) -> Result<(), String> {
        let url = format!("{}/api/rules/{}", self.base_url, id);
        let resp = self
            .client
            .delete(&url)
            .header("x-api-key", &self.api_key)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("Go API returned {}", resp.status()))
        }
    }

    pub async fn add_to_blacklist(&self, ip: &str, reason: Option<&str>) -> Result<(), String> {
        let url = format!("{}/api/blacklist", self.base_url);
        let mut body = serde_json::json!({ "ip_address": ip });
        if let Some(r) = reason {
            body["reason"] = serde_json::json!(r);
        }

        let resp = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .header("x-api-key", &self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("Go API returned {}", resp.status()))
        }
    }

    pub async fn remove_from_blacklist(&self, ip: &str) -> Result<(), String> {
        let url = format!("{}/api/blacklist/{}", self.base_url, ip);
        let resp = self
            .client
            .delete(&url)
            .header("x-api-key", &self.api_key)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("Go API returned {}", resp.status()))
        }
    }
}
