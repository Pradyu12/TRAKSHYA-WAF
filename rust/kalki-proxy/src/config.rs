use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub proxy_port: u16,
    pub upstream_url: String,
    pub management_api_url: String,
    pub posture: Posture,
    pub rate_limit: RateLimitConfig,
    pub circuit_breaker: CircuitBreakerConfig,
    pub geoip_db_path: Option<String>,
    pub jwt_secret: Option<String>,
    pub blocked_countries: Vec<String>,
    pub trusted_ips: Vec<String>,
    pub api_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub enum Posture {
    #[default]
    Monitor,
    Standard,
    UnderAttack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_minute: u32,
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: 60,
            burst_size: 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    pub enabled: bool,
    pub failure_threshold: u32,
    pub recovery_timeout_secs: u64,
    pub half_open_max_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: 5,
            recovery_timeout_secs: 30,
            half_open_max_requests: 3,
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let config_path = std::env::var("KALKI_CONFIG")
            .unwrap_or_else(|_| "/etc/kalki/config.yaml".to_string());

        if let Ok(content) = std::fs::read_to_string(&config_path) {
            let cfg: Config = serde_yaml::from_str(&content)?;
            return Ok(cfg);
        }

        Ok(Config {
            proxy_port: std::env::var("KALKI_PROXY_PORT")
                .unwrap_or_else(|_| "8080".into()).parse()?,
            upstream_url: std::env::var("KALKI_UPSTREAM_URL")
                .unwrap_or_else(|_| "http://localhost:3000".into()),
            management_api_url: std::env::var("KALKI_MGMT_API_URL")
                .unwrap_or_else(|_| "http://localhost:8000".into()),
            posture: Posture::Monitor,
            rate_limit: RateLimitConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            geoip_db_path: None,
            jwt_secret: None,
            blocked_countries: vec![],
            trusted_ips: vec![],
            api_key: std::env::var("KALKI_API_KEY")
                .unwrap_or_default(),
        })
    }
}

pub struct AppState {
    pub config: RwLock<Config>,
    pub http_client: reqwest::Client,
}

impl AppState {
    pub async fn new(cfg: &Config) -> anyhow::Result<Self> {
        Ok(Self {
            config: RwLock::new(cfg.clone()),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        })
    }
}
