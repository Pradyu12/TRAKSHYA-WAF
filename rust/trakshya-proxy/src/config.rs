use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub rate_limiter: RateLimitConfig,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    #[serde(default)]
    pub geoip: GeoIPConfig,
    #[serde(default)]
    pub jwt: JWTConfig,
    #[serde(default)]
    pub trusted_ips: Vec<String>,
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_db_path")]
    pub database_path: String,
}

fn default_db_path() -> String {
    std::env::var("TRAKSHYA_DUCKDB_PATH").unwrap_or_else(|_| "trakshya_events.duckdb".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "default_proxy_port")]
    pub port: u16,
    #[serde(default = "default_upstream_url")]
    pub upstream_url: String,
    #[serde(default = "default_posture")]
    pub posture: Posture,
    #[serde(default = "default_mgmt_api_url")]
    pub management_api_url: String,
}

fn default_proxy_port() -> u16 {
    8080
}
fn default_upstream_url() -> String {
    "http://localhost:3000".to_string()
}
fn default_posture() -> Posture {
    Posture::Monitor
}
fn default_mgmt_api_url() -> String {
    "http://localhost:8000".to_string()
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: default_proxy_port(),
            upstream_url: default_upstream_url(),
            posture: default_posture(),
            management_api_url: default_mgmt_api_url(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Posture {
    #[default]
    Monitor,
    Standard,
    UnderAttack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_requests_per_minute")]
    pub requests_per_minute: u32,
    #[serde(default = "default_burst_size")]
    pub burst_size: u32,
}

fn default_true() -> bool {
    true
}
fn default_requests_per_minute() -> u32 {
    60
}
fn default_burst_size() -> u32 {
    10
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            requests_per_minute: default_requests_per_minute(),
            burst_size: default_burst_size(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_recovery_timeout")]
    pub recovery_timeout_secs: u64,
    #[serde(default = "default_half_open_max")]
    pub half_open_max_requests: u32,
}

fn default_failure_threshold() -> u32 {
    5
}
fn default_recovery_timeout() -> u64 {
    30
}
fn default_half_open_max() -> u32 {
    3
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            failure_threshold: default_failure_threshold(),
            recovery_timeout_secs: default_recovery_timeout(),
            half_open_max_requests: default_half_open_max(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoIPConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub db_path: Option<String>,
    #[serde(default)]
    pub blocked_countries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JWTConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default = "default_required_role")]
    pub required_role: String,
}

fn default_required_role() -> String {
    "admin".to_string()
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let config_path = std::env::var("TRAKSHYA_CONFIG")
            .unwrap_or_else(|_| "/etc/trakshya/config.yaml".to_string());

        if let Ok(content) = std::fs::read_to_string(&config_path) {
            let mut cfg: Config = serde_yaml::from_str(&content)?;
            if let Ok(url) = std::env::var("TRAKSHYA_MGMT_API_URL") {
                cfg.proxy.management_api_url = url;
            }
            if let Ok(url) = std::env::var("TRAKSHYA_UPSTREAM_URL") {
                cfg.proxy.upstream_url = url;
            }
            if let Ok(port) = std::env::var("TRAKSHYA_PROXY_PORT") {
                cfg.proxy.port = port.parse()?;
            }
            return Ok(cfg);
        }

        Ok(Config {
            proxy: ProxyConfig::default(),
            rate_limiter: RateLimitConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            geoip: GeoIPConfig::default(),
            jwt: JWTConfig::default(),
            trusted_ips: vec![],
            api_key: std::env::var("TRAKSHYA_API_KEY").unwrap_or_default(),
            database_path: default_db_path(),
        })
    }
}

pub struct AppState {
    pub config: RwLock<Config>,
    pub http_client: reqwest::Client,
    pub db_conn: std::sync::Mutex<duckdb::Connection>,
    pub gateway: crate::gateway::Gateway,
    pub start_time: Instant,
    pub broadcast_tx: tokio::sync::broadcast::Sender<serde_json::Value>,
}

impl AppState {
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        let db_config = duckdb::Config::default()
            .access_mode(duckdb::AccessMode::ReadOnly)?;
        let conn = duckdb::Connection::open_with_flags(&cfg.database_path, db_config)?;

        let (tx, _rx) = tokio::sync::broadcast::channel(100);

        let gateway = crate::gateway::Gateway::new(
            &cfg.proxy.management_api_url,
            &cfg.api_key,
        );

        Ok(Self {
            config: RwLock::new(cfg.clone()),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
            db_conn: std::sync::Mutex::new(conn),
            gateway,
            start_time: Instant::now(),
            broadcast_tx: tx,
        })
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}
