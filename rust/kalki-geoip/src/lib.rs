use maxminddb::geoip2;
use maxminddb::Reader;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpResult {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub is_proxy: bool,
}

pub struct GeoIp {
    reader: Option<Reader<Vec<u8>>>,
}

impl GeoIp {
    pub fn new(db_path: Option<&Path>) -> Self {
        let reader = db_path
            .and_then(|p| Reader::open_readfile(p).ok());

        if reader.is_none() {
            tracing::warn!("GeoIP database not loaded - geo-blocking disabled");
        }

        Self { reader }
    }

    pub fn lookup(&self, ip: &str) -> Option<GeoIpResult> {
        let ip_addr: IpAddr = ip.parse().ok()?;
        let reader = self.reader.as_ref()?;

        let result: geoip2::City = reader.lookup(ip_addr).ok()?;

        let country_code = result
            .country
            .as_ref()
            .and_then(|c| c.iso_code)
            .map(|s| s.to_string());
        let country_name = result
            .country
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en").map(|s| s.to_string()));
        let city = result
            .city
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en").map(|s| s.to_string()));
        let latitude = result
            .location
            .as_ref()
            .and_then(|l| l.latitude);
        let longitude = result
            .location
            .as_ref()
            .and_then(|l| l.longitude);
        let is_proxy = result
            .traits
            .and_then(|t| t.is_anonymous_proxy)
            .unwrap_or(false);

        Some(GeoIpResult {
            country_code,
            country_name,
            city,
            latitude,
            longitude,
            is_proxy,
        })
    }

    pub fn is_blocked(&self, ip: &str, blocked_countries: &[String]) -> bool {
        if blocked_countries.is_empty() {
            return false;
        }
        match self.lookup(ip) {
            Some(result) => result
                .country_code
                .map(|code| blocked_countries.iter().any(|c| c.eq_ignore_ascii_case(&code)))
                .unwrap_or(false),
            None => false,
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.reader.is_some()
    }
}
