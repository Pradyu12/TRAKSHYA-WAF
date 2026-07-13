package models

import "time"

type Posture string

const (
	PostureMonitor    Posture = "monitor"
	PostureStandard   Posture = "standard"
	PostureUnderAttack Posture = "under_attack"
)

type Incident struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	RuleID      string    `json:"rule_id"`
	AttackType  string    `json:"attack_type"`
	ClientIP    string    `json:"client_ip"`
	Path        string    `json:"path"`
	Method      string    `json:"method"`
	Severity    string    `json:"severity"`
	Message     string    `json:"message"`
	Source      string    `json:"source"`
	Timestamp   time.Time `json:"timestamp"`
	Acknowledged bool     `json:"acknowledged"`
}

type Agent struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	IP        string    `json:"ip"`
	Version   string    `json:"version"`
	Status    string    `json:"status"`
	LastSeen  time.Time `json:"last_seen"`
	Tags      []string  `json:"tags"`
}

type Rule struct {
	RuleID      string `json:"rule_id"`
	Identifier  string `json:"identifier"`
	Pattern     string `json:"pattern"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Action      string `json:"action"`
	IsActive    bool   `json:"is_active"`
	BlocksCount int    `json:"blocks_count"`
	CreatedAt   string `json:"created_at"`
}

type BlacklistEntry struct {
	ID        int    `json:"id"`
	IPAddress string `json:"ip_address"`
	Reason    string `json:"reason"`
	CreatedAt string `json:"created_at"`
}

type SIEMStats struct {
	Total          int            `json:"total"`
	BySeverity     map[string]int `json:"by_severity"`
	ByType         map[string]int `json:"by_type"`
	Unacknowledged int            `json:"unacknowledged"`
}

type SIEMAlert struct {
	ID          int    `json:"id"`
	RuleName    string `json:"rule_name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	SourceIP    string `json:"source_ip"`
	Path        string `json:"path"`
	Timestamp   string `json:"timestamp"`
	Acked       bool   `json:"acked"`
}

type Config struct {
	ProxyPort        int      `yaml:"proxy_port" json:"proxy_port"`
	UpstreamURL      string   `yaml:"upstream_url" json:"upstream_url"`
	ManagementPort   int      `yaml:"management_port" json:"management_port"`
	Posture          Posture  `yaml:"posture" json:"posture"`
	BlockedCountries []string `yaml:"blocked_countries" json:"blocked_countries"`
	TrustedIPs       []string `yaml:"trusted_ips" json:"trusted_ips"`
	DBPath           string   `yaml:"db_path" json:"db_path"`
	LogLevel         string   `yaml:"log_level" json:"log_level"`
}

type DashboardStats struct {
	TotalRequests      int64            `json:"total_requests"`
	BlockedRequests    int64            `json:"blocked_requests"`
	ActiveIPs          int              `json:"active_ips"`
	IncidentsToday     int              `json:"incidents_today"`
	Posture            Posture          `json:"posture"`
	UptimeSeconds      int64            `json:"uptime_seconds"`
	TopAttacks         []AttackCount    `json:"top_attacks"`
	RecentIncidents    []Incident       `json:"recent_incidents"`
	AgentsOnline       int              `json:"agents_online"`
	RuleCount          int              `json:"rule_count"`
}

type AttackCount struct {
	AttackType string `json:"attack_type"`
	Count      int    `json:"count"`
}

type GeoPoint struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

type GeoLocation struct {
	IP          string   `json:"ip"`
	CountryCode string   `json:"country_code"`
	CountryName string   `json:"country_name"`
	City        string   `json:"city"`
	Latitude    float64  `json:"latitude"`
	Longitude   float64  `json:"longitude"`
	Count       int      `json:"count"`
	LastSeen    string   `json:"last_seen"`
}

type GeoStats struct {
	TotalIPs       int           `json:"total_ips"`
	TotalCountries int           `json:"total_countries"`
	Locations      []GeoLocation `json:"locations"`
}

type VulnScan struct {
	ID          string        `json:"id"`
	Status      string        `json:"status"`
	Target      string        `json:"target"`
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt *time.Time    `json:"completed_at,omitempty"`
	TotalPkgs   int           `json:"total_packages"`
	TotalCVEs   int           `json:"total_cves"`
	Findings    []VulnFinding `json:"findings,omitempty"`
}

type VulnFinding struct {
	ID              string `json:"id"`
	ScanID          string `json:"scan_id"`
	Package         string `json:"package"`
	Installed       string `json:"installed_version"`
	Available       string `json:"available_version"`
	Severity        string `json:"severity"`
	CVE             string `json:"cve"`
	Description     string `json:"description"`
	Category        string `json:"category"`
}

type VulnStats struct {
	TotalCVEs      int            `json:"total_cves"`
	TotalPackages  int            `json:"total_packages"`
	AvgCVSS        float64        `json:"avg_cvss"`
	BySeverity     map[string]int `json:"by_severity"`
	LastScanTime   *time.Time     `json:"last_scan_time,omitempty"`
	LastScanStatus string         `json:"last_scan_status"`
}
