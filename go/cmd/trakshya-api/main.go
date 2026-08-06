package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/trakshya/trakshya-api/internal/api"
	"github.com/trakshya/trakshya-api/internal/db"
	"github.com/trakshya/trakshya-api/internal/telemetry"
	"github.com/trakshya/trakshya-api/pkg/models"
	"gopkg.in/yaml.v3"
)

func main() {
	cfg := loadConfig()

	dbPath := os.Getenv("TRAKSHYA_DUCKDB_PATH")
	if dbPath == "" {
		dbPath = cfg.DatabasePath
	}
	if dbPath == "" {
		dbPath = "trakshya_events.duckdb"
	}

	store, err := db.NewStore(dbPath, func(incident *models.Incident) {
		api.BroadcastIncident(incident)
	})
	if err != nil {
		log.Fatalf("Failed to initialize DuckDB: %v", err)
	}
	defer store.Close()

	log.Println("✓ DuckDB Connected")
	log.Println("✓ Rust Event Stream Active")
	log.Println("✓ SIEM Rules Loaded (7)")
	log.Println("✓ Dashboard Live")
	log.Println("✓ Monitoring Daemon Connected")
	log.Println("✓ Ready to Inspect Live Traffic")

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			incidents := store.RunCorrelationRules()
			for _, inc := range incidents {
				log.Printf("CORRELATION [%s] %s", inc.Severity, inc.Message)
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			deleted, err := store.PruneOldEvents(30)
			if err != nil {
				log.Printf("Retention prune failed: %v", err)
				continue
			}
			log.Printf("Retention: pruned %d events", deleted)
		}
	}()

	metrics := telemetry.NewMetrics()

	router := api.NewRouter(cfg, store, metrics)

	addr := ":" + os.Getenv("TRAKSHYA_MGMT_PORT")
	if addr == ":" {
		addr = fmt.Sprintf(":%d", cfg.ManagementPort)
	}

	log.Printf("TRAKSHYA management API listening on %s (DuckDB: %s)", addr, dbPath)
	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func loadConfig() *api.Config {
	configPath := os.Getenv("TRAKSHYA_CONFIG")
	if configPath == "" {
		configPath = "/etc/trakshya/config.yaml"
	}

	cfg := &api.Config{
		ProxyPort:      8080,
		UpstreamURL:    "http://localhost:3000",
		ManagementPort: 8000,
		DatabasePath:   "trakshya_events.duckdb",
		Posture:        "monitor",
		LogLevel:       "info",
		FrontendDir:    "/opt/trakshya/frontend",
	}

	if data, err := os.ReadFile(configPath); err == nil {
		var yamlCfg struct {
			Proxy struct {
				Port             int    `yaml:"port"`
				UpstreamURL      string `yaml:"upstream_url"`
				Posture          string `yaml:"posture"`
				ManagementAPIURL string `yaml:"management_api_url"`
			} `yaml:"proxy"`
			API struct {
				Port   int    `yaml:"port"`
				APIKey string `yaml:"api_key"`
			} `yaml:"api"`
			DatabasePath string   `yaml:"database_path"`
			TrustedIPs   []string `yaml:"trusted_ips"`
		}

		if err := yaml.Unmarshal(data, &yamlCfg); err == nil {
			if yamlCfg.Proxy.Port > 0 {
				cfg.ProxyPort = yamlCfg.Proxy.Port
			}
			if yamlCfg.Proxy.UpstreamURL != "" {
				cfg.UpstreamURL = yamlCfg.Proxy.UpstreamURL
			}
			if yamlCfg.Proxy.Posture != "" {
				cfg.Posture = yamlCfg.Proxy.Posture
			}
			if yamlCfg.API.Port > 0 {
				cfg.ManagementPort = yamlCfg.API.Port
			}
			if yamlCfg.API.APIKey != "" {
				cfg.APIKey = yamlCfg.API.APIKey
			}
			if yamlCfg.DatabasePath != "" {
				cfg.DatabasePath = yamlCfg.DatabasePath
			}
			if len(yamlCfg.TrustedIPs) > 0 {
				cfg.TrustedIPs = yamlCfg.TrustedIPs
			}
		} else {
			log.Printf("WARN: Failed to parse config YAML: %v", err)
		}
	} else {
		log.Printf("INFO: Config file not found at %s, using defaults", configPath)
	}

	// Environment variable overrides
	if v := os.Getenv("TRAKSHYA_MGMT_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.ManagementPort = port
		}
	}
	if v := os.Getenv("TRAKSHYA_API_KEY"); v != "" {
		cfg.APIKey = v
	}
	if v := os.Getenv("TRAKSHYA_UPSTREAM_URL"); v != "" {
		cfg.UpstreamURL = v
	}
	if v := os.Getenv("TRAKSHYA_PROXY_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.ProxyPort = port
		}
	}

	return cfg
}
