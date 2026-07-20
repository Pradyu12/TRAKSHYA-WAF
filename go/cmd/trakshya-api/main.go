package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/trakshya/trakshya-api/internal/api"
	"github.com/trakshya/trakshya-api/internal/db"
	"github.com/trakshya/trakshya-api/internal/telemetry"
	"github.com/trakshya/trakshya-api/pkg/models"
)

func main() {
	cfg := loadConfig()

	dbPath := os.Getenv("TRAKSHYA_DUCKDB_PATH")
	if dbPath == "" {
		dbPath = "trakshya_events.duckdb"
	}

	store, err := db.NewStore(dbPath, func(incident *models.Incident) {
		log.Printf("SIEM ALERT [%s] %s: %s", incident.Severity, incident.AttackType, incident.Message)
	})
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer store.Close()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			incidents := store.RunCorrelationRules()
			for _, inc := range incidents {
				log.Printf("CORRELATION [%s] %s", inc.Severity, inc.Message)
			}
		}
	}()

	metrics := telemetry.NewMetrics()

	router := api.NewRouter(cfg, store, metrics)

	addr := ":" + os.Getenv("TRAKSHYA_MGMT_PORT")
	if addr == ":" {
		addr = ":8000"
	}

	log.Printf("TRAKSHYA management API listening on %s (DuckDB: %s)", addr, dbPath)
	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func loadConfig() *api.Config {
	dbPath := os.Getenv("TRAKSHYA_DUCKDB_PATH")
	if dbPath == "" {
		dbPath = "trakshya_events.duckdb"
	}
	frontendDir := os.Getenv("TRAKSHYA_FRONTEND_DIR")
	if frontendDir == "" {
		frontendDir = "/opt/trakshya/frontend"
	}
	apiKey := os.Getenv("TRAKSHYA_API_KEY")
	return &api.Config{
		ProxyPort:      8080,
		UpstreamURL:    "http://localhost:3000",
		ManagementPort: 8000,
		DatabasePath:   dbPath,
		Posture:        "monitor",
		LogLevel:       "info",
		FrontendDir:    frontendDir,
		APIKey:         apiKey,
	}
}
