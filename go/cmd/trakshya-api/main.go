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

	database, err := db.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	if err := database.RunMigrations(); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	if err := database.RunVulnMigrations(); err != nil {
		log.Fatalf("Failed to run vuln migrations: %v", err)
	}

	if err := database.RunVaptMigrations(); err != nil {
		log.Fatalf("Failed to run vapt migrations: %v", err)
	}

	// ── DuckDB: embedded analytical layer for SIEM events ──────────────────
	duckdbPath := os.Getenv("TRAKSHYA_DUCKDB_PATH")
	if duckdbPath == "" {
		duckdbPath = "trakshya_events.duckdb"
	}

	duckDB, err := db.NewDuckDB(duckdbPath, func(incident *models.Incident) {
		// Callback: correlation engine fired — write confirmed incident to PostgreSQL
		if err := database.CreateIncident(incident); err != nil {
			log.Printf("SIEM: failed to persist correlated incident: %v", err)
		}
		log.Printf("SIEM ALERT [%s] %s: %s", incident.Severity, incident.AttackType, incident.Message)
	})
	if err != nil {
		log.Fatalf("Failed to initialize DuckDB: %v", err)
	}
	defer duckDB.Close()

	// ── Background SIEM correlation loop ───────────────────────────────────
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			incidents := duckDB.RunCorrelationRules()
			for _, inc := range incidents {
				log.Printf("CORRELATION [%s] %s", inc.Severity, inc.Message)
			}
		}
	}()

	metrics := telemetry.NewMetrics()

	router := api.NewRouter(cfg, database, duckDB, metrics)

	addr := ":" + os.Getenv("TRAKSHYA_MGMT_PORT")
	if addr == ":" {
		addr = ":8000"
	}

	log.Printf("TRAKSHYA management API listening on %s (DuckDB analytics: %s)", addr, duckdbPath)
	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func loadConfig() *api.Config {
	databaseURL := os.Getenv("TRAKSHYA_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://trakshya:trakshya@localhost:5432/trakshya?sslmode=disable"
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
		DatabaseURL:    databaseURL,
		Posture:        "monitor",
		LogLevel:       "info",
		FrontendDir:    frontendDir,
		APIKey:         apiKey,
	}
}
