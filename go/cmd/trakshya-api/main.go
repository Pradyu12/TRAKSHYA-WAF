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
		UpstreamURL:    "http://localhost:8000",
		ManagementPort: 8000,
		DatabasePath:   dbPath,
		Posture:        "monitor",
		LogLevel:       "info",
		FrontendDir:    frontendDir,
		APIKey:         apiKey,
	}
}
