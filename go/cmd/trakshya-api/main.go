package main

import (
	"log"
	"net/http"
	"os"

	"github.com/trakshya/trakshya-api/internal/api"
	"github.com/trakshya/trakshya-api/internal/db"
	"github.com/trakshya/trakshya-api/internal/telemetry"
)

func main() {
	cfg := loadConfig()

	database, err := db.NewSQLite(cfg.DBPath)
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

	metrics := telemetry.NewMetrics()

	router := api.NewRouter(cfg, database, metrics)

	addr := ":" + os.Getenv("TRAKSHYA_MGMT_PORT")
	if addr == ":" {
		addr = ":8000"
	}

	log.Printf("TRAKSHYA management API listening on %s", addr)
	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func loadConfig() *api.Config {
	dbPath := os.Getenv("TRAKSHYA_DB_PATH")
	if dbPath == "" {
		dbPath = "/var/lib/trakshya/trakshya.db"
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
		DBPath:         dbPath,
		Posture:        "monitor",
		LogLevel:       "info",
		FrontendDir:    frontendDir,
		APIKey:         apiKey,
	}
}