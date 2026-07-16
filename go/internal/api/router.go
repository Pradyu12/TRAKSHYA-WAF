package api

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/trakshya/trakshya-api/internal/db"
	"github.com/trakshya/trakshya-api/internal/telemetry"
)



type Config struct {
	ProxyPort      int    `yaml:"proxy_port"`
	UpstreamURL    string `yaml:"upstream_url"`
	ManagementPort int    `yaml:"management_port"`
	DBPath         string `yaml:"db_path"`
	Posture        string `yaml:"posture"`
	LogLevel       string `yaml:"log_level"`
	FrontendDir    string `yaml:"frontend_dir"`
	APIKey         string `yaml:"api_key"`
}

type Server struct {
	cfg     *Config
	db      *db.SQLite
	metrics *telemetry.Metrics
	startAt time.Time
}

func NewRouter(cfg *Config, database *db.SQLite, metrics *telemetry.Metrics) http.Handler {
	srv := &Server{
		cfg:     cfg,
		db:      database,
		metrics: metrics,
		startAt: time.Now(),
	}

	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:8080", "http://127.0.0.1:8080"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-API-Key"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	r.Get("/health", srv.healthCheck)

	r.Route("/api", func(r chi.Router) {
		r.Use(chimw.Timeout(30 * time.Second))
		r.Use(srv.authMiddleware)

		r.Get("/dashboard/stats", srv.getDashboardStats)

		r.Get("/incidents", srv.listIncidents)
		r.Post("/incidents", srv.createIncident)
		r.Put("/incidents/{id}/acknowledge", srv.acknowledgeIncident)

		r.Get("/config", srv.getConfig)
		r.Put("/config", srv.updateConfig)

		r.Get("/posture", srv.getPosture)
		r.Put("/posture", srv.setPosture)

		r.Get("/agents", srv.listAgents)
		r.Post("/agents/register", srv.registerAgent)

		// Rules
		r.Get("/rules", srv.listRules)
		r.Post("/rules", srv.createRule)
		r.Put("/rules/{id}/toggle", srv.toggleRule)
		r.Delete("/rules/{id}", srv.deleteRule)

		// Blacklist
		r.Get("/blacklist", srv.listBlacklist)
		r.Post("/blacklist", srv.addBlacklist)
		r.Delete("/blacklist/{ip}", srv.removeBlacklist)

		// SIEM (backed by incidents table)
		r.Get("/siem/stats", srv.getSIEMStats)
		r.Get("/siem/alerts", srv.listSIEMAlerts)
		r.Post("/siem/alerts/{id}/ack", srv.ackSIEMAlert)

		// Geo-location data for map visualization
		r.Get("/geo", srv.getGeoData)

		// Vulnerability scanning
		r.Get("/vulns/stats", srv.getVulnStats)
		r.Get("/vulns", srv.listVulnFindings)
		r.Post("/vulns/scan", srv.startVulnScan)
		r.Get("/vulns/scan/{id}", srv.getVulnScan)

		// VAPT scanning
		r.Get("/vapt/stats", srv.getVaptStats)
		r.Get("/vapt", srv.listVaptFindings)
		r.Get("/vapt/scans", srv.listVaptScans)
		r.Post("/vapt/scan", srv.startVaptScan)
		r.Get("/vapt/scan/{id}", srv.getVaptScan)
		r.Get("/vapt/scan/{id}/findings", srv.getVaptScanFindings)

		// Mitigation posture (frontend-compatible alias)
		r.Get("/mitigation-posture", srv.getPosture)
		r.Post("/mitigation-posture", srv.setMitigationPosture)

		r.Handle("/metrics", srv.metrics.Handler())
	})

	// Long-lived connections (no timeout)
	r.Get("/api/stream", srv.streamTelemetry)
	r.Get("/ws", srv.handleWebSocket)

	if srv.cfg.FrontendDir != "" {
		fileServer := http.FileServer(http.Dir(srv.cfg.FrontendDir))
		r.Get("/static/*", func(w http.ResponseWriter, r *http.Request) {
			http.StripPrefix("/static/", fileServer).ServeHTTP(w, r)
		})
		r.Get("/trakshya_waf_logo.png", fileServer.ServeHTTP)
		r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, srv.cfg.FrontendDir+"/dashboard.html")
		})
	}

	return r
}

func (s *Server) json(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) errorJSON(w http.ResponseWriter, status int, msg string) {
	s.json(w, status, map[string]string{"error": msg})
}

func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "trakshya-management-api",
		"uptime":  time.Since(s.startAt).String(),
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		host := r.RemoteAddr
		if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			host = h
		}

		if host == "127.0.0.1" || host == "::1" || host == "localhost" {
			next.ServeHTTP(w, r)
			return
		}

		if key := r.Header.Get("X-API-Key"); key != "" && s.cfg.APIKey != "" && key == s.cfg.APIKey {
			next.ServeHTTP(w, r)
			return
		}

		s.errorJSON(w, http.StatusUnauthorized, "unauthorized: provide valid X-API-Key header or connect from localhost")
	})
}

func (s *Server) getDashboardStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.GetDashboardStats()
	if err != nil {
		log.Printf("Failed to get dashboard stats: %v", err)
		s.errorJSON(w, http.StatusInternalServerError, "failed to get stats")
		return
	}

	stats.UptimeSeconds = int64(time.Since(s.startAt).Seconds())
	s.json(w, http.StatusOK, stats)
}
