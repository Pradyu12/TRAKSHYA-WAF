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
	ProxyPort        int      `yaml:"proxy_port"`
	UpstreamURL      string   `yaml:"upstream_url"`
	ManagementPort   int      `yaml:"management_port"`
	DatabasePath     string   `yaml:"database_path"`
	Posture          string   `yaml:"posture"`
	LogLevel         string   `yaml:"log_level"`
	FrontendDir      string   `yaml:"frontend_dir"`
	APIKey           string   `yaml:"api_key"`
}

type Server struct {
	cfg     *Config
	db      *db.Store
	metrics *telemetry.Metrics
	startAt time.Time
}

func NewRouter(cfg *Config, store *db.Store, metrics *telemetry.Metrics) http.Handler {
	srv := &Server{
		cfg:     cfg,
		db:      store,
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

		r.Get("/rules", srv.listRules)
		r.Post("/rules", srv.createRule)
		r.Put("/rules/{id}/toggle", srv.toggleRule)
		r.Delete("/rules/{id}", srv.deleteRule)

		r.Get("/blacklist", srv.listBlacklist)
		r.Post("/blacklist", srv.addBlacklist)
		r.Delete("/blacklist/{ip}", srv.removeBlacklist)

		r.Get("/siem/stats", srv.getSIEMStats)
		r.Get("/siem/alerts", srv.listSIEMAlerts)
		r.Post("/siem/alerts/{id}/ack", srv.ackSIEMAlert)

		r.Get("/analytics/events", srv.getEventStats)
		r.Post("/analytics/ingest", srv.ingestEvent)
		r.Post("/analytics/request-stats", srv.recordRequestStats)

		r.Get("/geo", srv.getGeoData)

		r.Get("/vulns/stats", srv.getVulnStats)
		r.Get("/vulns", srv.listVulnFindings)
		r.Post("/vulns/scan", srv.startVulnScan)
		r.Get("/vulns/scan/{id}", srv.getVulnScan)

		r.Get("/vapt/stats", srv.getVaptStats)
		r.Get("/vapt", srv.listVaptFindings)
		r.Get("/vapt/scans", srv.listVaptScans)
		r.Post("/vapt/scan", srv.startVaptScan)
		r.Get("/vapt/scan/{id}", srv.getVaptScan)
		r.Get("/vapt/scan/{id}/findings", srv.getVaptScanFindings)

		r.Get("/mitigation-posture", srv.getPosture)
		r.Post("/mitigation-posture", srv.setMitigationPosture)

		r.Handle("/metrics", srv.metrics.Handler())
	})

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

func isPrivateHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified()
	}
	return false
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

		if isPrivateHost(host) {
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

func (s *Server) getEventStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.GetEventStats()
	if err != nil {
		log.Printf("Failed to get event stats: %v", err)
		s.errorJSON(w, http.StatusInternalServerError, "failed to get event stats")
		return
	}
	s.json(w, http.StatusOK, stats)
}

func (s *Server) ingestEvent(w http.ResponseWriter, r *http.Request) {
	var evt db.RawEvent
	if err := json.NewDecoder(r.Body).Decode(&evt); err != nil {
		s.errorJSON(w, http.StatusBadRequest, "invalid event payload")
		return
	}
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now()
	}
	s.db.Ingest(evt)
	s.json(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

func (s *Server) recordRequestStats(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ClientIP string `json:"client_ip"`
		Blocked  bool   `json:"blocked"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.errorJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.ClientIP == "" {
		s.errorJSON(w, http.StatusBadRequest, "client_ip is required")
		return
	}
	s.db.RecordRequest(body.ClientIP, body.Blocked)
	s.json(w, http.StatusAccepted, map[string]string{"status": "ok"})
}
