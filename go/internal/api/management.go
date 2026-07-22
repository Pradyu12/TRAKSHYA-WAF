package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/trakshya/trakshya-api/pkg/models"
)

// Rules handlers
func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.db.ListRules()
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "failed to list rules")
		return
	}
	if rules == nil {
		rules = []models.Rule{}
	}
	s.json(w, http.StatusOK, rules)
}

func (s *Server) createRule(w http.ResponseWriter, r *http.Request) {
	var rule models.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		s.errorJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if rule.Identifier == "" || rule.Pattern == "" {
		s.errorJSON(w, http.StatusBadRequest, "identifier and pattern are required")
		return
	}

	rule.RuleID = uuid.New().String()
	rule.IsActive = true
	rule.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	rule.Action = "Drop"

	if err := s.db.CreateRule(&rule); err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "failed to create rule")
		return
	}

	s.json(w, http.StatusCreated, rule)
}

func (s *Server) toggleRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		s.errorJSON(w, http.StatusBadRequest, "rule id required")
		return
	}

	var body struct {
		IsActive bool `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.errorJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := s.db.ToggleRule(id, body.IsActive); err != nil {
		s.errorJSON(w, http.StatusNotFound, "rule not found")
		return
	}

	s.json(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		s.errorJSON(w, http.StatusBadRequest, "rule id required")
		return
	}

	if err := s.db.DeleteRule(id); err != nil {
		s.errorJSON(w, http.StatusNotFound, "rule not found")
		return
	}

	s.json(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// Blacklist handlers
func (s *Server) listBlacklist(w http.ResponseWriter, r *http.Request) {
	entries, err := s.db.ListBlacklist()
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "failed to list blacklist")
		return
	}
	if entries == nil {
		entries = []models.BlacklistEntry{}
	}

	ips := make([]string, len(entries))
	for i, e := range entries {
		ips[i] = e.IPAddress
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"blacklisted_ips": ips,
		"entries":         entries,
	})
}

func (s *Server) addBlacklist(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IPAddress string `json:"ip_address"`
		Reason    string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.errorJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.IPAddress == "" {
		s.errorJSON(w, http.StatusBadRequest, "ip_address is required")
		return
	}

	if net.ParseIP(body.IPAddress) == nil {
		s.errorJSON(w, http.StatusBadRequest, "invalid IP address format")
		return
	}

	entry := &models.BlacklistEntry{
		ID:        uuid.New().String(),
		IPAddress: body.IPAddress,
		Reason:    body.Reason,
	}

	if err := s.db.CreateBlacklistEntry(entry); err != nil {
		s.errorJSON(w, http.StatusConflict, "IP already blacklisted or invalid")
		return
	}

	s.json(w, http.StatusCreated, entry)
}

func (s *Server) removeBlacklist(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if ip == "" {
		s.errorJSON(w, http.StatusBadRequest, "ip required")
		return
	}

	if err := s.db.DeleteBlacklistEntry(ip); err != nil {
		s.errorJSON(w, http.StatusNotFound, "IP not found in blacklist")
		return
	}

	s.json(w, http.StatusOK, map[string]string{"status": "removed"})
}

// SIEM handlers
func (s *Server) getSIEMStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.GetSIEMStats()
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "failed to get SIEM stats")
		return
	}
	s.json(w, http.StatusOK, stats)
}

func (s *Server) listSIEMAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := s.db.GetSIEMAlerts(30)
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "failed to list SIEM alerts")
		return
	}
	if alerts == nil {
		alerts = []models.SIEMAlert{}
	}
	s.json(w, http.StatusOK, alerts)
}

func (s *Server) ackSIEMAlert(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		s.errorJSON(w, http.StatusBadRequest, "alert id required")
		return
	}

	if err := s.db.AckSIEMAlert(id); err != nil {
		s.errorJSON(w, http.StatusNotFound, "alert not found")
		return
	}

	s.json(w, http.StatusOK, map[string]string{"status": "acknowledged"})
}

// Posture setter (frontend uses /api/mitigation-posture)
func (s *Server) setMitigationPosture(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Posture string `json:"posture"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.errorJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}

	postureMap := map[string]string{
		"Monitor Only":     "monitor",
		"Standard Posture": "standard",
		"Under Attack":     "under_attack",
	}

	internal, ok := postureMap[body.Posture]
	if !ok {
		s.errorJSON(w, http.StatusBadRequest, "invalid posture. use: Monitor Only, Standard Posture, or Under Attack")
		return
	}

	s.cfgMu.Lock()
	s.cfg.Posture = internal
	s.cfgMu.Unlock()
	s.json(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"posture": internal,
	})
}

func readLiveMetrics() (cpu float64, memMB float64) {
	cpu = 0
	memMB = 0

	data, err := os.ReadFile("/proc/self/stat")
	if err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 13 {
			utime, _ := strconv.ParseFloat(fields[13], 64)
			stime, _ := strconv.ParseFloat(fields[14], 64)
			cutime, _ := strconv.ParseFloat(fields[15], 64)
			cstime, _ := strconv.ParseFloat(fields[16], 64)
			total := utime + stime + cutime + cstime
			uptimeData, err := os.ReadFile("/proc/uptime")
			if err == nil {
				uptimeFields := strings.Fields(string(uptimeData))
				if len(uptimeFields) > 0 {
					uptime, _ := strconv.ParseFloat(uptimeFields[0], 64)
					if uptime > 0 {
						clkTck := 100.0
						cpu = (total / clkTck / uptime) * 100
					}
				}
			}
		}
	}

	memData, err := os.ReadFile("/proc/self/status")
	if err == nil {
		for _, line := range strings.Split(string(memData), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					val, _ := strconv.ParseFloat(fields[1], 64)
					memMB = val / 1024.0
				}
				break
			}
		}
	}

	return
}

// Telemetry streaming endpoint
func (s *Server) streamTelemetry(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	notify := r.Context().Done()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-notify:
			return
		case <-ticker.C:
			stats, err := s.db.GetDashboardStats()
			if err != nil {
				continue
			}
			cpu, memMB := readLiveMetrics()
			s.cfgMu.RLock()
			posture := s.cfg.Posture
			s.cfgMu.RUnlock()
			data, _ := json.Marshal(map[string]interface{}{
				"metrics": map[string]interface{}{
					"total_ingress": stats.TotalRequests,
					"total_blocked": stats.BlockedRequests,
					"cpu_percent":   cpu,
					"memory_mb":     memMB,
				},
				"posture":          posture,
				"recent_incidents": stats.RecentIncidents,
			})
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

type simulateAttackRequest struct {
	AttackType string `json:"attack_type"`
	Payload    string `json:"payload"`
}

func (s *Server) simulateAttack(w http.ResponseWriter, r *http.Request) {
	var req simulateAttackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.errorJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.AttackType == "" {
		s.errorJSON(w, http.StatusBadRequest, "attack_type is required")
		return
	}

	inc := models.Incident{
		ID:         uuid.New().String(),
		AttackType: req.AttackType,
		Type:       "simulated",
		Path:       "/simulated",
		ClientIP:   "127.0.0.1",
		Severity:   "medium",
		Message:    fmt.Sprintf("Simulated %s attack: %s", req.AttackType, req.Payload),
		Source:     "dashboard",
		Timestamp:  time.Now().UTC(),
	}

	if err := s.sqliteDB.CreateIncident(&inc); err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "failed to record simulated incident")
		return
	}

	s.db.CreateIncident(&inc)
	s.metrics.IncidentsTotal.Inc()
	BroadcastIncident(inc)

	s.json(w, http.StatusOK, map[string]interface{}{
		"status":   "simulated",
		"attack":   req.AttackType,
		"incident": inc,
	})
}
