package api

import (
	"encoding/json"
	"net/http"
)

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusOK, map[string]interface{}{
		"proxy_port":      s.cfg.ProxyPort,
		"upstream_url":    s.cfg.UpstreamURL,
		"management_port": s.cfg.ManagementPort,
		"posture":         s.cfg.Posture,
	})
}

func (s *Server) updateConfig(w http.ResponseWriter, r *http.Request) {
	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		s.errorJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if v, ok := updates["upstream_url"].(string); ok {
		s.cfg.UpstreamURL = v
	}
	if v, ok := updates["posture"].(string); ok {
		s.cfg.Posture = v
	}

	s.json(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) getPosture(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusOK, map[string]string{
		"posture": s.cfg.Posture,
	})
}

func (s *Server) setPosture(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Posture string `json:"posture"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.errorJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}

	validPostures := map[string]bool{
		"monitor":      true,
		"standard":     true,
		"under_attack": true,
	}

	if !validPostures[body.Posture] {
		s.errorJSON(w, http.StatusBadRequest, "invalid posture. use: monitor, standard, or under_attack")
		return
	}

	s.cfg.Posture = body.Posture
	s.json(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"posture": body.Posture,
	})
}
