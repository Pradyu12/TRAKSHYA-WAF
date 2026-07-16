package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/trakshya/trakshya-api/pkg/models"
)

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	incidents, err := s.db.ListIncidents()
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "failed to list incidents")
		return
	}
	if incidents == nil {
		incidents = []models.Incident{}
	}
	s.json(w, http.StatusOK, incidents)
}

func (s *Server) createIncident(w http.ResponseWriter, r *http.Request) {
	var inc models.Incident
	if err := json.NewDecoder(r.Body).Decode(&inc); err != nil {
		s.errorJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}

	inc.ID = uuid.New().String()
	if inc.Timestamp.IsZero() {
		inc.Timestamp = time.Now()
	}

	if err := s.db.CreateIncident(&inc); err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "failed to create incident")
		return
	}

	s.metrics.IncidentsTotal.Inc()
	s.json(w, http.StatusCreated, inc)
}

func (s *Server) acknowledgeIncident(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.db.AcknowledgeIncident(id); err != nil {
		s.errorJSON(w, http.StatusNotFound, "incident not found")
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "acknowledged"})
}
