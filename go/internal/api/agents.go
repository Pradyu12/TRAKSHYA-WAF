package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/kalki-waf/kalki-api/pkg/models"
)

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.db.ListAgents()
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "failed to list agents")
		return
	}
	if agents == nil {
		agents = []models.Agent{}
	}
	s.json(w, http.StatusOK, agents)
}

func (s *Server) registerAgent(w http.ResponseWriter, r *http.Request) {
	var agent models.Agent
	if err := json.NewDecoder(r.Body).Decode(&agent); err != nil {
		s.errorJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}

	agent.ID = uuid.New().String()
	agent.Status = "active"
	agent.LastSeen = time.Now()

	if err := s.db.CreateAgent(&agent); err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "failed to register agent")
		return
	}

	s.json(w, http.StatusCreated, agent)
}
