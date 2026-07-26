package api

import (
	"log"
	"net/http"
	"strconv"

	"github.com/trakshya/trakshya-api/internal/db"
)

func (s *Server) getTopAttackers(w http.ResponseWriter, r *http.Request) {
	limit := 10
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > 1000 {
				n = 1000
			}
			limit = n
		}
	}
	data, err := s.db.GetTopAttackers(limit)
	if err != nil {
		log.Printf("Failed to get top attackers: %v", err)
		s.errorJSON(w, http.StatusInternalServerError, "failed to get top attackers")
		return
	}
	if data == nil {
		data = []db.AttackCount{}
	}
	s.json(w, http.StatusOK, data)
}

func (s *Server) getTimeline(w http.ResponseWriter, r *http.Request) {
	data, err := s.db.GetTimeline()
	if err != nil {
		log.Printf("Failed to get timeline: %v", err)
		s.errorJSON(w, http.StatusInternalServerError, "failed to get timeline")
		return
	}
	if data == nil {
		data = []db.TimeBucket{}
	}
	s.json(w, http.StatusOK, data)
}

func (s *Server) getCountryStats(w http.ResponseWriter, r *http.Request) {
	data, err := s.db.GetCountryStats()
	if err != nil {
		log.Printf("Failed to get country stats: %v", err)
		s.errorJSON(w, http.StatusInternalServerError, "failed to get country stats")
		return
	}
	if data == nil {
		data = []db.AttackCount{}
	}
	s.json(w, http.StatusOK, data)
}

func (s *Server) getRuleTriggers(w http.ResponseWriter, r *http.Request) {
	data, err := s.db.GetRuleTriggers()
	if err != nil {
		log.Printf("Failed to get rule triggers: %v", err)
		s.errorJSON(w, http.StatusInternalServerError, "failed to get rule triggers")
		return
	}
	if data == nil {
		data = []db.AttackCount{}
	}
	s.json(w, http.StatusOK, data)
}
