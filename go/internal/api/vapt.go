package api

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/trakshya/trakshya-api/internal/scanner"
	"github.com/trakshya/trakshya-api/pkg/models"
)

var (
	vaptMu       sync.Mutex
	activeVaptScan string
)

func (s *Server) getVaptStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.GetVaptStats()
	if err != nil {
		log.Printf("Failed to get vapt stats: %v", err)
		s.errorJSON(w, http.StatusInternalServerError, "failed to get vapt stats")
		return
	}
	s.json(w, http.StatusOK, stats)
}

func (s *Server) listVaptFindings(w http.ResponseWriter, r *http.Request) {
	findings, err := s.db.ListAllVaptFindings()
	if err != nil {
		log.Printf("Failed to list vapt findings: %v", err)
		s.errorJSON(w, http.StatusInternalServerError, "failed to list findings")
		return
	}
	s.json(w, http.StatusOK, findings)
}

func (s *Server) listVaptScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.db.ListVaptScans(50)
	if err != nil {
		log.Printf("Failed to list vapt scans: %v", err)
		s.errorJSON(w, http.StatusInternalServerError, "failed to list scans")
		return
	}
	s.json(w, http.StatusOK, scans)
}

func (s *Server) startVaptScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.errorJSON(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Target == "" {
		s.errorJSON(w, http.StatusBadRequest, "target is required")
		return
	}

	if err := scanner.ValidateScanTarget(req.Target); err != nil {
		s.errorJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	vaptMu.Lock()
	if activeVaptScan != "" {
		vaptMu.Unlock()
		s.json(w, http.StatusConflict, map[string]string{
			"error":   "vapt scan already in progress",
			"scan_id": activeVaptScan,
		})
		return
	}

	scanID := uuid.New().String()
	activeVaptScan = scanID
	vaptMu.Unlock()

	scan := &models.VaptScan{
		ID:        scanID,
		Status:    "running",
		Target:    req.Target,
		StartedAt: time.Now().UTC(),
	}
	if err := s.db.CreateVaptScan(scan); err != nil {
		log.Printf("Failed to create vapt scan: %v", err)
		vaptMu.Lock()
		activeVaptScan = ""
		vaptMu.Unlock()
		s.errorJSON(w, http.StatusInternalServerError, "failed to create scan")
		return
	}

	go s.runVaptScanAsync(scanID, req.Target)

	s.json(w, http.StatusAccepted, map[string]string{
		"scan_id": scanID,
		"status":  "running",
		"target":  req.Target,
	})
}

func (s *Server) runVaptScanAsync(scanID, target string) {
	defer func() {
		vaptMu.Lock()
		if activeVaptScan == scanID {
			activeVaptScan = ""
		}
		vaptMu.Unlock()
	}()

	sc := scanner.NewVaptScanner()
	result, err := sc.Scan(target)
	if err != nil {
		log.Printf("VAPT scan failed: %v", err)
		s.db.UpdateVaptScan(&models.VaptScan{
			ID:     scanID,
			Status: "failed",
		})
		return
	}

	result.ID = scanID
	result.Status = "completed"
	if err := s.db.UpdateVaptScan(result); err != nil {
		log.Printf("Failed to update vapt scan: %v", err)
		return
	}

	for i := range result.Findings {
		result.Findings[i].ID = uuid.New().String()
		result.Findings[i].ScanID = scanID
		if err := s.db.CreateVaptFinding(&result.Findings[i]); err != nil {
			log.Printf("Failed to store vapt finding: %v", err)
		}
	}

	log.Printf("VAPT scan %s completed on %s: %d findings", scanID, target, len(result.Findings))
}

func (s *Server) getVaptScan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	scan, err := s.db.GetVaptScan(id)
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "failed to get scan")
		return
	}
	if scan == nil {
		s.errorJSON(w, http.StatusNotFound, "scan not found")
		return
	}
	s.json(w, http.StatusOK, scan)
}

func (s *Server) getVaptScanFindings(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	findings, err := s.db.ListVaptFindings(id)
	if err != nil {
		s.errorJSON(w, http.StatusInternalServerError, "failed to get findings")
		return
	}
	s.json(w, http.StatusOK, findings)
}
