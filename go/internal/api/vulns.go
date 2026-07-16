package api

import (
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
	scanMu    sync.Mutex
	activeScan string
)

func (s *Server) getVulnStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.GetVulnStats()
	if err != nil {
		log.Printf("Failed to get vuln stats: %v", err)
		s.errorJSON(w, http.StatusInternalServerError, "failed to get vulnerability stats")
		return
	}
	s.json(w, http.StatusOK, stats)
}

func (s *Server) listVulnFindings(w http.ResponseWriter, r *http.Request) {
	findings, err := s.db.ListAllVulnFindings()
	if err != nil {
		log.Printf("Failed to list vuln findings: %v", err)
		s.errorJSON(w, http.StatusInternalServerError, "failed to list findings")
		return
	}
	s.json(w, http.StatusOK, findings)
}

func (s *Server) startVulnScan(w http.ResponseWriter, r *http.Request) {
	scanMu.Lock()
	if activeScan != "" {
		scanMu.Unlock()
		s.json(w, http.StatusConflict, map[string]string{
			"error":   "scan already in progress",
			"scan_id": activeScan,
		})
		return
	}
	scanMu.Unlock()

	scanID := uuid.New().String()
	scanMu.Lock()
	activeScan = scanID
	scanMu.Unlock()

	scan := &models.VulnScan{
		ID:        scanID,
		Status:    "running",
		Target:    "localhost",
		StartedAt: time.Now(),
	}

	if err := s.db.CreateVulnScan(scan); err != nil {
		log.Printf("Failed to create scan record: %v", err)
		scanMu.Lock()
		activeScan = ""
		scanMu.Unlock()
		s.errorJSON(w, http.StatusInternalServerError, "failed to create scan")
		return
	}

	go s.runScanAsync(scanID)

	s.json(w, http.StatusAccepted, map[string]string{
		"scan_id": scanID,
		"status":  "running",
	})
}

func (s *Server) runScanAsync(scanID string) {
	defer func() {
		scanMu.Lock()
		if activeScan == scanID {
			activeScan = ""
		}
		scanMu.Unlock()
	}()

	sc := scanner.New()
	result, err := sc.Scan()
	if err != nil {
		log.Printf("Scan failed: %v", err)
		s.db.UpdateVulnScan(&models.VulnScan{
			ID:     scanID,
			Status: "failed",
		})
		return
	}

	result.ID = scanID
	result.Status = "completed"
	if err := s.db.UpdateVulnScan(result); err != nil {
		log.Printf("Failed to update scan result: %v", err)
		return
	}

	for i := range result.Findings {
		result.Findings[i].ScanID = scanID
		if err := s.db.CreateVulnFinding(&result.Findings[i]); err != nil {
			log.Printf("Failed to store finding: %v", err)
		}
	}

	log.Printf("Scan %s completed: %d findings across %d packages", scanID, len(result.Findings), result.TotalPkgs)
}

func (s *Server) getVulnScan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	scan, err := s.db.GetVulnScan(id)
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
