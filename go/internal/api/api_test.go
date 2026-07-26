package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/trakshya/trakshya-api/internal/db"
	"github.com/trakshya/trakshya-api/pkg/models"
)

func newTestServer(t *testing.T) (*Server, func()) {
	t.Helper()
	dir := t.TempDir()
	dbPath := dir + "/test.duckdb"
	store, err := db.NewStore(dbPath, func(*models.Incident) {})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	cfg := &Config{
		APIKey:         "test-key",
		ProxyPort:      8080,
		UpstreamURL:    "http://localhost:3000",
		ManagementPort: 8000,
		Posture:        "monitor",
		LogLevel:       "info",
	}
	srv := &Server{
		cfg:     cfg,
		db:      store,
		startAt: time.Now(),
	}
	return srv, func() {
		store.Close()
	}
}

func TestAuthMiddlewareAllowsLocalhost(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	r := chi.NewRouter()
	r.Use(srv.authMiddleware)
	r.Get("/api/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("localhost request got %d, want 200", w.Code)
	}
}

func TestAuthMiddlewareRequiresAPIKeyForRemote(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	r := chi.NewRouter()
	r.Use(srv.authMiddleware)
	r.Get("/api/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("remote request without key got %d, want 401", w.Code)
	}
}

func TestAuthMiddlewareAcceptsValidAPIKey(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	r := chi.NewRouter()
	r.Use(srv.authMiddleware)
	r.Get("/api/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("X-API-Key", "test-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("remote request with valid key got %d, want 200", w.Code)
	}
}

func TestScanDedupRejectsConcurrentScan(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/api/vulns/scan", nil)
	req.Header.Set("X-API-Key", "test-key")
	w1 := httptest.NewRecorder()
	srv.startVulnScan(w1, req)

	if w1.Code != http.StatusAccepted {
		t.Fatalf("first scan got %d, want 202", w1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/vulns/scan", nil)
	req2.Header.Set("X-API-Key", "test-key")
	w2 := httptest.NewRecorder()
	srv.startVulnScan(w2, req2)

	if w2.Code != http.StatusConflict {
		t.Fatalf("concurrent scan got %d, want 409", w2.Code)
	}
}

func TestStoreCloseIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/idempotent.duckdb"
	store, err := db.NewStore(dbPath, func(*models.Incident) {})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	store.Close()
	store.Close() // should not panic
}

func TestReadyCheckRequiresHealthyDuckDB(t *testing.T) {
	srv, cleanup := newTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	w := httptest.NewRecorder()
	srv.readyCheck(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("ready check got %d, want 200", w.Code)
	}
}
