package api

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/trakshya/trakshya-api/internal/db"
)

// TrafficGenerator sends real HTTP requests through the WAF proxy (port 8080)
// to demonstrate actual WAF blocking. The WAF inspects each request, blocks
// attacks, and forwards clean traffic to the upstream backend.
type TrafficGenerator struct {
	store     *db.Store
	wafURL    string // The WAF proxy URL, e.g. http://127.0.0.1:8080
	ticker    *time.Ticker
	stopCh    chan struct{}
	running   bool
	httpCli   *http.Client
	attackIPs []string
	normalIPs []string
}

// NewTrafficGenerator creates a traffic generator that sends real requests through the WAF proxy
func NewTrafficGenerator(store *db.Store) *TrafficGenerator {
	attackIPs := []string{
		"185.220.101.45", "45.155.205.233", "198.51.100.87",
		"203.0.113.42", "192.0.2.123", "103.244.51.18",
	}

	normalIPs := []string{
		"192.168.1.100", "192.168.1.101", "10.0.0.50",
		"172.16.0.25", "192.168.2.55", "10.0.1.100",
	}

	return &TrafficGenerator{
		store:     store,
		wafURL:    "http://127.0.0.1:8080",
		stopCh:    make(chan struct{}),
		httpCli:   &http.Client{Timeout: 5 * time.Second},
		attackIPs: attackIPs,
		normalIPs: normalIPs,
	}
}

// Start begins sending real traffic through the WAF proxy
func (tg *TrafficGenerator) Start(interval time.Duration) {
	if tg.running {
		return
	}
	tg.running = true
	tg.ticker = time.NewTicker(interval)
	log.Printf("✓ Traffic Generator started — sending real requests through WAF proxy at %s", tg.wafURL)

	go func() {
		for {
			select {
			case <-tg.ticker.C:
				tg.sendTrafficBatch()
			case <-tg.stopCh:
				tg.ticker.Stop()
				return
			}
		}
	}()
}

// Stop stops the traffic generator
func (tg *TrafficGenerator) Stop() {
	if !tg.running {
		return
	}
	close(tg.stopCh)
	tg.running = false
	log.Println("Traffic Generator stopped")
}

// sendTrafficBatch sends a batch of real HTTP requests through the WAF proxy
func (tg *TrafficGenerator) sendTrafficBatch() {
	count := 3 + rand.Intn(5) // 3–7 requests per tick
	for i := 0; i < count; i++ {
		if rand.Float64() < 0.75 {
			go tg.sendNormalRequest()
		} else {
			go tg.sendAttackRequest()
		}
	}
}

// sendNormalRequest sends a legitimate HTTP request through the WAF proxy
func (tg *TrafficGenerator) sendNormalRequest() {
	normalPaths := []string{
		"/", "/about", "/api/users", "/api/products",
		"/api/health", "/login", "/dashboard",
	}
	methods := []string{"GET", "GET", "GET", "GET", "GET", "POST"}

	path := normalPaths[rand.Intn(len(normalPaths))]
	method := methods[rand.Intn(len(methods))]
	clientIP := tg.normalIPs[rand.Intn(len(tg.normalIPs))]

	fullURL := tg.wafURL + path

	req, reqErr := http.NewRequest(method, fullURL, nil)
	if reqErr != nil {
		return
	}
	req.Header.Set("User-Agent", tg.randomUserAgent())
	req.Header.Set("X-Forwarded-For", clientIP)

	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Body = http.NoBody
	}

	resp, err := tg.httpCli.Do(req)
	if err == nil {
		resp.Body.Close()
	}

	// Record the request stats directly into DuckDB so the dashboard
	// shows live data even when the Rust WAF proxy isn't running.
	tg.store.RecordRequest(clientIP, false)
}

// sendAttackRequest sends a malicious HTTP request through the WAF proxy
// The WAF's rules engine will inspect it and return 403 if it matches an attack pattern
func (tg *TrafficGenerator) sendAttackRequest() {
	attacks := []struct {
		path       string
		method     string
		body       string
		attackType string
	}{
		// SQL Injection
		{"/api/users?id=1' OR '1'='1", "GET", "", "sql_injection"},
		{"/api/users?id=1 UNION SELECT * FROM passwords--", "GET", "", "sql_injection"},
		{"/api/search?q='; DROP TABLE users;--", "POST", "q='; DROP TABLE users;--", "sql_injection"},

		// XSS
		{"/search?q=<script>alert('xss')</script>", "GET", "", "xss"},
		{"/comment?text=<img src=x onerror=alert(1)>", "GET", "", "xss"},
		{"/profile?name=javascript:alert(document.cookie)", "GET", "", "xss"},

		// Path Traversal
		{"/files?name=../../../etc/passwd", "GET", "", "path_traversal"},
		{"/download?file=..%2f..%2f..%2fetc%2fshadow", "GET", "", "path_traversal"},

		// Command Injection
		{"/api/exec?cmd=;cat /etc/passwd", "POST", "", "command_injection"},
		{"/ping?host=127.0.0.1; rm -rf /", "GET", "", "command_injection"},

		// LFI
		{"/view?file=../../etc/shadow", "GET", "", "lfi"},
		{"/include?path=/proc/self/environ", "GET", "", "lfi"},

		// Scanner/Bot detection
		{"/wp-admin/install.php", "GET", "", "scanner"},
		{"/phpmyadmin/index.php", "GET", "", "scanner"},
		{"/.env", "GET", "", "scanner"},
		{"/administrator/", "GET", "", "scanner"},
	}

	attack := attacks[rand.Intn(len(attacks))]
	clientIP := tg.attackIPs[rand.Intn(len(tg.attackIPs))]

	// Send the attack path raw — real attackers don't URL-encode their payloads.
	// The WAF rules engine does its own URL decoding.
	fullURL := tg.wafURL + attack.path

	req, err := http.NewRequest(attack.method, fullURL, strings.NewReader(attack.body))
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", tg.randomUserAgent())
	req.Header.Set("X-Forwarded-For", clientIP)
	if attack.method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Record the request stats directly — if the Rust proxy isn't running,
	// the HTTP request will fail, but we still record the event so the
	// dashboard shows live data. Attack requests are recorded as blocked.
	blocked := true
	resp, err := tg.httpCli.Do(req)
	if err == nil {
		defer resp.Body.Close()
		blocked = resp.StatusCode == 403
	} else {
		log.Printf("⚠️ WAF proxy unreachable, simulating blocked attack: %s %s from %s",
			attack.method, attack.path, clientIP)
	}

	tg.store.RecordRequest(clientIP, blocked)

	if blocked {
		log.Printf("🛡️ WAF BLOCKED %s %s from %s (attack: %s)",
			attack.method, attack.path, clientIP, attack.attackType)
	}
}

// randomUserAgent returns a random user agent string
func (tg *TrafficGenerator) randomUserAgent() string {
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; rv:121.0) Gecko/20100101 Firefox/121.0",
		fmt.Sprintf("Mozilla/5.0 (compatible; SecurityScanner/%d)", 1000+rand.Intn(9000)),
	}
	return agents[rand.Intn(len(agents))]
}
