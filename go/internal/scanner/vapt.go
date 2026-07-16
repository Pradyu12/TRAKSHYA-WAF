package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/trakshya/trakshya-api/pkg/models"
)

type VaptScanner struct{}

func NewVaptScanner() *VaptScanner { return &VaptScanner{} }

func (v *VaptScanner) Scan(target string) (*models.VaptScan, error) {
	scanID := uuid.New().String()
	scan := &models.VaptScan{
		ID:     scanID,
		Status: "running",
		Target: target,
	}

	var findings []models.VaptFinding

	findings = append(findings, v.auditHeaders(target)...)
	findings = append(findings, v.checkSensitivePaths(target)...)
	findings = append(findings, v.checkMethods(target)...)
	findings = append(findings, v.scanCommonPorts(target)...)
	findings = append(findings, v.checkTLS(target)...)

	now := time.Now()
	scan.CompletedAt = &now
	scan.TotalProbes = len(findings)
	scan.Findings = findings
	scan.Status = "completed"

	return scan, nil
}

func (v *VaptScanner) auditHeaders(target string) []models.VaptFinding {
	var findings []models.VaptFinding
	client := &http.Client{Timeout: 8 * time.Second}

	req, _ := http.NewRequest(http.MethodGet, target, nil)
	resp, err := client.Do(req)
	if err != nil {
		return append(findings, models.VaptFinding{
			ID:          uuid.New().String(),
			Category:    "headers",
			Severity:    "critical",
			Title:       "Target unreachable",
			Description: fmt.Sprintf("Failed to connect to %s: %v", target, err),
			Evidence:    err.Error(),
			Remediation: "Verify the target URL, network path, and firewall rules.",
		})
	}
	defer resp.Body.Close()

	h := resp.Header

	check := func(name, expected string, sev, title, desc, rem string) {
		val := h.Get(name)
		if val == "" {
			findings = append(findings, models.VaptFinding{
				ID:          uuid.New().String(),
				Category:    "headers",
				Severity:    sev,
				Title:       fmt.Sprintf("Missing header: %s", name),
				Description: desc,
				Evidence:    fmt.Sprintf("%s not present in response", name),
				Remediation: rem,
			})
		}
	}

	check("X-Frame-Options", "DENY", "medium", "Missing X-Frame-Options",
		"Clickjacking protection is missing.",
		"Add X-Frame-Options: DENY or SAMEORIGIN.")
	check("X-Content-Type-Options", "nosniff", "medium", "Missing X-Content-Type-Options",
		"Browsers may MIME-sniff responses.",
		"Add X-Content-Type-Options: nosniff.")
	check("Content-Security-Policy", "", "medium", "Missing CSP",
		"No Content-Security-Policy header found.",
		"Add a restrictive Content-Security-Policy header.")
	check("Strict-Transport-Security", "", "high", "Missing HSTS",
		"HTTPS site does not enforce HSTS.",
		"Add Strict-Transport-Security: max-age=31536000; includeSubDomains.")
	check("Referrer-Policy", "", "low", "Missing Referrer-Policy",
		"Referrer policy is not set.",
		"Add Referrer-Policy: strict-origin-when-cross-origin.")

	if strings.Contains(target, "https://") {
		check("Permissions-Policy", "", "low", "Missing Permissions-Policy",
			"Feature policy/policy permissions are not restricted.",
			"Add Permissions-Policy to disable unnecessary browser features.")
	}

	return findings
}

func (v *VaptScanner) checkSensitivePaths(target string) []models.VaptFinding {
	var findings []models.VaptFinding
	paths := []string{
		"/.env", "/.git/config", "/.DS_Store", "/backup.sql", "/id_rsa",
		"/dump.sql", "/admin/config", "/actuator", "/swagger-ui.html",
	}
	client := &http.Client{Timeout: 6 * time.Second}

	for _, p := range paths {
		full := strings.TrimRight(target, "/") + p
		resp, err := client.Get(full)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			findings = append(findings, models.VaptFinding{
				ID:          uuid.New().String(),
				Category:    "sensitive_files",
				Severity:    "critical",
				Title:       fmt.Sprintf("Sensitive path exposed: %s", p),
				Description: "A sensitive file or directory is publicly accessible.",
				Evidence:    fmt.Sprintf("GET %s returned %d %s", full, resp.StatusCode, resp.Status),
				Remediation: "Restrict access, remove sensitive files from web root, or block via WAF rules.",
			})
		}
	}
	return findings
}

func (v *VaptScanner) checkMethods(target string) []models.VaptFinding {
	var findings []models.VaptFinding
	methods := []string{http.MethodOptions, http.MethodPut, http.MethodDelete, http.MethodTrace}
	client := &http.Client{Timeout: 6 * time.Second}

	for _, m := range methods {
		req, _ := http.NewRequest(m, target, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotImplemented {
			findings = append(findings, models.VaptFinding{
				ID:          uuid.New().String(),
				Category:    "http_methods",
				Severity:    "medium",
				Title:       fmt.Sprintf("Potentially dangerous HTTP method allowed: %s", m),
				Description: "The server accepted an unusual HTTP method.",
				Evidence:    fmt.Sprintf("%s %s -> %d %s", m, target, resp.StatusCode, resp.Status),
				Remediation: "Disable unused HTTP methods at the server/WAF level.",
			})
		}
	}
	return findings
}

func (v *VaptScanner) scanCommonPorts(target string) []models.VaptFinding {
	var findings []models.VaptFinding
	u, err := url.Parse(target)
	if err != nil {
		return findings
	}
	host := u.Hostname()
	if host == "" {
		host = target
	}
	ports := []int{21, 22, 23, 25, 53, 80, 443, 445, 3306, 5432, 6379, 27017, 3389}

	for _, port := range ports {
		address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			conn.Close()
			findings = append(findings, models.VaptFinding{
				ID:          uuid.New().String(),
				Category:    "open_ports",
				Severity:    "low",
				Title:       fmt.Sprintf("Open port detected: %d", port),
				Description: "A common service port is reachable from the scanner host.",
				Evidence:    fmt.Sprintf("TCP connection to %s succeeded", address),
				Remediation: "Restrict exposure via firewall or bind services to localhost.",
			})
		}
	}
	return findings
}

func (v *VaptScanner) checkTLS(target string) []models.VaptFinding {
	var findings []models.VaptFinding
	if !strings.Contains(target, "https://") {
		return findings
	}
	u, err := url.Parse(target)
	if err != nil {
		return findings
	}
	address := u.Hostname()
	if address == "" {
		address = target
	}
	_, port, _ := net.SplitHostPort(u.Host)
	if port == "" {
		address = net.JoinHostPort(address, "443")
	} else {
		address = net.JoinHostPort(address, port)
	}

	conn, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: false})
	if err != nil {
		findings = append(findings, models.VaptFinding{
			ID:          uuid.New().String(),
			Category:    "tls",
			Severity:    "high",
			Title:       "TLS handshake failed",
			Description: "The HTTPS endpoint failed TLS negotiation.",
			Evidence:    err.Error(),
			Remediation: "Verify certificate validity, TLS version support, and trust store configuration.",
		})
		return findings
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if state.Version < tls.VersionTLS12 {
		findings = append(findings, models.VaptFinding{
			ID:          uuid.New().String(),
			Category:    "tls",
			Severity:    "high",
			Title:       "Outdated TLS version",
			Description: "Server negotiated a deprecated TLS version.",
			Evidence:    fmt.Sprintf("TLS version: %x", state.Version),
			Remediation: "Disable TLS 1.0/1.1 and prefer TLS 1.2 or 1.3.",
		})
	}

	cipher := state.CipherSuite
	_ = cipher

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		if cert.NotAfter.Before(time.Now()) {
			findings = append(findings, models.VaptFinding{
				ID:          uuid.New().String(),
				Category:    "tls",
				Severity:    "critical",
				Title:       "Expired TLS certificate",
				Description: "The server presented an expired certificate.",
				Evidence:    fmt.Sprintf("Certificate expired at %s", cert.NotAfter.Format(time.RFC3339)),
				Remediation: "Renew the TLS certificate and reload the server.",
			})
		}
	}

	return findings
}
