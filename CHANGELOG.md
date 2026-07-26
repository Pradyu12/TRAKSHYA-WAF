# Changelog

All notable changes to this project will be documented in this file.
Dates are in ISO format.

## Unreleased

### Added
- Real-time analytics engine: event ingestion, top attackers, timeline, country stats, rule triggers, data retention
- 3 new Rust rule modules: SSRF (cloud metadata, localhost), CRLF injection (header, response splitting), JNDI/Log4Shell
- Input evasion detection: double URL decode, HTML entity decode, full-width Unicode normalization
- Kubernetes Helm chart with Recreate strategy for single-writer DuckDB
- K8s readiness/liveness probes (`/healthz`, `/ready`) for all deployments
- API integration tests: auth middleware, ready check, scan dedup, store idempotency
- Analytics store tests: event ingestion, correlations, prune, live updates
- Traffic generator utility: `scripts/traffic-generator.py`
- Nginx dashboard template with envsubst: `deploy/nginx/k8s-dashboard.conf.template`

### Changed
- **Replaced Node.js mock server with live Go/DuckDB management API** (core change)
- Replaced SQLite with DuckDB as sole database across Go API and Rust proxy
- Removed all Datadog, Firebase, and n8n integrations (zero SaaS dependencies)
- Dashboard Dockerfile: Node → nginx:alpine with envsubst template
- Go Dockerfile: build context from repo root (was `./go`)
- WebSocket hub: RWMutex → Mutex, safe concurrent client cleanup
- SIEM correlation engine: threshold-based rules, graceful goroutine shutdown
- C FIM engine: null-pointer guards, baseline init check, return written count
- C HIDS engine: fixed variable shadowing, goto-based error handling
- VAPT scanner: private IP validation, unreachable cipher variable fix
- Blacklist/SIEM alert IDs: `int` → `string` (UUID-based)
- Config field: `database_url` → `database_path` in Go models
- Env var normalization: `TRAKSHYA_DUCKDB_PATH` used consistently everywhere
- CI workflows: regression/validate now build and run live Go API (no mock server)

## 2.0.0

### Added
- Initial multi-language WAF stack with Rust proxy, Go management API, and C system daemon
- Landing page and dashboard UI
- GitHub Actions release workflow
