# TRAKSHYA WAF — Web Application Firewall

![Deploy Landing Page](https://github.com/Pradyu12/TRAKSHYA-WAF/actions/workflows/deploy-dashboard.yml/badge.svg)

**Landing Page:** [GitHub Pages](https://pradyu12.github.io/TRAKSHYA-WAF/)

A high-performance polyglot Web Application Firewall with integrated SIEM/XDR capabilities.
Built with **Rust** (core proxy), **Go** (management API), and **C** (system monitoring).
Runs entirely on your machine — no Docker, no cloud dependency.

## Quick Start

### Windows
```cmd
git clone https://github.com/Pradyu12/TRAKSHYA-WAF.git
cd TRAKSHYA-WAF
start-waf.bat
```

### macOS / Linux
```bash
git clone https://github.com/Pradyu12/TRAKSHYA-WAF.git
cd TRAKSHYA-WAF
chmod +x start-waf.sh
./start-waf.sh
```

This starts all services and opens the dashboard in your browser at **http://localhost:8000**.

## Architecture

```
Client Request → WAF Proxy (8080) → Rust Rules Engine inspects
                                        ↓
                                  Attack? → 403 BLOCKED
                                  Clean?  → Forward to Upstream (3000)
                                        ↓
                                  Reports incident to Go API (8000)
                                        ↓
                                  Dashboard shows live WAF data (browser)
```

| Service | Port | Description |
|---------|------|-------------|
| **Upstream Server** | 3000 | Your protected backend website |
| **Go API** | 8000 | Dashboard, management API, traffic generator |
| **WAF Proxy** | 8080 | Real WAF — inspects, blocks attacks, forwards clean traffic |

## What the WAF Blocks

| Attack Type | Rule | Severity |
|-------------|------|----------|
| SQL Injection | `SQLI-001` | Critical |
| Cross-Site Scripting | `XSS-001`, `XSS-002` | High |
| Path Traversal | `PT-001`, `PT-003` | High |
| Command Injection | `CMDI-001` | Critical |
| Remote File Inclusion | `RFI-001` | Medium |
| Local File Inclusion | `LFI-001` | High |
| SSRF | `SSRF-001` | High |
| XXE | `XXE-001` | High |
| SSTI | `SSTI-001` | High |
| JNDI | `JNDI-001` | High |
| Scanner/Bot Detection | `SCANNER-001` | Low |

## Testing the WAF

### Normal traffic (should pass)
```bash
curl http://localhost:8080/
# → 200 OK (forwarded to upstream)
```

### Attack traffic (should be blocked)
```bash
# SQL Injection
curl "http://localhost:8080/api/users?id=1' OR '1'='1"
# → 403 Forbidden (blocked by SQLI-001)

# XSS
curl "http://localhost:8080/search?q=<script>alert(1)</script>"
# → 403 Forbidden (blocked by XSS-001)

# Path Traversal
curl "http://localhost:8080/files?name=../../../etc/passwd"
# → 403 Forbidden (blocked by PT-001)
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `UPSTREAM_PORT` | 3000 | Port for the upstream backend server |
| `TRAKSHYA_FRONTEND_DIR` | `frontend` | Directory containing dashboard.html |
| `TRAKSHYA_DUCKDB_PATH` | `trakshya_events.db` | Database file path |

### Custom Ports
```bash
# macOS/Linux
UPSTREAM_PORT=4000 ./start-waf.sh

# Windows
set UPSTREAM_PORT=4000
start-waf.bat
```

## Project Structure

```
TRAKSHYA-WAF/
├── rust/                    # Rust workspace (performance-critical)
│   ├── trakshya-proxy/         # HTTP reverse proxy + request pipeline
│   ├── trakshya-rules/         # Regex-based attack detection engine
│   ├── trakshya-rate-limiter/  # Token bucket rate limiter
│   ├── trakshya-circuit-breaker/ # Upstream health monitoring
│   ├── trakshya-geoip/         # MaxMind GeoIP country blocking
│   └── trakshya-jwt/           # JWT token validation
├── go/                      # Go module (orchestration & API)
│   ├── cmd/trakshya-api/    # Management API server
│   └── internal/
│       ├── api/             # REST handlers, auth, router
│       ├── siem/            # SIEM correlation engine (7 rules)
│       ├── agents/          # Remote agent fleet management
│       ├── webhooks/        # Slack/Discord notification dispatcher
│       ├── telemetry/       # Prometheus metrics + OTLP tracing
│       ├── ws/              # WebSocket & SSE real-time events
│       └── db/              # Database layer (events, incidents, SIEM)
├── frontend/dashboard.html  # Web dashboard (browser-based)
├── config/trakshya.yaml     # Shared configuration
├── server.js                # Sample upstream backend server
├── start-waf.bat            # Windows start script
├── start-waf.sh             # macOS/Linux start script
├── scripts/                 # Build/run/test helpers
├── Makefile                 # Local task entrypoints
└── openapi.yml              # Management API spec
```

## Building from Source

### Prerequisites
- [Rust](https://rustup.rs/) (for WAF proxy)
- [Go 1.22+](https://go.dev/dl/) (for management API)
- [Node.js](https://nodejs.org/) (for upstream server)

### Build
```bash
# Build Go API
cd go && go build -o ../app/bin/trakshya-api ./cmd/trakshya-api

# Build Rust proxy
cd rust && cargo build --release -p trakshya-proxy
cp target/release/trakshya-proxy ../app/bin/
```

## Kubernetes Deployment

### Using Helm
```bash
helm install trakshya-waf ./helm/trakshya-waf \
  --namespace trakshya-waf --create-namespace \
  --set secrets.apiKey=$(openssl rand -hex 32)
```

### Using kubectl
```bash
kubectl apply -f k8s/
```

## Make Targets

```bash
make build          # build proxy, API, and C daemon
make run            # run local dev services
make smoke          # run smoke tests
make regression     # run regression tests
make test           # smoke + regression
make certs          # generate localhost dev certs
make clean          # remove build artifacts
```

## Testing

```bash
make test

# or individually
python3 scripts/smoke-test.py
python3 scripts/regression.py
```

## CI/CD

GitHub Actions workflows in `.github/workflows/`:
- `validate.yml` — live API smoke checks
- `regression.yml` — WAF rule regression tests
- `dependency-scan.yml` — npm audit, cargo audit, govulncheck
- `openapi-validation.yml` — OpenAPI schema validation
- `release.yml` — release workflow

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

See [LICENSE](LICENSE).
