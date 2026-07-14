# TRAKSHYA WAF — Desktop Web Application Firewall

![Deploy Landing Page](https://github.com/Pradyu12/KALKI-WAF/actions/workflows/deploy-dashboard.yml/badge.svg)

**Landing Page:** [GitHub Pages](https://pradyu12.github.io/KALKI-WAF/)

A high-performance polyglot Web Application Firewall with integrated SIEM/XDR capabilities.
Built with **Rust** (core proxy), **Go** (management API), and **C** (system monitoring).
Runs entirely on your machine via an Electron desktop app. No cloud dependency.

## Quick Install

```bash
# Option 1: npm (recommended)
npm install -g trakshya-waf
trakshya-waf

# Option 2: curl one-liner
curl -fsSL https://pradyu12.github.io/KALKI-WAF/install.sh | bash
trakshya-waf

# Option 3: Docker
git clone https://github.com/Pradyu12/KALKI-WAF.git
cd KALKI-WAF
docker compose up --build
# Dashboard at http://localhost:8000
```

## Architecture

```
Internet → [Rust Proxy :8080] → Upstream Web App
               │
        (reports incidents via REST/JSON)
               ↓
         [Go API :8000] ←→ SQLite
               ↑
        (C daemon reports via HTTP)
               │
         [C Daemon :9001]
```

## Language Breakdown

| Language | Component | Role |
|----------|-----------|------|
| **Rust** | Proxy, Rules Engine, Rate Limiter, Circuit Breaker, GeoIP, JWT | Performance-critical request pipeline |
| **Go** | Management API, SIEM, Agents, Webhooks, Telemetry, WebSocket | Orchestration, API, observability |
| **C** | HIDS, FIM, SCA, Vulnerability Scanner, Active Response | System-level monitoring & response |

## Features

- **Real-time threat detection** — Blocks SQLi, XSS, RFI, CMDi, path traversal, LFI, XXE, SSTI
- **Multi-language architecture** — Each component in its best-fit language, communicating via REST/JSON
- **Rate limiting** — Token bucket algorithm, per-IP sliding window
- **Circuit breaker** — Automatic upstream health monitoring with half-open recovery
- **SIEM correlation engine** — 7 detection rules (brute force, port scan, XSS/SQLi waves, etc.)
- **HIDS** — Parses auth logs, detects SSH brute force, sudo abuse
- **FIM** — SHA-256 file integrity monitoring for critical system files
- **SCA** — CIS benchmark compliance checks (file perms, SSH config, password policy)
- **Vulnerability scanner** — CVE matching against installed packages
- **Active response** — iptables/nftables IP blocking, UFW, systemd posture lockdown
- **Multiple postures** — Monitor, Standard, Under Attack
- **GeoIP blocking** — MaxMind GeoLite2 country-based blocking
- **JWT validation** — Token-based auth for management API
- **Remote agents** — Fleet management for distributed sensors
- **Webhook alerts** — Slack and Discord notification channels
- **Prometheus metrics** — Exposed at `/metrics`
- **OpenTelemetry** — Distributed tracing via OTLP exporter
- **WebSocket/SSE** — Real-time dashboard events
- **Firebase Firestore backend** - Scalable, serverless database for rules and security events
- **Dashboard UI** - Real-time telemetry and incident monitoring
- **Docker ready** - Containerized deployment with docker-compose

## Dashboard Themes

The dashboard includes 7 cyber-themed color palettes that users can switch between:

| Theme | Color | Vibe |
|-------|-------|------|
| **Cyber Violet** (default) | `#a855f7` | Holographic purple |
| **Matrix Green** | `#22c55e` | Terminal/hacker |
| **Neon Cyan** | `#06b6d4` | TRON-style ice |
| **Blood Red** | `#ef4444` | Aggressive/under-attack |
| **Electric Blue** | `#3b82f6` | Professional/clean |
| **Synthwave Pink** | `#ec4899` | Retro-wave neon |
| **Toxic Amber** | `#f59e0b` | Warning/radiation |

Theme preference is saved in `localStorage` and persists across sessions.

## Dashboard Features

- **Hologram 3D Globe** — Custom GLSL shader with Fresnel effects, scan lines, and flicker animation
- **Demo Mode** — Full functionality on GitHub Pages with embedded realistic mock data
- **Keyboard Shortcuts** — `Ctrl+K` search, `1-9` navigation, `F` fullscreen, `?` help
- **Quick Actions FAB** — Floating action button with refresh, export, theme, fullscreen
- **Attack Heatmap** — 24x7 grid showing attack density by hour/day
- **System Health Panel** — Real-time component status for all WAF services
- **Export Reports** — Download dashboard state as JSON
- **Particle Background** — Animated constellation network effect
- **Footer Status Bar** — Connection status, last update, current theme

## Getting Started

### Prerequisites

- Rust 1.75+ (Cargo)
- Go 1.22+
- CMake 3.20+, C11 compiler (gcc/clang)
- libmicrohttpd, libcurl, libssl (for C daemon)
- Docker & Docker Compose (optional)

### Building

```bash
# Build all components
./scripts/build-all.sh
```

### Running (Development)

```bash
# Start all components locally
./scripts/run-all.sh
```

### Running (Docker)

```bash
# Build and run all services
docker compose up --build

# Or in detached mode
docker compose up -d --build
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api/dashboard/stats` | Dashboard statistics |
| GET | `/api/incidents` | List recent incidents |
| POST | `/api/incidents` | Report an incident |
| PUT | `/api/incidents/{id}/acknowledge` | Acknowledge incident |
| GET | `/api/config` | Get proxy config |
| PUT | `/api/config` | Update proxy config |
| GET | `/api/posture` | Get current posture |
| PUT | `/api/posture` | Set posture (monitor/standard/under_attack) |
| GET | `/api/agents` | List registered agents |
| POST | `/api/agents/register` | Register new agent |
| GET | `/api/metrics` | Prometheus metrics |
| GET | `/ws` | WebSocket real-time events |
| GET | `/api/reload-rules` | Reload rule definitions |

## Mitigation Postures

| Posture | Rate Limit | Action |
|---------|------------|--------|
| Monitor Only | 50 req/10s | Logs threats but allows traffic |
| Standard Posture | 50 req/10s | Blocks detected threats |
| Under Attack | 10 req/10s | Aggressive blocking |

## Default Security Rules

- SQLi Core Ruleset (OWASP)
- XSS Aggressive Scrutiny
- Remote File Inclusion (RFI)
- Command Injection Shield
- Path Traversal Protection
- And more...

## Project Structure

```
KALKI-WAF/
├── rust/                    # Rust workspace (performance-critical)
│   ├── kalki-proxy/         # HTTP reverse proxy + request pipeline
│   ├── kalki-rules/         # Regex-based attack detection engine
│   ├── kalki-rate-limiter/  # Token bucket rate limiter
│   ├── kalki-circuit-breaker/ # Upstream health monitoring
│   ├── kalki-geoip/         # MaxMind GeoIP country blocking
│   └── kalki-jwt/           # JWT token validation
├── go/                      # Go module (orchestration & API)
│   ├── cmd/kalki-api/       # Management API server
│   └── internal/
│       ├── api/             # REST handlers, auth, router
│       ├── siem/            # SIEM correlation engine (7 rules)
│       ├── agents/          # Remote agent fleet management
│       ├── webhooks/        # Slack/Discord notification dispatcher
│       ├── telemetry/       # Prometheus metrics + OTLP tracing
│       ├── ws/              # WebSocket & SSE real-time events
│       └── db/              # SQLite database layer
├── c/                       # C project (system-level monitoring)
│   ├── include/kalki.h      # Shared header
│   ├── src/
│   │   ├── hids/            # Host-based intrusion detection
│   │   ├── fim/             # File integrity monitoring (SHA-256)
│   │   ├── sca/             # Security configuration assessment
│   │   ├── vuln/            # CVE vulnerability scanning
│   │   └── active_response/ # iptables/UFW blocking, posture
│   └── tests/
├── config/kalki.yaml        # Shared configuration
├── frontend/dashboard.html  # Web dashboard (static HTML)
├── scripts/
│   ├── build-all.sh         # Build all 3 languages
│   └── run-all.sh           # Start all 3 daemons
├── docker-compose.yml       # Multi-service orchestration
├── datadog/                 # Datadog monitoring configs
└── .env.example             # Environment template
```

## CI/CD

The project includes GitHub Actions CI/CD pipeline:
- Automated testing on PRs
- Docker image build and push on main branch
- GitHub Container Registry integration

## Deployment

### GitHub Pages (Landing Page)

The landing page is deployed automatically to GitHub Pages on every push to `main` via the `deploy-dashboard.yml` workflow. It deploys the `landing/` directory.

### Local Installation

The full WAF dashboard runs locally on your machine:

1. **AppImage** — Single file, no dependencies. Download from GitHub Releases.
2. **npm** — `npm install -g trakshya-waf` downloads and installs the AppImage automatically.
3. **Docker** — `docker compose up --build` runs all services in containers.

### Local Development

```bash
# Start the Go API server with dashboard
cd go && CGO_ENABLED=1 go build -o ../build/kalki-api ./cmd/kalki-api/
cd ..
KALKI_FRONTEND_DIR="$(pwd)/frontend" ./build/kalki-api --config config/kalki.yaml
# Dashboard at http://localhost:8000
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



## Datadog Monitoring

This project includes built-in Datadog integration for metrics, traces, and log collection.

### Architecture

The Datadog Agent runs as a sidecar container alongside the WAF, collecting telemetry via:
- **OpenTelemetry OTLP** - Traces from the WAF FastAPI application forwarded to Datadog APM
- **Prometheus / OpenMetrics** - Metrics (request rate, block rate, latency, etc.) scraped from /metrics
- **Docker Log Collection** - All container logs automatically collected and tagged

### Setup

1. **Get a Datadog API Key**: app.datadoghq.com/organization-settings/api-keys
2. **Set environment variables** (in .env or your CI/CD):

DD_API_KEY=your_api_key_here
DD_SITE=datadoghq.com          # or datadoghq.eu
DD_ENV=production              # or staging / development

3. **Deploy with Docker Compose**:

export DD_API_KEY=your_api_key_here
docker compose up -d --build

### What Gets Monitored

| Data Type | Source | Destination |
|-----------|--------|-------------|
| Application traces | OpenTelemetry (OTLP gRPC, port 4317) | Datadog APM |
| Prometheus metrics | waf:8000/metrics | Datadog Metrics |
| Container logs | Docker daemon | Datadog Logs |
| System metrics | Datadog Agent | Datadog Infrastructure |

### Dashboards & Monitors

Pre-built dashboard and monitor definitions are in the datadog/ directory:

| File | Description |
|------|-------------|
| datadog/dashboard.json | Security Overview dashboard (import via Datadog UI) |
| datadog/monitors/waf-monitors.json | Alert monitors (block rate, timeouts, agent health, latency) |
| datadog/conf.d/openmetrics.d/conf.yaml | Agent-side Prometheus scraping config |
| datadog/conf.d/logs.d/conf.yaml | Log metadata enrichment config |

### Importing Monitors and Dashboards

1. Dashboard: In Datadog - Dashboards - New Dashboard - Import from JSON
2. Monitors: Use the Datadog API or manually recreate from datadog/monitors/waf-monitors.json

### CI/CD Pipeline Integration

The GitLab CI pipeline (.gitlab-ci.yml) includes:
- Git metadata labeling on Docker images for source-to-trace correlation
- Optional datadog-ci trace upload (requires DD_API_KEY in CI variables)
- Unified service tagging (DD_SERVICE, DD_ENV, DD_VERSION) on all artifacts

### Key Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| DD_API_KEY | (required) | Datadog API key for agent authentication |
| DD_SITE | datadoghq.com | Datadog intake site |
| DD_ENV | production | Deployment environment label |
| DD_AGENT_HOST | datadog-agent | Agent hostname (internal Docker DNS) |
| OTEL_EXPORTER_OTLP_ENDPOINT | http://datadog-agent:4317 | OTLP gRPC endpoint |

## License

This project is licensed under the MIT License.

## Support

- GitHub Issues: [https://github.com/your-org/kalki-waf/issues](https://github.com/your-org/kalki-waf/issues)
- Documentation: [https://github.com/your-org/kalki-waf/wiki](https://github.com/your-org/kalki-waf/wiki)