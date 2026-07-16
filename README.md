# TRAKSHYA WAF — Desktop Web Application Firewall

![Deploy Landing Page](https://github.com/Pradyu12/TRAKSHYA-WAF/actions/workflows/deploy-dashboard.yml/badge.svg)

**Landing Page:** [GitHub Pages](https://pradyu12.github.io/TRAKSHYA-WAF/)

A high-performance polyglot Web Application Firewall with integrated SIEM/XDR capabilities.
Built with **Rust** (core proxy), **Go** (management API), and **C** (system monitoring).
Runs entirely on your machine via an Electron desktop app. No cloud dependency.

## Contents

- [Quick Install](#quick-install)
- [Architecture](#architecture)
- [Management CLI](#management-cli)
- [Local HTTPS Dev Certs](#local-https-dev-certs)
- [Docker](#docker)
- [Make Targets](#make-targets)
- [Testing](#testing)
- [CI/CD](#cicd)
- [Contributing](#contributing)
- [License](#license)

## Quick Install

```bash
# Option 1: local npm CLI
cd npm-package && npm link
trakshya-install install --mode=local
trakshya-waf

# Option 2: clone and setup
git clone https://github.com/Pradyu12/TRAKSHYA-WAF.git
cd TRAKSHYA-WAF
bash install.sh
trakshya-waf

# Option 3: Docker
git clone https://github.com/Pradyu12/TRAKSHYA-WAF.git
cd TRAKSHYA-WAF
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

## Project Structure

```
TRAKSHYA-WAF/
├── rust/                    # Rust workspace (performance-critical)
│   ├── krsna-proxy/         # HTTP reverse proxy + request pipeline
│   ├── krsna-rules/         # Regex-based attack detection engine
│   ├── krsna-rate-limiter/  # Token bucket rate limiter
│   ├── krsna-circuit-breaker/ # Upstream health monitoring
│   ├── krsna-geoip/         # MaxMind GeoIP country blocking
│   └── krsna-jwt/           # JWT token validation
├── go/                      # Go module (orchestration & API)
│   ├── cmd/trakshya-api/    # Management API server
│   └── internal/
│       ├── api/             # REST handlers, auth, router
│       ├── siem/            # SIEM correlation engine (7 rules)
│       ├── agents/          # Remote agent fleet management
│       ├── webhooks/        # Slack/Discord notification dispatcher
│       ├── telemetry/       # Prometheus metrics + OTLP tracing
│       ├── ws/              # WebSocket & SSE real-time events
│       └── db/              # SQLite database layer
├── c/                       # C project (system-level monitoring)
│   ├── include/trakshya.h   # Shared header
│   ├── src/
│   │   ├── hids/            # Host-based intrusion detection
│   │   ├── fim/             # File integrity monitoring (SHA-256)
│   │   ├── sca/             # Security configuration assessment
│   │   ├── vuln/            # CVE vulnerability scanning
│   │   └── active_response/ # iptables/UFW blocking, posture
│   └── tests/
├── config/trakshya.yaml     # Shared configuration
├── frontend/dashboard.html  # Web dashboard (static HTML)
├── scripts/                 # Build/run/test helpers
├── docker-compose.yml       # Local multi-service orchestration
├── docker-compose.stack.yml # Full container stack
├── openapi.yml              # Management API spec
├── Makefile                 # Local task entrypoints
├── dev-certs/               # Localhost TLS material
├── datadog/                 # Observability configs
└── .env.example             # Environment template
```

## Management CLI

```bash
# local development stack
trakshya-waf start
trakshya-waf status
trakshya-waf logs [service]
trakshya-waf stop

# quality and certs
trakshya-waf test
trakshya-waf certs
trakshya-waf scan

# Windows installer
powershell -ExecutionPolicy Bypass -File npm-package/bin/trakshya-install.ps1 install --mode=local
powershell -ExecutionPolicy Bypass -File npm-package/bin/trakshya-install.ps1 install --mode=service
powershell -ExecutionPolicy Bypass -File npm-package/bin/trakshya-install.ps1 status
```

## Local HTTPS Dev Certs

The project includes a local dev certificate generator so you can test TLS scanner paths against `https://127.0.0.1:8443`.

```bash
# generate local certs
make certs

# start mock server with HTTPS enabled
node server.js

# request local HTTPS endpoint
curl -k https://127.0.0.1:8443/health
```

### Trust the local CA

`curl -k` works for quick checks, but browsers and some scanners will still warn. To trust the local CA more broadly:

- **Chrome/Chromium:** open `Settings → Privacy and security → Security → Manage certificates → Authorities → Import` and import `dev-certs/trakshya-ca.crt`.
- **Firefox:** open `Preferences → Privacy & Security → View Certificates → Authorities → Import` and import `dev-certs/trakshya-ca.crt`.
- **macOS Keychain:** `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain dev-certs/trakshya-ca.crt`
- **Ubuntu:** copy `dev-certs/trakshya-ca.crt` to `/usr/local/share/ca-certificates/trakshya-ca.crt` and run `sudo update-ca-certificates`.

## Docker

```bash
# build and run full stack
docker compose -f docker-compose.stack.yml up --build

# detached
docker compose -f docker-compose.stack.yml up -d --build

# stop
docker compose -f docker-compose.stack.yml down
```

## Kubernetes Deployment

TRAKSHYA-WAF can be deployed on Kubernetes using the included Helm chart or raw manifests.

### Prerequisites

- Kubernetes 1.24+
- Helm 3.12+ (for Helm deployment)
- A container registry (Docker Hub, GHCR, etc.)

### Using Helm

```bash
# Add your registry images to values.yaml or pass inline
helm install trakshya-waf ./helm/trakshya-waf \
  --namespace trakshya-waf --create-namespace \
  --set image.dashboard.repository=ghcr.io/Pradyu12/trakshya-waf-dashboard \
  --set image.proxy.repository=ghcr.io/Pradyu12/trakshya-waf-proxy \
  --set image.api.repository=ghcr.io/Pradyu12/trakshya-waf-api \
  --set secrets.apiKey=$(openssl rand -hex 32)
```

### Using kubectl

```bash
kubectl apply -f k8s/
```

### Updating WAF rules/config without redeploying pods

The recommended Kubernetes update path is rolling image updates. When you change firewall rules or config:

1. Update `config/trakshya.yaml` or the WAF rules source
2. Rebuild and push images with a new tag:
   - `docker compose -f docker-compose.stack.yml build`
   - `docker push ghcr.io/Pradyu12/trakshya-waf-proxy:newtag`
3. Roll the deployment:
   - `kubectl set image deployment/trakshya-proxy proxy=ghcr.io/Pradyu12/trakshya-waf-proxy:newtag -n trakshya-waf`
   - `kubectl rollout status deployment/trakshya-proxy -n trakshya-waf`
4. For config-only changes, use a rolling restart:
   - `kubectl rollout restart deployment/trakshya-proxy -n trakshya-waf`

### Exposing the dashboard

```bash
# Option 1: LoadBalancer (cloud)
kubectl expose deployment trakshya-dashboard --port=8000 --target-port=8000 --type=LoadBalancer -n trakshya-waf

# Option 2: NodePort
kubectl expose deployment trakshya-dashboard --port=8000 --target-port=8000 --type=NodePort -n trakshya-waf

# Option 3: Ingress
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: trakshya-dashboard
  namespace: trakshya-waf
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
    - host: waf.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: trakshya-dashboard
                port:
                  number: 8000
EOF
```

## Make Targets

```bash
make build          # build proxy, API, and C daemon
make run            # run local dev services
make smoke          # run smoke tests
make regression     # run regression tests
make test           # smoke + regression
make certs          # generate localhost dev certs
make docker-build   # build docker images
make docker-up      # docker compose up
make docker-down    # docker compose down
make lint           # pre-commit run --all-files
make pre-commit-run # pre-commit run on changed files
make openapi-validate # validate openapi.yml schema
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

Use the GitHub Actions workflows in `.github/workflows/`:

- `validate.yml` — mock server route smoke checks
- `regression.yml` — VAPT + WAF rule regression suite
- `dependency-scan.yml` — `npm audit`, `cargo audit`, `govulncheck`
- `openapi-validation.yml` — `openapi.yml` schema validation
- `compose-healthgate.yml` — compose file/service ordering validation
- `release.yml` — release workflow

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

See [LICENSE](LICENSE).
