# Changelog

All notable changes to this project will be documented in this file.
Dates are in ISO format.

## Unreleased

### Added
- Automated regression script for VAPT + WAF rule detection: `scripts/regression.py`
- CI smoke test and validation workflows: `.github/workflows/validate.yml`, `.github/workflows/regression.yml`
- CI dependency scanning: `.github/workflows/dependency-scan.yml`
- OpenAPI schema for management API: `openapi.yml`
- Docker multi-stage build and compose stack: `rust/trakshya-proxy/Dockerfile`, `go/Dockerfile`, `dashboard/Dockerfile`, `docker-compose.stack.yml`
- Management CLI subcommands: `npm-package/bin/trakshya-cli.js`
- Figlet-style ASCII logo: `scripts/trakshya-ascii.sh`
- Local dev CA and HTTPS runtime listener on `8443`
- Pre-commit hooks: `.pre-commit-config.yaml`
- Makefile entrypoints: `Makefile`
- GitHub issue/PR templates and `SECURITY.md`

### Changed
- Rebrand from KALKI-WAF to TRAKSHYA-WAF across source, CI, docs, and configs
- Refactored `server.js` to share request handling across HTTP and HTTPS listeners

## 2.0.0

### Added
- Initial multi-language WAF stack with Rust proxy, Go management API, and C system daemon
- Landing page and dashboard UI
- GitHub Actions release workflow
