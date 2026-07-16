#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEV_CERTS_DIR="${REPO_ROOT}/dev-certs"
mkdir -p "$DEV_CERTS_DIR"

if command -v openssl >/dev/null 2>&1; then
  echo "Generating local dev CA and localhost certs..."
  openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
    -keyout "${DEV_CERTS_DIR}/trakshya-ca.key" \
    -out "${DEV_CERTS_DIR}/trakshya-ca.crt" \
    -subj "/CN=TRAKSHYA WAF Dev CA" || true

  openssl req -new -newkey rsa:2048 -nodes \
    -keyout "${DEV_CERTS_DIR}/localhost.key" \
    -out "${DEV_CERTS_DIR}/localhost.csr" \
    -subj "/CN=localhost" || true

  cat > "${DEV_CERTS_DIR}/localhost.ext" <<'EOF'
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
EOF

  openssl x509 -req -in "${DEV_CERTS_DIR}/localhost.csr" \
    -CA "${DEV_CERTS_DIR}/trakshya-ca.crt" \
    -CAkey "${DEV_CERTS_DIR}/trakshya-ca.key" \
    -CAcreateserial -out "${DEV_CERTS_DIR}/localhost.crt" \
    -days 365 -sha256 -extfile "${DEV_CERTS_DIR}/localhost.ext" || true

  echo "Dev certs written to: ${DEV_CERTS_DIR}"
else
  echo "openssl not found; skipping dev cert generation."
fi
