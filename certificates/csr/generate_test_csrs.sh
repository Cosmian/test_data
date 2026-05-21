#!/usr/bin/env bash
# Generate test CSRs for certify integration tests.
# Requires: OpenSSL CLI
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# RSA-2048
openssl req -new -newkey rsa:2048 -nodes \
  -keyout /dev/null \
  -subj "/CN=Test CSR RSA-2048" \
  -out "${SCRIPT_DIR}/test_rsa2048.csr.pem" 2>/dev/null

# EC P-256
openssl req -new -newkey ec:<(openssl ecparam -name prime256v1) -nodes \
  -keyout /dev/null \
  -subj "/CN=Test CSR EC-P256" \
  -out "${SCRIPT_DIR}/test_ec_p256.csr.pem" 2>/dev/null

# Ed25519
openssl req -new -newkey ed25519 -nodes \
  -keyout /dev/null \
  -subj "/CN=Test CSR Ed25519" \
  -out "${SCRIPT_DIR}/test_ed25519.csr.pem" 2>/dev/null

echo "Generated CSRs in ${SCRIPT_DIR}:"
ls -1 "${SCRIPT_DIR}"/test_*.csr.pem
