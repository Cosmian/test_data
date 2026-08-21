#!/usr/bin/env bash
# generate-test-certs.sh — Create TLS certificates for the SPIRE integration test stack.
#
# Outputs (all in the same directory as this script):
#   ca.crt / ca.key          — root CA (self-signed, 10y)
#   auth.crt / auth.key      — auth-verifier TLS cert
#                              SANs: auth-verifier, localhost, host.docker.internal
#   kms.crt  / kms.key       — KMS TLS cert
#                              SANs: cosmian-kms, localhost, host.docker.internal
#
# Usage:
#   bash tests/spire/certs/generate-test-certs.sh
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Root CA ──────────────────────────────────────────────────────────────────
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
  -keyout "${DIR}/ca.key" -out "${DIR}/ca.crt" \
  -days 3650 -nodes \
  -subj "/CN=Cosmian Test CA/O=Cosmian/C=FR"

# ── Helper: issue a leaf cert ─────────────────────────────────────────────────
issue_cert() {
  local name="$1"
  shift
  local san_hosts=("$@")

  # Build SAN extension string (DNS + IP SANs)
  local san_parts=()
  for h in "${san_hosts[@]}"; do
    # Detect IP addresses
    if [[ "$h" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      san_parts+=("IP:${h}")
    else
      san_parts+=("DNS:${h}")
    fi
  done
  local san_string
  san_string=$(
    IFS=,
    echo "${san_parts[*]}"
  )

  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
    -keyout "${DIR}/${name}.key" -out "${DIR}/${name}.csr" \
    -nodes -subj "/CN=${name}/O=Cosmian/C=FR"

  openssl x509 -req \
    -in "${DIR}/${name}.csr" \
    -CA "${DIR}/ca.crt" -CAkey "${DIR}/ca.key" -CAcreateserial \
    -out "${DIR}/${name}.crt" \
    -days 3650 \
    -extfile <(printf "subjectAltName=%s\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth" "${san_string}")

  rm -f "${DIR}/${name}.csr"
  echo "issued: ${name}.crt (SANs: ${san_string})"
}

# auth-verifier: SANs include host.docker.internal so containers can reach the
# process from inside the Docker network.
issue_cert "auth" "auth-verifier" "localhost" "host.docker.internal" "127.0.0.1"

# KMS: SANs include host.docker.internal so containers (SPIRE servers) can reach
# the KMS Vault-compatible API directly (KMS proxies /v1/auth/* itself).
issue_cert "kms" "cosmian-kms" "localhost" "host.docker.internal" "127.0.0.1"

# P-256 JWT signing key pair for auth-verifier session tokens.
# The auth-verifier TLS key uses P-384 (above); the JWKS builder requires P-256,
# so a dedicated key pair is needed for JWT operations.
# Uses PKCS#8 format (BEGIN PRIVATE KEY) as required by auth-verifier.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "${DIR}/jwt.key.pem"
openssl pkey -in "${DIR}/jwt.key.pem" -pubout \
  -out "${DIR}/jwt.pub.pem"
echo "issued: jwt.key.pem / jwt.pub.pem (P-256 PKCS#8 for JWT signing)"

echo ""
echo "Certificates generated in: ${DIR}"
echo "  ca.crt              — root CA (import into containers)"
echo "  auth.crt/key        — auth-verifier TLS (SANs: auth-verifier, localhost, host.docker.internal)"
echo "  kms.crt/key         — KMS TLS (SANs: cosmian-kms, localhost, host.docker.internal)"
echo "  jwt.key.pem/jwt.pub.pem — P-256 JWT signing key for auth-verifier"

# ── mTLS client certificate for SPIRE → KMS ──────────────────────────────────
# Used by the eviden_kms KeyManager and UpstreamAuthority plugins to authenticate
# to the KMS via mutual TLS. The KMS server validates this cert against ca.crt.
# The cert carries CN=spire-client and extendedKeyUsage=clientAuth.
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
  -keyout "${DIR}/spire-client.key" \
  -out "${DIR}/spire-client.csr" \
  -nodes -subj "/CN=spire-client/O=SPIFFE/C=US"

openssl x509 -req \
  -in "${DIR}/spire-client.csr" \
  -CA "${DIR}/ca.crt" -CAkey "${DIR}/ca.key" -CAcreateserial \
  -out "${DIR}/spire-client.crt" \
  -days 3650 \
  -extfile <(printf "keyUsage=digitalSignature\nextendedKeyUsage=clientAuth")

rm -f "${DIR}/spire-client.csr"
echo "issued: spire-client.crt (mTLS client cert for SPIRE → KMS)"
