#!/bin/bash
# Generates all client and server certificates used by the KMS test suite.
#
# Usage:
#   ./generate_certs.sh [/path/to/openssl]
#
# On macOS pass the Homebrew OpenSSL binary to avoid LibreSSL's deprecated RC2
# PKCS#12 algorithm:
#   ./generate_certs.sh /opt/homebrew/opt/openssl@3/bin/openssl
#
# Output layout:
#   ca/               — shared test CA (key + self-signed cert)
#   server/           — KMS server TLS certificate
#   owner/            — legacy "owner" client cert  (CN: owner.client@acme.com)
#   user/             — legacy "user" client cert   (CN: user.client@acme.com)
#   # RBAC role certs — one directory per role instance:
#   operator-1/       — Operator role (instance 1)
#   operator-2/       — Operator role (instance 2)
#   crypto-officer-1/ — CryptoOfficer role (instance 1)
#   crypto-officer-2/ — CryptoOfficer role (instance 2)
#   administrator/    — Administrator (config-only)
#   custodian-1/      — Administrator ceremony custodian
#   custodian-2/      — Administrator ceremony custodian
#   custodian-3/      — Administrator ceremony custodian
#   auditor-1/        — Auditor role (instance 1)
#   auditor-2/        — Auditor role (instance 2)
#
# All client certificates use CN=<email> so the KMS mTLS auth layer extracts
# the email address as the user identity.

set -euo pipefail

OPENSSL_BIN=${1:-openssl}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Helper: generate one client certificate ──────────────────────────────────
# gen_client <dir> <email>
gen_client() {
    local dir="$1"
    local email="$2"
    local base
    base="$(echo "$email" | tr '@' '.' | tr '/' '-')"

    mkdir -p "$dir"

    $OPENSSL_BIN genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "$dir/$base.key" 2>/dev/null

    $OPENSSL_BIN req -new \
        -key "$dir/$base.key" \
        -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=$email" \
        -out "$dir/$base.csr" 2>/dev/null

    $OPENSSL_BIN x509 -req -days 3650 \
        -in "$dir/$base.csr" \
        -CA "$SCRIPT_DIR/ca/ca.crt" \
        -CAkey "$SCRIPT_DIR/ca/ca.key" \
        -CAcreateserial \
        -out "$dir/$base.crt" 2>/dev/null

    $OPENSSL_BIN pkcs12 -export \
        -out "$dir/$base.p12" \
        -inkey "$dir/$base.key" \
        -in "$dir/$base.crt" \
        -certfile "$SCRIPT_DIR/ca/ca.crt" \
        -password pass:password 2>/dev/null

    echo "  [ok] $email → $dir/$base.{key,crt,p12}"
}

cd "$SCRIPT_DIR"

# ── CA ────────────────────────────────────────────────────────────────────────
echo "==> Generating CA..."
mkdir -p ca
$OPENSSL_BIN genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca/ca.key 2>/dev/null
$OPENSSL_BIN req -new -x509 -days 3650 \
    -key ca/ca.key \
    -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=Acme Test Root CA" \
    -out ca/ca.crt 2>/dev/null
echo "  [ok] ca/ca.crt"

# ── Server cert ───────────────────────────────────────────────────────────────
echo "==> Generating server certificate..."
mkdir -p server
$OPENSSL_BIN genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out server/kmserver.acme.com.key 2>/dev/null
$OPENSSL_BIN req -new \
    -key server/kmserver.acme.com.key \
    -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=kmserver.acme.com" \
    -out server/kmserver.acme.com.csr 2>/dev/null
$OPENSSL_BIN x509 -req -days 3650 \
    -in server/kmserver.acme.com.csr \
    -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial \
    -out server/kmserver.acme.com.crt 2>/dev/null
$OPENSSL_BIN pkcs12 -export \
    -out server/kmserver.acme.com.p12 \
    -inkey server/kmserver.acme.com.key \
    -in server/kmserver.acme.com.crt \
    -certfile ca/ca.crt \
    -password pass:password 2>/dev/null
echo "  [ok] server/kmserver.acme.com.{key,crt,p12}"

# ── Legacy client certs (backward compatibility) ──────────────────────────────
echo "==> Generating legacy client certificates..."
gen_client owner "owner.client@acme.com"
gen_client user  "user.client@acme.com"

# ── RBAC role client certs ────────────────────────────────────────────────────
echo "==> Generating RBAC role certificates..."

# Operator role
gen_client operator-1       "operator-1@example.com"
gen_client operator-2       "operator-2@example.com"

# CryptoOfficer role
gen_client crypto-officer-1 "crypto-officer-1@example.com"
gen_client crypto-officer-2 "crypto-officer-2@example.com"

# Administrator (config-only)
gen_client administrator    "administrator@example.com"

# Administrator ceremony custodians
gen_client custodian-1      "custodian-1@example.com"
gen_client custodian-2      "custodian-2@example.com"
gen_client custodian-3      "custodian-3@example.com"

# Auditor role
gen_client auditor-1        "auditor-1@example.com"
gen_client auditor-2        "auditor-2@example.com"

echo ""
echo "Done. All certificates signed by ca/ca.crt."
