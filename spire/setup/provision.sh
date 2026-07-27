#!/usr/bin/env bash
# provision.sh — Bootstrap AppRole credentials and PKI CA key for the SPIRE test stack.
#
# Run ONCE after `docker compose up -d` brings all services healthy:
#
#   docker compose -f tests/spire/docker-compose.yml exec cosmian-auth bash /setup/provision.sh
#
# OR from the host (set VAULT_ADDR to the nginx proxy address):
#
#   VAULT_ADDR=https://localhost:8200 VAULT_CACERT=tests/spire/certs/ca.crt \
#     bash tests/spire/setup/provision.sh
#
# What it does:
#   1. Obtain an admin token from auth-verifier (using the built-in admin credentials).
#   2. Create AppRole "spire-server"    (G5: dedicated role for SPIRE).
#   3. Create AppRole "mistral-agents"  (G5: dedicated role for Mistral AI agents).
#   4. Generate secret-IDs for both roles and write them to /run/secrets/.
#   5. Via ckms CLI: create an EC P-384 CA key pair tagged vault_pki_ca in KMS.

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-https://vault-proxy:8200}"
VAULT_CACERT="${VAULT_CACERT:-/etc/auth_verifier/ca.crt}"
KMS_URL="${KMS_URL:-https://cosmian-kms:9998}"

# Admin credentials for the auth-verifier (set via env or use defaults for test).
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-AdminPassword123!}"

SECRETS_DIR="${SECRETS_DIR:-/run/secrets}"
mkdir -p "${SECRETS_DIR}"

log() { echo "[provision] $*"; }

# ── 1. Obtain admin token ─────────────────────────────────────────────────────
log "Obtaining admin token from auth-verifier..."
ADMIN_TOKEN=$(curl -sf \
  --cacert "${VAULT_CACERT}" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" \
  "${VAULT_ADDR}/v1/auth/userpass/login/${ADMIN_USER}" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['auth']['client_token'])")
log "Admin token obtained."

vault_api() {
  local method="$1"; local path="$2"; shift 2
  curl -sf \
    --cacert "${VAULT_CACERT}" \
    -X "${method}" \
    -H "X-Vault-Token: ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    "$@" \
    "${VAULT_ADDR}${path}"
}

# ── 2. Create AppRole: spire-server (G5) ──────────────────────────────────────
log "Creating AppRole 'spire-server'..."
vault_api POST /v1/auth/approle/role/spire-server -d '{
  "token_ttl":       "1h",
  "token_max_ttl":   "4h",
  "token_policies":  ["default"],
  "secret_id_ttl":   "0",
  "secret_id_num_uses": 0
}' > /dev/null

SPIRE_ROLE_ID=$(vault_api GET /v1/auth/approle/role/spire-server/role-id \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['role_id'])")
log "spire-server role_id: ${SPIRE_ROLE_ID}"

SPIRE_SECRET_ID=$(vault_api POST /v1/auth/approle/role/spire-server/secret-id \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['secret_id'])")
log "spire-server secret_id obtained (redacted)."

echo "${SPIRE_ROLE_ID}"   > "${SECRETS_DIR}/spire-role-id"
echo "${SPIRE_SECRET_ID}" > "${SECRETS_DIR}/spire-secret-id"
chmod 600 "${SECRETS_DIR}/spire-role-id" "${SECRETS_DIR}/spire-secret-id"

# ── 3. Create AppRole: mistral-agents (G5) ────────────────────────────────────
log "Creating AppRole 'mistral-agents'..."
vault_api POST /v1/auth/approle/role/mistral-agents -d '{
  "token_ttl":       "1h",
  "token_max_ttl":   "4h",
  "token_policies":  ["default"],
  "secret_id_ttl":   "0",
  "secret_id_num_uses": 0
}' > /dev/null

MISTRAL_ROLE_ID=$(vault_api GET /v1/auth/approle/role/mistral-agents/role-id \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['role_id'])")
log "mistral-agents role_id: ${MISTRAL_ROLE_ID}"

MISTRAL_SECRET_ID=$(vault_api POST /v1/auth/approle/role/mistral-agents/secret-id \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['secret_id'])")
log "mistral-agents secret_id obtained (redacted)."

echo "${MISTRAL_ROLE_ID}"   > "${SECRETS_DIR}/mistral-role-id"
echo "${MISTRAL_SECRET_ID}" > "${SECRETS_DIR}/mistral-secret-id"
chmod 600 "${SECRETS_DIR}/mistral-role-id" "${SECRETS_DIR}/mistral-secret-id"

# ── 4. Create SPIRE join token ────────────────────────────────────────────────
log "Creating SPIRE join token..."
# Token must match the one in spire-agent.conf (cosmian-test-join-token-12345).
# In a production setup, create a fresh token per deployment:
#   /opt/spire/bin/spire-server token generate -spiffeID spiffe://trust-domain/agent
log "Join token is hardcoded in spire-agent.conf for local testing: cosmian-test-join-token-12345"
log "For production, replace with: spire-server token generate -spiffeID spiffe://cosmian-test.local/agent/local"

# ── 5. Register SPIRE workload entries ────────────────────────────────────────
log "Registering SPIRE workload entries for mistral agents..."
# These allow any process with unix uid=1000 to obtain a SPIFFE identity.
# In production, use more specific selectors (process path, container image, etc.)
#
# Run from inside the spire-server container:
#   /opt/spire/bin/spire-server entry create \
#     -spiffeID spiffe://cosmian-test.local/mistral-agent \
#     -parentID  spiffe://cosmian-test.local/agent/local \
#     -selector  unix:uid:1000
log "To register workload entries, run from the spire-server container:"
log "  /opt/spire/bin/spire-server entry create \\"
log "    -spiffeID spiffe://cosmian-test.local/mistral-agent \\"
log "    -parentID  spiffe://cosmian-test.local/agent/local \\"
log "    -selector  unix:uid:1000"

# ── 6. Create PKI CA key in KMS ────────────────────────────────────────────────
log "Creating PKI CA key in KMS (EC P-384, tagged vault_pki_ca)..."
# Use ckms CLI if available, otherwise use the KMS REST API directly.
if command -v ckms &> /dev/null; then
  ckms --url "${KMS_URL}" \
    ec keys create \
    --curve p384 \
    --algorithm ec \
    --tag vault_pki_ca
  log "PKI CA key created via ckms."
else
  log "ckms not found. Create the PKI CA key manually:"
  log "  ckms --url ${KMS_URL} ec keys create --curve p384 --tag vault_pki_ca"
fi

log ""
log "=== Provisioning complete ==="
log "  SPIRE AppRole credentials: ${SECRETS_DIR}/spire-role-id, spire-secret-id"
log "  Mistral AppRole credentials: ${SECRETS_DIR}/mistral-role-id, mistral-secret-id"
log "  PKI CA key tagged: vault_pki_ca (in KMS)"
