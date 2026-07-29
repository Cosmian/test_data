#!/usr/bin/env bash
# provision.sh — Bootstrap AppRole credentials for the SPIRE integration test stack.
#
# Called by `mise run test:spire` after KMS and auth-verifier are healthy.
#
# Auth flow:
#   - Admin operations (AppRole CRUD) use `ckms vault approle`, which talks
#     DIRECTLY to the auth-verifier at AUTH_VERIFIER_URL (it performs the admin
#     `/login?realm=_` cookie handshake internally). The KMS never proxies the
#     admin API.
#   - Transit smoke test goes through KMS at VAULT_ADDR using an
#     AppRole token obtained via `POST /v1/auth/approle/login` (KMS proxies
#     /v1/auth/* to auth-verifier /auth/*).
#
# Environment:
#   AUTH_VERIFIER_URL -- auth-verifier base URL; default: https://localhost:8443
#   VAULT_ADDR        -- KMS base URL; default: https://localhost:9998
#   VAULT_CACERT      -- path to CA cert; default: test_data/spire/certs/ca.crt
#   ADMIN_USER        -- auth-verifier admin username; default: admin
#   ADMIN_PASS        -- auth-verifier admin password; default: change_me
#   CKMS_BIN          -- path to the ckms binary (required for admin AppRole ops)
#   CKMS_CONF         -- ckms client config path (KMS conf; required)
#   SECRETS_ENV_FILE  -- output file path; default: /tmp/spire-secrets.env

set -euo pipefail

AUTH_VERIFIER_URL="${AUTH_VERIFIER_URL:-https://localhost:8443}"
VAULT_ADDR="${VAULT_ADDR:-https://localhost:9998}"
VAULT_CACERT="${VAULT_CACERT:-test_data/spire/certs/ca.crt}"

ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-change_me}"

SECRETS_ENV_FILE="${SECRETS_ENV_FILE:-/tmp/spire-secrets.env}"

log() { echo "[provision] $*"; }

if [[ -z "${CKMS_BIN:-}" ]]; then
  echo "[provision] ERROR: CKMS_BIN is not set (path to the ckms binary)." >&2
  exit 1
fi
if [[ -z "${CKMS_CONF:-}" ]]; then
  echo "[provision] ERROR: CKMS_CONF is not set (ckms client config path)." >&2
  exit 1
fi

# ── ckms admin helper (talks DIRECTLY to the auth-verifier) ───────────────────
# Every `ckms vault approle` sub-command is an auth-verifier admin operation: it
# performs the admin `/login?realm=_` cookie handshake internally, so we point
# it at AUTH_VERIFIER_URL directly. --accept-invalid-certs: the test
# auth-verifier presents a self-signed certificate.
ckms_approle() {
  "${CKMS_BIN}" --conf-path "${CKMS_CONF}" vault approle "$@" \
    --auth-verifier-url "${AUTH_VERIFIER_URL}" \
    --admin-user "${ADMIN_USER}" \
    --admin-password "${ADMIN_PASS}" \
    --accept-invalid-certs
}

# ── 1+2. Create per-tenant SPIRE AppRoles ────────────────────────────────────
# Two INDEPENDENT SPIRE servers (tenants "a" and "b") run against the same KMS,
# each with its OWN AppRole so their Vault UpstreamAuthority logins are isolated.
# create_spire_approle <role-name> prints "<role_id> <secret_id>" on stdout so
# the caller can capture both (avoids bash 4.3 namerefs for macOS portability).
create_spire_approle() {
  local role_name="$1" role_id secret_id

  log "Creating AppRole '${role_name}' via ckms..." >&2
  ckms_approle create-role "${role_name}" --token-ttl 3600 --token-policies default >&2

  # get-role-id prints the raw role_id; generate-secret-id prints "secret_id: <v>".
  role_id=$(ckms_approle get-role-id "${role_name}" | tr -d '[:space:]')
  log "${role_name} role_id: ${role_id}" >&2

  secret_id=$(ckms_approle generate-secret-id "${role_name}" | awk '/^secret_id:/{print $2}')
  log "${role_name} secret_id obtained." >&2

  echo "${role_id} ${secret_id}"
}

read -r SPIRE_ROLE_ID_A SPIRE_SECRET_ID_A < <(create_spire_approle spire-server-a)
read -r SPIRE_ROLE_ID_B SPIRE_SECRET_ID_B < <(create_spire_approle spire-server-b)

# ── 3. Create AppRole: mistral-agents ────────────────────────────────────────
log "Creating AppRole 'mistral-agents' via ckms..."
ckms_approle create-role mistral-agents --token-ttl 3600 --token-policies default
MISTRAL_ROLE_ID=$(ckms_approle get-role-id mistral-agents | tr -d '[:space:]')
log "mistral-agents role_id: ${MISTRAL_ROLE_ID}"
MISTRAL_SECRET_ID=$(ckms_approle generate-secret-id mistral-agents | awk '/^secret_id:/{print $2}')
log "mistral-agents secret_id obtained."

# ── 4. Transit smoke test via KMS ─────────────────────────────────────────────
# Login with the mistral-agents AppRole via KMS (which proxies /v1/auth/* to
# auth-verifier).  On success, list transit keys to verify the full Vault API
# path (auth → transit) is reachable through KMS.
log "Transit smoke test: logging in with mistral-agents AppRole..."
MISTRAL_TOKEN=""
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  MISTRAL_TOKEN=$(curl -sf \
    --cacert "${VAULT_CACERT}" \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{\"role_id\":\"${MISTRAL_ROLE_ID}\",\"secret_id\":\"${MISTRAL_SECRET_ID}\"}" \
    "${VAULT_ADDR}/v1/auth/approle/login" \
    2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])" 2>/dev/null) \
    || true
  if [[ -n "${MISTRAL_TOKEN:-}" ]]; then
    break
  fi
  log "AppRole login via KMS not ready yet (attempt ${attempt}/10), retrying in 3s..."
  sleep 3
done

if [[ -n "${MISTRAL_TOKEN:-}" ]]; then
  TRANSIT_LIST=$(curl -sf \
    --cacert "${VAULT_CACERT}" \
    -H "X-Vault-Token: ${MISTRAL_TOKEN}" \
    "${VAULT_ADDR}/v1/transit/keys" 2>/dev/null || echo "{}")
  log "Transit smoke test OK. Response: ${TRANSIT_LIST:0:80}..."
else
  echo "[provision] ERROR: KMS auth proxy could not reach auth-verifier after 10 attempts." >&2
  exit 1
fi

# ── 5. Write credentials to env file ─────────────────────────────────────────
log "Writing credentials to ${SECRETS_ENV_FILE}..."
cat > "${SECRETS_ENV_FILE}" <<EOF
# Generated by provision.sh -- source this file to inject AppRole credentials.
# DO NOT COMMIT -- contains test secrets.
# Per-tenant SPIRE server AppRoles (tenants a and b run against the same KMS).
export SPIRE_ROLE_ID_A="${SPIRE_ROLE_ID_A}"
export SPIRE_SECRET_ID_A="${SPIRE_SECRET_ID_A}"
export SPIRE_ROLE_ID_B="${SPIRE_ROLE_ID_B}"
export SPIRE_SECRET_ID_B="${SPIRE_SECRET_ID_B}"
export MISTRAL_ROLE_ID="${MISTRAL_ROLE_ID}"
export MISTRAL_SECRET_ID="${MISTRAL_SECRET_ID}"
EOF
chmod 600 "${SECRETS_ENV_FILE}"

log ""
log "=== Provisioning complete ==="
log "  SPIRE tenant-a AppRole role_id: ${SPIRE_ROLE_ID_A}"
log "  SPIRE tenant-b AppRole role_id: ${SPIRE_ROLE_ID_B}"
log "  Mistral AppRole role_id:        ${MISTRAL_ROLE_ID}"
log "  Credentials written to:         ${SECRETS_ENV_FILE}"
log "  PKI CA key must already exist in KMS with tag: vault_pki_ca"
