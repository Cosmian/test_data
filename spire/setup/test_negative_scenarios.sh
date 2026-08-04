#!/usr/bin/env bash
# test_negative_scenarios.sh — adversarial / negative-path tests for the
# KMS + auth-verifier drop-in Vault replacement used by SPIRE.
#
# Where test_vault_api.sh proves the *happy path* wire contract, this script
# attacks it: cross-tenant isolation, proxy path traversal, AppRole secret_id
# num_uses race, exportable-bypass, malformed-input fuzzing, and lifecycle
# orphaning. Each section maps to a numbered scenario in reviews_spire_live.md.
#
# Recommended execution order (highest risk first): 11, 9, 1, 5, then 4, 8, 7, 12.
#
# Required environment:
#   VAULT_ADDR         — KMS base URL, e.g. https://localhost:9998
#   VAULT_CACERT       — path to PEM CA bundle for TLS verification
#   AUTH_VERIFIER_URL  — auth-verifier base URL, e.g. https://localhost:8443
#   ADMIN_USER         — auth-verifier admin username (for throwaway role CRUD)
#   ADMIN_PASS         — auth-verifier admin password
#   SPIRE_ROLE_ID_A    — tenant-a AppRole role_id   (victim owner)
#   SPIRE_SECRET_ID_A  — tenant-a AppRole secret_id
#   SPIRE_ROLE_ID_B    — tenant-b AppRole role_id   (attacker — different KMS owner)
#   SPIRE_SECRET_ID_B  — tenant-b AppRole secret_id
#   CKMS_BIN           — path to the ckms/cosmian CLI binary
#   CKMS_CONF          — path to the ckms client config for the KMS
#
# Exit code: 0 when all scenarios pass; non-zero on first failure (set -e).

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-https://localhost:9998}"
VAULT_CACERT="${VAULT_CACERT:-}"
AUTH_VERIFIER_URL="${AUTH_VERIFIER_URL:-https://localhost:8443}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-change_me}"
SPIRE_ROLE_ID_A="${SPIRE_ROLE_ID_A:-}"
SPIRE_SECRET_ID_A="${SPIRE_SECRET_ID_A:-}"
SPIRE_ROLE_ID_B="${SPIRE_ROLE_ID_B:-}"
SPIRE_SECRET_ID_B="${SPIRE_SECRET_ID_B:-}"
CKMS_BIN="${CKMS_BIN:-}"
CKMS_CONF="${CKMS_CONF:-}"
VERBOSE="${VERBOSE:-}"

# ── Colour helpers ─────────────────────────────────────────────────────────────
_RED='\033[0;31m'; _GREEN='\033[0;32m'; _YELLOW='\033[1;33m'; _NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

_pass() { PASS_COUNT=$((PASS_COUNT + 1)); echo -e "  ${_GREEN}PASS${_NC}  $1"; }
_fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo -e "  ${_RED}FAIL${_NC}  $1" >&2
  echo -e "  ${_RED}      $2${_NC}" >&2
  exit 1
}
_section() { echo; echo -e "${_YELLOW}── $* ──${_NC}"; }

# ── curl wrapper ──────────────────────────────────────────────────────────────
# Writes response body to _HTTP_BODY and HTTP status to _HTTP_STATUS.
# Uses VAULT_TOKEN (X-Vault-Token) when set. Extra curl args precede the URL.
_CURL_BODY_FILE=$(mktemp /tmp/neg-test-body.XXXXXX)
_TMP=$(mktemp -d /tmp/neg-test.XXXXXX)
trap 'rm -rf "${_CURL_BODY_FILE}" "${_TMP}"' EXIT

_HTTP_STATUS=""
_HTTP_BODY=""

_vcurl() {
  local _args=(-s -o "${_CURL_BODY_FILE}" -w "%{http_code}" --max-time 20)
  [[ -n "${VAULT_CACERT}" ]] && _args+=(--cacert "${VAULT_CACERT}")
  [[ -n "${VAULT_TOKEN:-}" ]] && _args+=(-H "X-Vault-Token: ${VAULT_TOKEN}")
  _HTTP_STATUS=$(curl "${_args[@]}" "$@") || {
    _fail "curl failed" "command: curl $*"
  }
  _HTTP_BODY=$(cat "${_CURL_BODY_FILE}")
  [[ -n "${VERBOSE:-}" ]] && echo "    HTTP ${_HTTP_STATUS} ← ${_HTTP_BODY:0:300}" >&2 || true
}

# Assert exact HTTP status.
_assert_status() {
  local name="$1" expected="$2"
  [[ "${_HTTP_STATUS}" == "${expected}" ]] ||
    _fail "${name}" "expected HTTP ${expected}, got ${_HTTP_STATUS}. Body: ${_HTTP_BODY:0:300}"
}

# Assert HTTP status is a 4xx (client rejection), never 2xx/5xx.
_assert_4xx() {
  local name="$1"
  if [[ "${_HTTP_STATUS}" =~ ^4[0-9][0-9]$ ]]; then
    return 0
  fi
  _fail "${name}" "expected 4xx, got ${_HTTP_STATUS}. Body: ${_HTTP_BODY:0:300}"
}

# Assert HTTP status is NOT 2xx (i.e. the operation was refused). Accepts 4xx/5xx.
_assert_not_2xx() {
  local name="$1"
  if [[ "${_HTTP_STATUS}" =~ ^2[0-9][0-9]$ ]]; then
    _fail "${name}" "expected non-2xx (refusal), got ${_HTTP_STATUS}. Body: ${_HTTP_BODY:0:300}"
  fi
}

# Extract a Python-evaluated field from _HTTP_BODY; fails if absent/null.
_json() {
  local name="$1" expr="$2" result
  result=$(echo "${_HTTP_BODY}" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    v = ${expr}
    print('__NULL__' if v is None else v)
except Exception as e:
    print('__ERROR__: ' + str(e))
" 2>&1) || true
  if [[ "${result}" == __NULL__* || "${result}" == __ERROR__* ]]; then
    _fail "${name}" "JSON field '${expr}' absent/null. Body: ${_HTTP_BODY:0:400}"
  fi
  echo "${result}"
}

# AppRole login against the KMS proxy; sets VAULT_TOKEN. Fails on non-200.
_login() {
  local name="$1" role_id="$2" secret_id="$3"
  local saved="${VAULT_TOKEN:-}"; VAULT_TOKEN=""
  _vcurl -X POST -H "Content-Type: application/json" \
    -d "{\"role_id\":\"${role_id}\",\"secret_id\":\"${secret_id}\"}" \
    "${VAULT_ADDR}/v1/auth/approle/login"
  if [[ "${_HTTP_STATUS}" != "200" ]]; then
    VAULT_TOKEN="${saved}"
    _fail "${name}" "AppRole login failed: HTTP ${_HTTP_STATUS}. Body: ${_HTTP_BODY:0:300}"
  fi
  VAULT_TOKEN=$(_json "${name}" "d['auth']['client_token']")
}

# Admin session cookie against the auth-verifier (for throwaway AppRole CRUD).
_ADMIN_COOKIE="${_TMP}/admin-cookie"
_admin_login() {
  local creds
  creds=$(printf '%s:%s' "${ADMIN_USER}" "${ADMIN_PASS}" | base64 | tr -d '\n')
  local args=(-s -o /dev/null -w "%{http_code}" --max-time 20 -c "${_ADMIN_COOKIE}")
  [[ -n "${VAULT_CACERT}" ]] && args+=(--cacert "${VAULT_CACERT}")
  local code
  code=$(curl "${args[@]}" -X POST \
    -H "Authorization: Basic ${creds}" -H "Content-Type: application/json" \
    -d '{}' "${AUTH_VERIFIER_URL}/login?realm=_")
  [[ "${code}" == "200" ]] ||
    _fail "admin-login" "admin cookie login failed: HTTP ${code}"
}

# Call the auth-verifier admin API with the session cookie; echoes body.
_admin_api() {
  local method="$1" path="$2"; shift 2
  local args=(-sf --max-time 20 -b "${_ADMIN_COOKIE}")
  [[ -n "${VAULT_CACERT}" ]] && args+=(--cacert "${VAULT_CACERT}")
  curl "${args[@]}" -X "${method}" -H "Content-Type: application/json" \
    "$@" "${AUTH_VERIFIER_URL}${path}"
}

_RAND="$(date +%s)$$"

# ── Preconditions ─────────────────────────────────────────────────────────────
for _v in VAULT_CACERT SPIRE_ROLE_ID_A SPIRE_SECRET_ID_A SPIRE_ROLE_ID_B SPIRE_SECRET_ID_B; do
  [[ -n "${!_v}" ]] || _fail "preconditions" "required env var ${_v} is empty"
done

echo -e "${_YELLOW}=========================================================${_NC}"
echo -e "${_YELLOW}  SPIRE adversarial / negative-scenario tests${_NC}"
echo -e "${_YELLOW}=========================================================${_NC}"

# =============================================================================
# Scenario 11 — Cross-tenant transit isolation
# =============================================================================
# Tenant-a (SPIRE_ROLE_ID_A) and tenant-b (SPIRE_ROLE_ID_B) are DIFFERENT
# AppRoles → different KMS owners. A key created by A must be completely
# invisible/untouchable to B: get/sign/delete → 404, and absent from B's list.
_section "Scenario 11 — cross-tenant transit isolation"

VICTIM="victim-${_RAND}"

_login "N11-login-a" "${SPIRE_ROLE_ID_A}" "${SPIRE_SECRET_ID_A}"
TOK_A="${VAULT_TOKEN}"

echo -n "[N11-01] tenant-a creates transit key '${VICTIM}' → 200 … "
VAULT_TOKEN="${TOK_A}" _vcurl -X POST -H "Content-Type: application/json" \
  -d '{"type":"ecdsa-p256","exportable":false,"auto_rotate_period":0}' \
  "${VAULT_ADDR}/v1/transit/keys/${VICTIM}"
_assert_status "N11-01" "200"
_pass "N11-01 tenant-a create"

echo -n "[N11-02] tenant-a can read its own key → 200 (positive control) … "
VAULT_TOKEN="${TOK_A}" _vcurl -X GET "${VAULT_ADDR}/v1/transit/keys/${VICTIM}"
_assert_status "N11-02" "200"
_pass "N11-02 owner read"

_login "N11-login-b" "${SPIRE_ROLE_ID_B}" "${SPIRE_SECRET_ID_B}"
TOK_B="${VAULT_TOKEN}"

echo -n "[N11-03] tenant-b GET tenant-a's key → 404 … "
VAULT_TOKEN="${TOK_B}" _vcurl -X GET "${VAULT_ADDR}/v1/transit/keys/${VICTIM}"
_assert_status "N11-03" "404"
_pass "N11-03 cross-tenant read blocked"

echo -n "[N11-04] tenant-b sign with tenant-a's key → 404 … "
_DIGEST_B64=$(printf 'attack' | openssl dgst -sha256 -binary | openssl base64 -A)
VAULT_TOKEN="${TOK_B}" _vcurl -X POST -H "Content-Type: application/json" \
  -d "{\"input\":\"${_DIGEST_B64}\",\"marshaling_algorithm\":\"asn1\",\"prehashed\":true}" \
  "${VAULT_ADDR}/v1/transit/sign/${VICTIM}/sha2-256"
_assert_status "N11-04" "404"
_pass "N11-04 cross-tenant sign blocked"

echo -n "[N11-05] tenant-b DELETE tenant-a's key → 404 … "
VAULT_TOKEN="${TOK_B}" _vcurl -X DELETE "${VAULT_ADDR}/v1/transit/keys/${VICTIM}"
_assert_status "N11-05" "404"
_pass "N11-05 cross-tenant delete blocked"

echo -n "[N11-06] tenant-b list does NOT contain tenant-a's key … "
VAULT_TOKEN="${TOK_B}" _vcurl -X GET "${VAULT_ADDR}/v1/transit/keys"
if echo "${_HTTP_BODY}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
keys = d.get('data', {}).get('keys', [])
sys.exit(0 if '${VICTIM}' not in keys else 1)
"; then
  _pass "N11-06 cross-tenant list isolation"
else
  _fail "N11-06" "tenant-a's key '${VICTIM}' leaked into tenant-b's key list: ${_HTTP_BODY:0:300}"
fi

echo -n "[N11-07] tenant-a's key survived tenant-b's attacks → still 200 … "
VAULT_TOKEN="${TOK_A}" _vcurl -X GET "${VAULT_ADDR}/v1/transit/keys/${VICTIM}"
_assert_status "N11-07" "200"
_pass "N11-07 victim intact after attacks"

# Cleanup: owner deletes its key.
VAULT_TOKEN="${TOK_A}" _vcurl -X POST -H "Content-Type: application/json" \
  -d '{"deletion_allowed":true}' "${VAULT_ADDR}/v1/transit/keys/${VICTIM}/config"
VAULT_TOKEN="${TOK_A}" _vcurl -X DELETE "${VAULT_ADDR}/v1/transit/keys/${VICTIM}"

# =============================================================================
# Scenario 9 — Proxy path traversal + unauthenticated admin CRUD
# =============================================================================
# The KMS /v1/auth/* proxy must never let a client escape the auth namespace
# into the admin API via dot-segments, nor reach admin CRUD without a session.
_section "Scenario 9 — proxy path traversal + unauth admin CRUD"

# --path-as-is prevents curl from collapsing ../ before it reaches the KMS.
echo -n "[N09-01] /v1/auth/../admins/realms (literal ..) → 400 … "
_vcurl --path-as-is -X GET "${VAULT_ADDR}/v1/auth/../admins/realms"
_assert_status "N09-01" "400"
_pass "N09-01 literal dot-segment rejected"

echo -n "[N09-02] /v1/auth/%2e%2e/admins/realms (encoded ..) → 400 … "
_vcurl --path-as-is -X GET "${VAULT_ADDR}/v1/auth/%2e%2e/admins/realms"
_assert_status "N09-02" "400"
_pass "N09-02 encoded dot-segment rejected"

echo -n "[N09-03] /v1/auth/approle/../../admins (nested ..) → 400 … "
_vcurl --path-as-is -X GET "${VAULT_ADDR}/v1/auth/approle/../../admins"
_assert_status "N09-03" "400"
_pass "N09-03 nested dot-segment rejected"

echo -n "[N09-04] unauth admin AppRole list via proxy → 401/403 … "
VAULT_TOKEN="" _vcurl -X GET "${VAULT_ADDR}/v1/auth/approle/role"
_assert_not_2xx "N09-04"
_pass "N09-04 unauth admin list refused (HTTP ${_HTTP_STATUS})"

echo -n "[N09-05] unauth admin AppRole create via proxy → 401/403 … "
VAULT_TOKEN="" _vcurl -X POST -H "Content-Type: application/json" \
  -d '{"token_ttl":3600,"secret_id_ttl":0}' \
  "${VAULT_ADDR}/v1/auth/approle/role/evil-${_RAND}"
_assert_not_2xx "N09-05"
_pass "N09-05 unauth admin create refused (HTTP ${_HTTP_STATUS})"

# =============================================================================
# Scenario 1 — AppRole secret_id num_uses race (single-use enforcement)
# =============================================================================
# A secret_id created with num_uses=1 must be consumable exactly once even
# under concurrent logins (BEGIN IMMEDIATE + rows_affected guard in SQLite).
_section "Scenario 1 — secret_id num_uses=1 concurrency"

if [[ -z "${AUTH_VERIFIER_URL}" ]]; then
  _fail "N01" "AUTH_VERIFIER_URL required for throwaway role creation"
fi

RACE_ROLE="race-${_RAND}"
_admin_login

echo -n "[N01-00] provisioning throwaway role '${RACE_ROLE}' with a num_uses=1 secret_id … "
_admin_api POST "/auth/approle/role/${RACE_ROLE}" \
  -d '{"token_ttl":3600,"token_policies":["default"],"secret_id_ttl":0}' >/dev/null
RACE_ROLE_ID=$(_admin_api GET "/auth/approle/role/${RACE_ROLE}/role-id" |
  python3 -c "import sys,json; print(json.load(sys.stdin)['data']['role_id'])")
RACE_SECRET_ID=$(_admin_api POST "/auth/approle/role/${RACE_ROLE}/secret-id" \
  -d '{"num_uses":1}' |
  python3 -c "import sys,json; print(json.load(sys.stdin)['data']['secret_id'])")
[[ -n "${RACE_ROLE_ID}" && -n "${RACE_SECRET_ID}" ]] ||
  _fail "N01-00" "failed to provision throwaway role/secret_id"
echo "ok"

echo -n "[N01-01] 10 concurrent logins on a num_uses=1 secret_id → exactly one 200 … "
_RACE_DIR="${_TMP}/race"
mkdir -p "${_RACE_DIR}"
for i in $(seq 1 10); do
  (
    args=(-s -o /dev/null -w "%{http_code}" --max-time 20)
    [[ -n "${VAULT_CACERT}" ]] && args+=(--cacert "${VAULT_CACERT}")
    curl "${args[@]}" -X POST -H "Content-Type: application/json" \
      -d "{\"role_id\":\"${RACE_ROLE_ID}\",\"secret_id\":\"${RACE_SECRET_ID}\"}" \
      "${VAULT_ADDR}/v1/auth/approle/login" >"${_RACE_DIR}/${i}.code" 2>/dev/null || true
  ) &
done
wait
SUCCESS_COUNT=$(grep -l '^200$' "${_RACE_DIR}"/*.code 2>/dev/null | wc -l | tr -d ' ')
if [[ "${SUCCESS_COUNT}" == "1" ]]; then
  _pass "N01-01 single-use enforced (exactly one 200 of 10)"
else
  echo "  observed status codes:" >&2
  cat "${_RACE_DIR}"/*.code | sort | uniq -c >&2
  _fail "N01-01" "expected exactly one 200, got ${SUCCESS_COUNT} — num_uses race is exploitable"
fi

# Cleanup throwaway role.
_admin_api DELETE "/auth/approle/role/${RACE_ROLE}" >/dev/null 2>&1 || true

# =============================================================================
# Scenario 5 — exportable bypass + sensitive-key KMIP export refusal
# =============================================================================
_section "Scenario 5 — exportable bypass + sensitive export denied"

_login "N05-login-a" "${SPIRE_ROLE_ID_A}" "${SPIRE_SECRET_ID_A}"

EXPKEY="exp-${_RAND}"
echo -n "[N05-01] create transit key with exportable:true → server forces exportable=false … "
_vcurl -X POST -H "Content-Type: application/json" \
  -d '{"type":"ecdsa-p256","exportable":true,"auto_rotate_period":0}' \
  "${VAULT_ADDR}/v1/transit/keys/${EXPKEY}"
_assert_status "N05-01" "200"
_vcurl -X GET "${VAULT_ADDR}/v1/transit/keys/${EXPKEY}"
_assert_status "N05-01" "200"
if echo "${_HTTP_BODY}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
sys.exit(0 if d['data']['exportable'] is False else 1)
"; then
  _pass "N05-01 exportable forced to false"
else
  _fail "N05-01" "exportable:true was honoured — key is exportable. Body: ${_HTTP_BODY:0:300}"
fi
# Cleanup transit key.
_vcurl -X POST -H "Content-Type: application/json" \
  -d '{"deletion_allowed":true}' "${VAULT_ADDR}/v1/transit/keys/${EXPKEY}/config"
_vcurl -X DELETE "${VAULT_ADDR}/v1/transit/keys/${EXPKEY}"

# 5(b): unwrapped export of a SENSITIVE key must be denied by the KMIP layer.
if [[ -n "${CKMS_BIN}" && -n "${CKMS_CONF}" ]]; then
  SENS_TAG="neg-sensitive-${_RAND}"
  echo -n "[N05-02] create sensitive AES key, unwrapped export → DENIED … "
  if ! SENS_ID=$("${CKMS_BIN}" --conf-path "${CKMS_CONF}" --accept-invalid-certs \
      sym keys create --algorithm aes --number-of-bits 256 --sensitive \
      --tag "${SENS_TAG}" 2>"${_TMP}/sens-create.err" |
      grep -oE '[0-9a-fA-F-]{36}' | head -1); then
    cat "${_TMP}/sens-create.err" >&2
    _fail "N05-02" "failed to create sensitive key"
  fi
  [[ -n "${SENS_ID}" ]] || _fail "N05-02" "could not parse sensitive key id"
  if "${CKMS_BIN}" --conf-path "${CKMS_CONF}" --accept-invalid-certs \
      sym keys export -k "${SENS_ID}" "${_TMP}/leak.json" >"${_TMP}/exp.out" 2>&1; then
    _fail "N05-02" "unwrapped export of a sensitive key SUCCEEDED (leak). Output: $(cat "${_TMP}/exp.out")"
  fi
  if grep -iqE 'sensitive|denied|not allowed|cannot' "${_TMP}/exp.out"; then
    _pass "N05-02 sensitive key unwrapped export denied"
  else
    # Still a refusal (non-zero exit), but flag the unexpected message for review.
    _pass "N05-02 sensitive export refused (message: $(head -1 "${_TMP}/exp.out"))"
  fi
else
  echo -e "  ${_YELLOW}SKIP${_NC}  N05-02 (CKMS_BIN/CKMS_CONF not provided)"
fi

# =============================================================================
# Scenario 4 — sign-intermediate input validation
# =============================================================================
_section "Scenario 4 — sign-intermediate malformed input"

_login "N04-login" "${SPIRE_ROLE_ID_A}" "${SPIRE_SECRET_ID_A}"

# A syntactically valid CSR with an EMPTY uri_sans must be rejected (SPIFFE ID
# is mandatory) — and a request with NO uri_sans field at all.
_CSR_KEY="${_TMP}/n04.key"; _CSR_PEM="${_TMP}/n04.csr"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "${_CSR_KEY}" -out "${_CSR_PEM}" -subj "/CN=neg/O=Test/C=FR" 2>/dev/null
_CSR_JSON=$(python3 -c "import json; print(json.dumps(open('${_CSR_PEM}').read()))")

echo -n "[N04-01] sign-intermediate with empty uri_sans → 400 … "
_vcurl -X POST -H "Content-Type: application/json" \
  -d "{\"csr\": ${_CSR_JSON}, \"common_name\": \"neg\", \"uri_sans\": \"\"}" \
  "${VAULT_ADDR}/v1/pki/root/sign-intermediate"
_assert_status "N04-01" "400"
_pass "N04-01 empty uri_sans rejected"

echo -n "[N04-02] sign-intermediate with missing uri_sans field → 400 … "
_vcurl -X POST -H "Content-Type: application/json" \
  -d "{\"csr\": ${_CSR_JSON}, \"common_name\": \"neg\"}" \
  "${VAULT_ADDR}/v1/pki/root/sign-intermediate"
_assert_status "N04-02" "400"
_pass "N04-02 missing uri_sans rejected"

echo -n "[N04-03] sign-intermediate with malformed (non-PEM) CSR → 4xx … "
_vcurl -X POST -H "Content-Type: application/json" \
  -d '{"csr":"-----BEGIN CERTIFICATE REQUEST-----\nnope\n-----END CERTIFICATE REQUEST-----","uri_sans":"spiffe://cosmian-test-a.local/x"}' \
  "${VAULT_ADDR}/v1/pki/root/sign-intermediate"
_assert_not_2xx "N04-03"
_pass "N04-03 malformed CSR rejected (HTTP ${_HTTP_STATUS})"

echo -n "[N04-04] sign-intermediate WITHOUT a token → refused (non-2xx) … "
VAULT_TOKEN="" _vcurl -X POST -H "Content-Type: application/json" \
  -d "{\"csr\": ${_CSR_JSON}, \"uri_sans\": \"spiffe://cosmian-test-a.local/x\"}" \
  "${VAULT_ADDR}/v1/pki/root/sign-intermediate"
_assert_not_2xx "N04-04"
_pass "N04-04 unauthenticated sign refused (HTTP ${_HTTP_STATUS})"

# =============================================================================
# Scenario 3 — token revocation vs. validation cache (NEG-003, documented)
# =============================================================================
# The KMS caches successful lookup-self results for vault_token_cache_ttl_secs
# (30s in this test) to avoid a round-trip per transit/PKI call. A token that is
# self-revoked at the auth-verifier therefore remains usable at the KMS until
# the cache entry expires. This is an ACCEPTED trade-off — the test documents
# the behaviour rather than treating either outcome as a failure.
_section "Scenario 3 — revoke-self then replay within cache TTL"

_login "N03-login" "${SPIRE_ROLE_ID_A}" "${SPIRE_SECRET_ID_A}"
N3KEY="neg3-${_RAND}"

echo -n "[N03-01] warm the token validation cache with a transit op → 200 … "
_vcurl -X POST -H "Content-Type: application/json" \
  -d '{"type":"ecdsa-p256","exportable":false,"auto_rotate_period":0}' \
  "${VAULT_ADDR}/v1/transit/keys/${N3KEY}"
_assert_status "N03-01" "200"
_pass "N03-01 cache warmed"

echo -n "[N03-02] revoke-self at the auth-verifier → 2xx … "
_vcurl -X POST "${VAULT_ADDR}/v1/auth/token/revoke-self"
if [[ "${_HTTP_STATUS}" =~ ^2[0-9][0-9]$ ]]; then
  _pass "N03-02 token revoked (HTTP ${_HTTP_STATUS})"
else
  _fail "N03-02" "revoke-self failed: HTTP ${_HTTP_STATUS}. Body: ${_HTTP_BODY:0:300}"
fi

echo -n "[N03-03] replay revoked token within cache TTL → documents 200 (cache) or 403 (immediate) … "
_vcurl -X GET "${VAULT_ADDR}/v1/transit/keys/${N3KEY}"
if [[ "${_HTTP_STATUS}" == "200" ]]; then
  _pass "N03-03 revoked token still accepted within ${VAULT_TOKEN_CACHE_TTL:-30}s cache window (documented NEG-003 trade-off)"
elif [[ "${_HTTP_STATUS}" =~ ^40[13]$ ]]; then
  _pass "N03-03 revoked token rejected immediately (HTTP ${_HTTP_STATUS} — stronger than documented)"
else
  _fail "N03-03" "unexpected status ${_HTTP_STATUS} on revoked-token replay. Body: ${_HTTP_BODY:0:300}"
fi

# Cleanup with a fresh token (the previous one is revoked).
_login "N03-cleanup" "${SPIRE_ROLE_ID_A}" "${SPIRE_SECRET_ID_A}"
_vcurl -X POST -H "Content-Type: application/json" \
  -d '{"deletion_allowed":true}' "${VAULT_ADDR}/v1/transit/keys/${N3KEY}/config"
_vcurl -X DELETE "${VAULT_ADDR}/v1/transit/keys/${N3KEY}"

# =============================================================================
# Scenario 8 — AppRole login fuzzing (never 5xx, always recoverable)
# =============================================================================
_section "Scenario 8 — AppRole login input fuzzing"

VAULT_TOKEN=""
_fuzz_login() {
  local name="$1"; shift
  _vcurl "$@" "${VAULT_ADDR}/v1/auth/approle/login"
  if [[ "${_HTTP_STATUS}" =~ ^5[0-9][0-9]$ ]]; then
    _fail "${name}" "malformed input caused a 5xx (${_HTTP_STATUS}) — should be a clean 4xx"
  fi
  _assert_4xx "${name}"
  _pass "${name} (HTTP ${_HTTP_STATUS})"
}

echo -n "[N08-01] empty body … ";        _fuzz_login "N08-01" -X POST -H "Content-Type: application/json" -d ''
echo -n "[N08-02] non-JSON garbage … ";  _fuzz_login "N08-02" -X POST -H "Content-Type: application/json" -d 'not-json{{{'
echo -n "[N08-03] wrong value types … "; _fuzz_login "N08-03" -X POST -H "Content-Type: application/json" -d '{"role_id":123,"secret_id":[1,2,3]}'

echo -n "[N08-04] deeply nested JSON … "
python3 -c "print('{\"role_id\":' + '['*2000 + ']'*2000 + '}')" >"${_TMP}/deep.json"
_fuzz_login "N08-04" -X POST -H "Content-Type: application/json" --data-binary "@${_TMP}/deep.json"

echo -n "[N08-05] 1 MB junk body … "
head -c 1048576 /dev/zero | tr '\0' 'A' >"${_TMP}/big.bin"
_fuzz_login "N08-05" -X POST -H "Content-Type: application/json" --data-binary "@${_TMP}/big.bin"

echo -n "[N08-06] wrong method (PUT) … "
_vcurl -X PUT -H "Content-Type: application/json" -d '{}' "${VAULT_ADDR}/v1/auth/approle/login"
_assert_not_2xx "N08-06"
_pass "N08-06 wrong method rejected (HTTP ${_HTTP_STATUS})"

echo -n "[N08-07] server still serves a valid login after the fuzz → 200 … "
_login "N08-07" "${SPIRE_ROLE_ID_A}" "${SPIRE_SECRET_ID_A}"
_pass "N08-07 auth path healthy post-fuzz"

# =============================================================================
# Scenario 7 — Kubernetes login rejection
# =============================================================================
_section "Scenario 7 — Kubernetes login rejection"

VAULT_TOKEN=""
echo -n "[N07-01] k8s login, unknown role + garbage JWT → 4xx … "
_vcurl -X POST -H "Content-Type: application/json" \
  -d "{\"role\":\"nonexistent-${_RAND}\",\"jwt\":\"garbage\"}" \
  "${VAULT_ADDR}/v1/auth/kubernetes/login"
_assert_4xx "N07-01"
_pass "N07-01 unknown role rejected (HTTP ${_HTTP_STATUS})"

echo -n "[N07-02] k8s login, alg:none forged JWT → 4xx … "
# alg:none token: header {"alg":"none"} . payload {"sub":"system:serviceaccount:x:y"} . (empty sig)
_ALGNONE="$(printf '{"alg":"none","typ":"JWT"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=').$(printf '{"sub":"system:serviceaccount:default:attacker"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')."
_vcurl -X POST -H "Content-Type: application/json" \
  -d "{\"role\":\"nonexistent-${_RAND}\",\"jwt\":\"${_ALGNONE}\"}" \
  "${VAULT_ADDR}/v1/auth/kubernetes/login"
_assert_4xx "N07-02"
_pass "N07-02 alg:none JWT rejected (HTTP ${_HTTP_STATUS})"

echo -n "[N07-03] k8s login, missing fields → 4xx (no 5xx) … "
_vcurl -X POST -H "Content-Type: application/json" -d '{}' \
  "${VAULT_ADDR}/v1/auth/kubernetes/login"
_assert_4xx "N07-03"
_pass "N07-03 missing fields rejected (HTTP ${_HTTP_STATUS})"

# =============================================================================
# Scenario 12 — Transit key lifecycle: delete leaves no orphan
# =============================================================================
_section "Scenario 12 — delete then recreate (no orphan)"

_login "N12-login" "${SPIRE_ROLE_ID_A}" "${SPIRE_SECRET_ID_A}"

LIFEKEY="life-${_RAND}"
echo -n "[N12-01] create '${LIFEKEY}' → 200 … "
_vcurl -X POST -H "Content-Type: application/json" \
  -d '{"type":"ecdsa-p256","exportable":false,"auto_rotate_period":0}' \
  "${VAULT_ADDR}/v1/transit/keys/${LIFEKEY}"
_assert_status "N12-01" "200"
_pass "N12-01 create"

echo -n "[N12-02] config {deletion_allowed:true} → 204 … "
_vcurl -X POST -H "Content-Type: application/json" \
  -d '{"deletion_allowed":true}' "${VAULT_ADDR}/v1/transit/keys/${LIFEKEY}/config"
_assert_status "N12-02" "204"
_pass "N12-02 config"

echo -n "[N12-03] DELETE → 204 … "
_vcurl -X DELETE "${VAULT_ADDR}/v1/transit/keys/${LIFEKEY}"
_assert_status "N12-03" "204"
_pass "N12-03 delete"

echo -n "[N12-04] GET after delete → 404 … "
_vcurl -X GET "${VAULT_ADDR}/v1/transit/keys/${LIFEKEY}"
_assert_status "N12-04" "404"
_pass "N12-04 gone"

echo -n "[N12-05] recreate SAME name → 200 (no orphan blocking) … "
_vcurl -X POST -H "Content-Type: application/json" \
  -d '{"type":"ecdsa-p256","exportable":false,"auto_rotate_period":0}' \
  "${VAULT_ADDR}/v1/transit/keys/${LIFEKEY}"
_assert_status "N12-05" "200"
_pass "N12-05 recreate succeeds"

echo -n "[N12-06] recreated key is usable (sign) → 200 … "
_DIGEST_B64=$(printf 'hello' | openssl dgst -sha256 -binary | openssl base64 -A)
_vcurl -X POST -H "Content-Type: application/json" \
  -d "{\"input\":\"${_DIGEST_B64}\",\"marshaling_algorithm\":\"asn1\",\"prehashed\":true}" \
  "${VAULT_ADDR}/v1/transit/sign/${LIFEKEY}/sha2-256"
_assert_status "N12-06" "200"
_pass "N12-06 recreated key signs"

# Cleanup.
_vcurl -X POST -H "Content-Type: application/json" \
  -d '{"deletion_allowed":true}' "${VAULT_ADDR}/v1/transit/keys/${LIFEKEY}/config"
_vcurl -X DELETE "${VAULT_ADDR}/v1/transit/keys/${LIFEKEY}"

# =============================================================================
# Summary
# =============================================================================
echo
echo -e "${_GREEN}=========================================================${_NC}"
echo -e "${_GREEN}  Negative scenarios passed: ${PASS_COUNT}   failed: ${FAIL_COUNT}${_NC}"
echo -e "${_GREEN}=========================================================${_NC}"
exit 0
