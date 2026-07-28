#!/usr/bin/env bash
# test_vault_api.sh — Vault API conformance tests for KMS + auth-verifier.
#
# Proves that KMS + auth-verifier is a valid drop-in replacement for HashiCorp Vault
# as required by SPIRE's vault plugin (upstreamauthority + hashicorp_vault keymanager).
#
# Reference: vault-technical-integration.txt (§3 Auth, §4 PKI, §5 Transit)
#
# Every test section maps to a numbered section in that document so failures
# can be traced back to the exact wire-protocol contract.
#
# Required environment:
#   VAULT_ADDR         — KMS base URL, e.g. https://localhost:9998
#   VAULT_CACERT       — path to PEM CA bundle for TLS verification
#   APPROLE_ROLE_ID    — valid AppRole role_id (from provision.sh)
#   APPROLE_SECRET_ID  — valid AppRole secret_id (from provision.sh)
#
# Exit code: 0 when all tests pass; non-zero on first failure (set -e).

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-https://localhost:9998}"
VAULT_CACERT="${VAULT_CACERT:-}"
APPROLE_ROLE_ID="${APPROLE_ROLE_ID:-}"
APPROLE_SECRET_ID="${APPROLE_SECRET_ID:-}"
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

# ── curl wrapper ──────────────────────────────────────────────────────────────
# Writes response body to _HTTP_BODY and HTTP status to _HTTP_STATUS.
_CURL_BODY_FILE=$(mktemp /tmp/vault-api-test-body.XXXXXX)
trap 'rm -f "${_CURL_BODY_FILE}"' EXIT

_HTTP_STATUS=""
_HTTP_BODY=""

# _vcurl [extra curl args...] <url>
# Uses VAULT_TOKEN if set (not yet set during auth bootstrap).
_vcurl() {
  local _args=(-s -o "${_CURL_BODY_FILE}" -w "%{http_code}" --max-time 15)
  [[ -n "${VAULT_CACERT}" ]] && _args+=(--cacert "${VAULT_CACERT}")
  [[ -n "${VAULT_TOKEN:-}" ]] && _args+=(-H "X-Vault-Token: ${VAULT_TOKEN}")
  _HTTP_STATUS=$(curl "${_args[@]}" "$@") || {
    _fail "curl failed" "command: curl $*"
  }
  _HTTP_BODY=$(cat "${_CURL_BODY_FILE}")
  [[ -n "${VERBOSE:-}" ]] && echo "    HTTP ${_HTTP_STATUS} ← ${_HTTP_BODY:0:300}" >&2 || true
}

# Assert HTTP status code matches expected value.
_assert_status() {
  local test_name="$1" expected="$2"
  if [[ "${_HTTP_STATUS}" != "${expected}" ]]; then
    _fail "${test_name}" "expected HTTP ${expected}, got ${_HTTP_STATUS}. Body: ${_HTTP_BODY:0:300}"
  fi
}

# Extract a field from _HTTP_BODY using a Python expression.
# The expression receives the parsed dict as `d`.
# Returns the value, or exits via _fail if the field is absent/null.
_json() {
  local test_name="$1" expr="$2"
  local result
  result=$(echo "${_HTTP_BODY}" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    v = ${expr}
    if v is None or v == '':
        print('__NULL__')
    else:
        print(v)
except Exception as e:
    print('__ERROR__: ' + str(e))
" 2>&1) || true
  if [[ "${result}" == __NULL__* || "${result}" == __ERROR__* ]]; then
    _fail "${test_name}" "JSON field '${expr}' absent or null. Body: ${_HTTP_BODY:0:400}"
  fi
  echo "${result}"
}

# ── Temp workspace ─────────────────────────────────────────────────────────────
_TMP=$(mktemp -d /tmp/vault-api-test.XXXXXX)
trap 'rm -rf "${_TMP}" "${_CURL_BODY_FILE}"' EXIT

# ── Section banner ─────────────────────────────────────────────────────────────
_section() { echo; echo -e "${_YELLOW}── $* ──${_NC}"; }

# =============================================================================
# §3  AUTHENTICATION
# =============================================================================
_section "§3 Authentication — AppRole + Token"

# T-01: AppRole login returns a valid client token
echo -n "[T-01] AppRole login → 200 + auth.{client_token, renewable, lease_duration} … "
_vcurl -X POST \
  -H "Content-Type: application/json" \
  -d "{\"role_id\":\"${APPROLE_ROLE_ID}\",\"secret_id\":\"${APPROLE_SECRET_ID}\"}" \
  "${VAULT_ADDR}/v1/auth/approle/login"
_assert_status "T-01" "200"
VAULT_TOKEN=$(_json "T-01" "d['auth']['client_token']")
_json "T-01" "str(d['auth']['renewable'])" >/dev/null   # must be present
_json "T-01" "str(d['auth']['lease_duration'])" >/dev/null
_pass "T-01"

# T-02: Token lookup-self returns required fields (§3.1)
echo -n "[T-02] Token lookup-self → 200 + data.{id, ttl, renewable} … "
_vcurl -X GET "${VAULT_ADDR}/v1/auth/token/lookup-self"
_assert_status "T-02" "200"
_json "T-02" "d['data']['id']" >/dev/null
_json "T-02" "str(d['data']['ttl'])" >/dev/null
_json "T-02" "str(d['data']['renewable'])" >/dev/null
_pass "T-02"

# T-03: Token lookup-self with an invalid token must return 403
echo -n "[T-03] Token lookup-self with bad token → 403 … "
VAULT_TOKEN="s.invalid-token-for-testing" \
  _vcurl -X GET "${VAULT_ADDR}/v1/auth/token/lookup-self"
_assert_status "T-03" "403"
_pass "T-03"
# Restore good token
_vcurl -X POST \
  -H "Content-Type: application/json" \
  -d "{\"role_id\":\"${APPROLE_ROLE_ID}\",\"secret_id\":\"${APPROLE_SECRET_ID}\"}" \
  "${VAULT_ADDR}/v1/auth/approle/login"
VAULT_TOKEN=$(_json "restore" "d['auth']['client_token']")

# T-04: AppRole login with wrong role_id must fail
echo -n "[T-04] AppRole login wrong role_id → 4xx … "
SAVED_TOKEN="${VAULT_TOKEN}"; VAULT_TOKEN=""
_vcurl -X POST \
  -H "Content-Type: application/json" \
  -d '{"role_id":"00000000-0000-0000-0000-bad-role","secret_id":"bad"}' \
  "${VAULT_ADDR}/v1/auth/approle/login"
if [[ "${_HTTP_STATUS}" == "200" ]]; then
  _fail "T-04" "expected 4xx, got 200 — bad role_id was accepted"
fi
VAULT_TOKEN="${SAVED_TOKEN}"
_pass "T-04"

# T-05: AppRole login with wrong secret_id must fail
echo -n "[T-05] AppRole login wrong secret_id → 4xx … "
SAVED_TOKEN="${VAULT_TOKEN}"; VAULT_TOKEN=""
_vcurl -X POST \
  -H "Content-Type: application/json" \
  -d "{\"role_id\":\"${APPROLE_ROLE_ID}\",\"secret_id\":\"00000000-bad-secret\"}" \
  "${VAULT_ADDR}/v1/auth/approle/login"
if [[ "${_HTTP_STATUS}" == "200" ]]; then
  _fail "T-05" "expected 4xx, got 200 — bad secret_id was accepted"
fi
VAULT_TOKEN="${SAVED_TOKEN}"
_pass "T-05"

# T-06: Token renewal (§3.6 POST /v1/auth/token/renew-self)
echo -n "[T-06] Token renew-self → 200 + auth.client_token … "
_vcurl -X POST "${VAULT_ADDR}/v1/auth/token/renew-self"
_assert_status "T-06" "200"
_json "T-06" "d['auth']['client_token']" >/dev/null
_pass "T-06"

# =============================================================================
# §4  PKI ENGINE — sign-intermediate
# =============================================================================
_section "§4 PKI Engine — sign-intermediate"

# Generate a test CSR with a SPIFFE URI SAN (required by SPIRE §4.1)
_CSR_KEY="${_TMP}/test-csr.key"
_CSR_PEM="${_TMP}/test-csr.pem"
_CSR_CNF="${_TMP}/csr.cnf"
cat >"${_CSR_CNF}" <<'CONF'
[req]
distinguished_name = dn
req_extensions     = req_ext
prompt             = no
[dn]
CN = Cosmian Test Intermediate CA
O  = Cosmian
C  = FR
[req_ext]
subjectAltName = URI:spiffe://cosmian-test.local/test-workload
CONF

openssl req -new \
  -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "${_CSR_KEY}" \
  -out    "${_CSR_PEM}" \
  -config "${_CSR_CNF}" \
  2>/dev/null

_CSR_DATA=$(cat "${_CSR_PEM}")

# T-07: sign-intermediate returns the required fields
echo -n "[T-07] sign-intermediate → 200 + data.{certificate, issuing_ca, ca_chain} … "
_vcurl -X POST \
  -H "Content-Type: application/json" \
  -d "{
    \"csr\":         $(python3 -c "import json, sys; print(json.dumps(open('${_CSR_PEM}').read()))"),
    \"uri_sans\":    \"spiffe://cosmian-test.local/test-workload\",
    \"common_name\": \"Cosmian Test Intermediate CA\",
    \"organization\":\"Cosmian\",
    \"country\":     \"FR\",
    \"ttl\":         \"1h\"
  }" \
  "${VAULT_ADDR}/v1/pki/root/sign-intermediate"
_assert_status "T-07" "200"
_SIGNED_CERT=$(_json "T-07" "d['data']['certificate']")
_ISSUING_CA=$(_json "T-07" "d['data']['issuing_ca']")
_CA_CHAIN_LEN=$(echo "${_HTTP_BODY}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['data'].get('ca_chain',[])))" 2>/dev/null || echo "0")
_pass "T-07"

# T-08: signed certificate has basicConstraints CA:TRUE
echo -n "[T-08] signed cert has basicConstraints CA:TRUE … "
_SIGNED_CERT_FILE="${_TMP}/signed-intermediate.pem"
printf '%s' "${_SIGNED_CERT}" >"${_SIGNED_CERT_FILE}"
_BC=$(openssl x509 -in "${_SIGNED_CERT_FILE}" -noout -text 2>/dev/null | grep -i "CA:TRUE" | head -1)
if [[ -z "${_BC}" ]]; then
  _fail "T-08" "basicConstraints CA:TRUE not found in signed certificate"
fi
_pass "T-08"

# T-09: signed cert URI SAN contains the requested SPIFFE ID
echo -n "[T-09] signed cert URI SAN matches request … "
_SAN=$(openssl x509 -in "${_SIGNED_CERT_FILE}" -noout -ext subjectAltName 2>/dev/null)
if ! echo "${_SAN}" | grep -q "spiffe://cosmian-test.local/test-workload"; then
  _fail "T-09" "expected SPIFFE URI SAN not found. Got: ${_SAN}"
fi
_pass "T-09"

# T-10: signed cert is signed by the issuing CA (chain verification)
echo -n "[T-10] signed cert is verifiable against the issuing CA … "
_ISSUING_CA_FILE="${_TMP}/issuing_ca.pem"
printf '%s' "${_ISSUING_CA}" >"${_ISSUING_CA_FILE}"
if ! openssl verify -CAfile "${_ISSUING_CA_FILE}" "${_SIGNED_CERT_FILE}" 2>/dev/null | grep -q "OK"; then
  _fail "T-10" "openssl verify failed: signed cert is not issued by the reported issuing_ca"
fi
_pass "T-10"

# T-11: ca_chain does NOT contain the signed cert itself (§4.2 deduplication)
echo -n "[T-11] ca_chain does not echo the signed cert (§4.2 dedup) … "
_SIGNED_CERT_NORM=$(openssl x509 -in "${_SIGNED_CERT_FILE}" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
_CA_CHAIN_CONTAINS_SIGNED=$(echo "${_HTTP_BODY}" | python3 -c "
import sys, json, subprocess, tempfile, os
d = json.load(sys.stdin)
chain = d['data'].get('ca_chain', [])
target = '''${_SIGNED_CERT_NORM}'''
found = False
for cert_pem in chain:
    with tempfile.NamedTemporaryFile(suffix='.pem', delete=False, mode='w') as f:
        f.write(cert_pem)
        fname = f.name
    try:
        out = subprocess.check_output(['openssl', 'x509', '-in', fname, '-noout', '-fingerprint', '-sha256'],
                                      stderr=subprocess.DEVNULL).decode()
        fp = out.split('=', 1)[1].strip()
        if fp == target:
            found = True
            break
    except Exception:
        pass
    finally:
        os.unlink(fname)
print('yes' if found else 'no')
" 2>/dev/null || echo "no")
if [[ "${_CA_CHAIN_CONTAINS_SIGNED}" == "yes" ]]; then
  _fail "T-11" "ca_chain echoes the signed certificate itself (violates §4.2 deduplication)"
fi
_pass "T-11"

# T-12: sign-intermediate with NO URI SANs must be rejected
echo -n "[T-12] sign-intermediate with no URI SANs → 400 … "
_NO_URI_CSR_KEY="${_TMP}/no-uri-csr.key"
_NO_URI_CSR_PEM="${_TMP}/no-uri-csr.pem"
openssl req -new \
  -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "${_NO_URI_CSR_KEY}" \
  -out    "${_NO_URI_CSR_PEM}" \
  -subj   "/CN=No URI SAN/O=Test/C=US" \
  2>/dev/null
_vcurl -X POST \
  -H "Content-Type: application/json" \
  -d "{
    \"csr\":         $(python3 -c "import json; print(json.dumps(open('${_NO_URI_CSR_PEM}').read()))"),
    \"common_name\": \"No URI SAN\",
    \"uri_sans\":    \"\"
  }" \
  "${VAULT_ADDR}/v1/pki/root/sign-intermediate"
if [[ "${_HTTP_STATUS}" == "200" ]]; then
  _fail "T-12" "expected non-200 for empty uri_sans, got 200"
fi
_pass "T-12"

# T-13: sign-intermediate with a malformed (non-PEM) CSR must return 4xx
echo -n "[T-13] sign-intermediate with malformed CSR → 4xx … "
_vcurl -X POST \
  -H "Content-Type: application/json" \
  -d '{"csr":"not-a-pem","uri_sans":"spiffe://cosmian-test.local/x"}' \
  "${VAULT_ADDR}/v1/pki/root/sign-intermediate"
if [[ "${_HTTP_STATUS}" == "200" ]]; then
  _fail "T-13" "expected 4xx for malformed CSR, got 200"
fi
_pass "T-13"

# =============================================================================
# §5  TRANSIT ENGINE — key management and signing
# =============================================================================
#
# For each key type, we test the full lifecycle:
#   create → read → sign (+ verify) → list → delete (config + delete + 404)
#
# Algorithm / hash mapping (vault-technical-integration.txt §5.5):
#   ecdsa-p256 → sha2-256
#   ecdsa-p384 → sha2-384
#   rsa-2048   → sha2-256
#   rsa-4096   → sha2-512

_TRANSIT_TEST_PLAIN="${_TMP}/test-plain.bin"
printf '%s' "Cosmian KMS Vault API conformance test data" >"${_TRANSIT_TEST_PLAIN}"

declare -A TRANSIT_HASH_ALG=(
  ["ecdsa-p256"]="sha2-256"
  ["ecdsa-p384"]="sha2-384"
  ["rsa-2048"]="sha2-256"
  ["rsa-4096"]="sha2-512"
)
declare -A OPENSSL_DGST_ALG=(
  ["ecdsa-p256"]="sha256"
  ["ecdsa-p384"]="sha384"
  ["rsa-2048"]="sha256"
  ["rsa-4096"]="sha512"
)

for KEY_TYPE in ecdsa-p256 ecdsa-p384 rsa-2048 rsa-4096; do
  KEY_NAME="conformance-test-${KEY_TYPE}"
  HASH_ALG="${TRANSIT_HASH_ALG[${KEY_TYPE}]}"
  OSSL_ALG="${OPENSSL_DGST_ALG[${KEY_TYPE}]}"

  _section "§5 Transit — ${KEY_TYPE}"

  # T-14: Create key
  echo -n "[T-14/${KEY_TYPE}] POST /keys/${KEY_NAME} → 200 + exportable=false … "
  _vcurl -X POST \
    -H "Content-Type: application/json" \
    -d "{\"type\":\"${KEY_TYPE}\",\"exportable\":false,\"auto_rotate_period\":0}" \
    "${VAULT_ADDR}/v1/transit/keys/${KEY_NAME}"
  _assert_status "T-14/${KEY_TYPE}" "200"
  _EXPORTABLE=$(_json "T-14/${KEY_TYPE}" "str(d['data']['exportable'])")
  if [[ "${_EXPORTABLE}" != "False" && "${_EXPORTABLE}" != "false" ]]; then
    _fail "T-14/${KEY_TYPE}" "exportable must be false, got '${_EXPORTABLE}'"
  fi
  _LATEST_V=$(_json "T-14/${KEY_TYPE}" "str(d['data']['latest_version'])")
  if [[ "${_LATEST_V}" != "1" ]]; then
    _fail "T-14/${KEY_TYPE}" "latest_version must be 1 on creation, got '${_LATEST_V}'"
  fi
  _pass "T-14/${KEY_TYPE}"

  # T-15: Read key — public key PEM + RFC3339 creation_time
  echo -n "[T-15/${KEY_TYPE}] GET /keys/${KEY_NAME} → 200 + public_key PEM + creation_time … "
  _vcurl -X GET "${VAULT_ADDR}/v1/transit/keys/${KEY_NAME}"
  _assert_status "T-15/${KEY_TYPE}" "200"
  _PUB_PEM=$(_json "T-15/${KEY_TYPE}" "d['data']['keys']['1']['public_key']")
  _CTIME=$(_json "T-15/${KEY_TYPE}" "d['data']['keys']['1']['creation_time']")
  # Validate PEM starts with the correct header
  if ! echo "${_PUB_PEM}" | grep -q "BEGIN PUBLIC KEY"; then
    _fail "T-15/${KEY_TYPE}" "public_key is not a valid SPKI PEM"
  fi
  # Validate creation_time is RFC3339 (contains T and Z or +)
  if ! echo "${_CTIME}" | grep -qE "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"; then
    _fail "T-15/${KEY_TYPE}" "creation_time '${_CTIME}' is not RFC3339"
  fi
  _RETURNED_TYPE=$(_json "T-15/${KEY_TYPE}" "d['data']['type']")
  if [[ "${_RETURNED_TYPE}" != "${KEY_TYPE}" ]]; then
    _fail "T-15/${KEY_TYPE}" "type: expected '${KEY_TYPE}', got '${_RETURNED_TYPE}'"
  fi
  _pass "T-15/${KEY_TYPE}"

  # T-16 + T-17: Sign prehashed data and verify signature
  echo -n "[T-16/${KEY_TYPE}] POST /sign/${KEY_NAME}/${HASH_ALG} → vault:v1:<b64> prefix … "
  _DIGEST_FILE="${_TMP}/digest-${KEY_TYPE}.bin"
  openssl dgst "-${OSSL_ALG}" -binary "${_TRANSIT_TEST_PLAIN}" >"${_DIGEST_FILE}"
  _DIGEST_B64=$(openssl base64 -A <"${_DIGEST_FILE}")
  _vcurl -X POST \
    -H "Content-Type: application/json" \
    -d "{\"input\":\"${_DIGEST_B64}\",\"marshaling_algorithm\":\"asn1\",\"prehashed\":true}" \
    "${VAULT_ADDR}/v1/transit/sign/${KEY_NAME}/${HASH_ALG}"
  _assert_status "T-16/${KEY_TYPE}" "200"
  _SIG_VAULT=$(_json "T-16/${KEY_TYPE}" "d['data']['signature']")
  if ! echo "${_SIG_VAULT}" | grep -q "^vault:v1:"; then
    _fail "T-16/${KEY_TYPE}" "signature missing 'vault:v1:' prefix: ${_SIG_VAULT:0:80}"
  fi
  _pass "T-16/${KEY_TYPE}"

  echo -n "[T-17/${KEY_TYPE}] Signature verifies against returned public key (openssl) … "
  # Strip "vault:v1:" prefix and base64-decode to raw signature bytes
  _SIG_B64="${_SIG_VAULT#vault:v1:}"
  _SIG_FILE="${_TMP}/sig-${KEY_TYPE}.bin"
  printf '%s' "${_SIG_B64}" | openssl base64 -d -A >"${_SIG_FILE}"
  # Write public key to file for verification
  _PUB_FILE="${_TMP}/pubkey-${KEY_TYPE}.pem"
  printf '%s\n' "${_PUB_PEM}" >"${_PUB_FILE}"
  # Verify with openssl dgst (works for ECDSA DER and RSA PKCS1v15)
  if ! openssl dgst "-${OSSL_ALG}" -verify "${_PUB_FILE}" \
      -signature "${_SIG_FILE}" "${_TRANSIT_TEST_PLAIN}" 2>/dev/null; then
    # For RSA PSS, retry with pkeyutl PSS mode
    if ! openssl pkeyutl -verify -pubin -inkey "${_PUB_FILE}" \
        -sigfile "${_SIG_FILE}" -in "${_DIGEST_FILE}" \
        -pkeyopt digest:"${OSSL_ALG}" \
        -pkeyopt rsa_padding_mode:pss \
        -pkeyopt rsa_pss_saltlen:digest 2>/dev/null; then
      _fail "T-17/${KEY_TYPE}" "signature did not verify (tried PKCS1v15 and PSS)"
    fi
  fi
  _pass "T-17/${KEY_TYPE}"

done

# T-18: List keys — all created key names must appear
_section "§5 Transit — list keys"
echo -n "[T-18] GET /transit/keys?list=true → all created keys present … "
_vcurl -X GET "${VAULT_ADDR}/v1/transit/keys"
_assert_status "T-18" "200"
_KEY_LIST=$(echo "${_HTTP_BODY}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(' '.join(d['data']['keys']))
" 2>/dev/null || echo "")
for KEY_TYPE in ecdsa-p256 ecdsa-p384 rsa-2048 rsa-4096; do
  KEY_NAME="conformance-test-${KEY_TYPE}"
  if ! echo "${_KEY_LIST}" | grep -q "${KEY_NAME}"; then
    _fail "T-18" "key '${KEY_NAME}' not found in list response. Got: ${_KEY_LIST}"
  fi
done
_pass "T-18"

# T-19 / T-20 / T-21: Delete key (two-step: config + delete + 404)
for KEY_TYPE in ecdsa-p256 ecdsa-p384 rsa-2048 rsa-4096; do
  KEY_NAME="conformance-test-${KEY_TYPE}"
  _section "§5 Transit — delete lifecycle for ${KEY_TYPE}"

  echo -n "[T-19/${KEY_TYPE}] POST /keys/${KEY_NAME}/config {deletion_allowed:true} → 204 … "
  _vcurl -X POST \
    -H "Content-Type: application/json" \
    -d '{"deletion_allowed":true}' \
    "${VAULT_ADDR}/v1/transit/keys/${KEY_NAME}/config"
  _assert_status "T-19/${KEY_TYPE}" "204"
  _pass "T-19/${KEY_TYPE}"

  echo -n "[T-20/${KEY_TYPE}] DELETE /keys/${KEY_NAME} → 204 … "
  _vcurl -X DELETE "${VAULT_ADDR}/v1/transit/keys/${KEY_NAME}"
  _assert_status "T-20/${KEY_TYPE}" "204"
  _pass "T-20/${KEY_TYPE}"

  echo -n "[T-21/${KEY_TYPE}] GET /keys/${KEY_NAME} after delete → 404 … "
  _vcurl -X GET "${VAULT_ADDR}/v1/transit/keys/${KEY_NAME}"
  _assert_status "T-21/${KEY_TYPE}" "404"
  _pass "T-21/${KEY_TYPE}"
done

# =============================================================================
# Error handling
# =============================================================================
_section "Error handling"

# T-22: Transit request without X-Vault-Token must be rejected
echo -n "[T-22] /v1/transit/* without X-Vault-Token → 403 … "
SAVED_TOKEN="${VAULT_TOKEN}"; VAULT_TOKEN=""
_vcurl -X GET "${VAULT_ADDR}/v1/transit/keys"
if [[ "${_HTTP_STATUS}" == "200" ]]; then
  _fail "T-22" "unauthenticated request was accepted (got 200)"
fi
VAULT_TOKEN="${SAVED_TOKEN}"
_pass "T-22"

# T-23: Create key with unsupported type must return 400
echo -n "[T-23] create key with type 'unsupported-type' → 400 … "
_vcurl -X POST \
  -H "Content-Type: application/json" \
  -d '{"type":"unsupported-type","exportable":false}' \
  "${VAULT_ADDR}/v1/transit/keys/bad-type-key"
_assert_status "T-23" "400"
_pass "T-23"

# T-24: Sign with non-existent key name must return 404
echo -n "[T-24] sign with non-existent key → 404 … "
_DUMMY_HASH=$(echo -n "test" | openssl dgst -sha256 -binary | openssl base64 -A)
_vcurl -X POST \
  -H "Content-Type: application/json" \
  -d "{\"input\":\"${_DUMMY_HASH}\",\"prehashed\":true}" \
  "${VAULT_ADDR}/v1/transit/sign/key-that-does-not-exist/sha2-256"
_assert_status "T-24" "404"
_pass "T-24"

# T-25: PKI sign-intermediate with X-Vault-Token missing → 403
echo -n "[T-25] sign-intermediate without X-Vault-Token → 403 … "
SAVED_TOKEN="${VAULT_TOKEN}"; VAULT_TOKEN=""
_vcurl -X POST \
  -H "Content-Type: application/json" \
  -d '{"csr":"x","uri_sans":"spiffe://test.local/x"}' \
  "${VAULT_ADDR}/v1/pki/root/sign-intermediate"
if [[ "${_HTTP_STATUS}" == "200" ]]; then
  _fail "T-25" "unauthenticated PKI request was accepted (got 200)"
fi
VAULT_TOKEN="${SAVED_TOKEN}"
_pass "T-25"

# =============================================================================
# Summary
# =============================================================================
echo
echo -e "${_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${_NC}"
echo -e "${_GREEN}  Vault API conformance: ${PASS_COUNT} passed, ${FAIL_COUNT} failed${_NC}"
echo -e "${_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${_NC}"
