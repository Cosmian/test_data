#!/usr/bin/env bash
# provision_opa_users.sh
#
# Provision the Cosmian Authentication Verifier with users required for KMS OPA
# RBAC testing.  Works for both automated CI runs and the manual `opa.toml` setup.
#
# Creates two realms and 8 users covering every role in kms.rego plus two
# edge-case identities (no roles, unknown role):
#
#   Realm ${REALM_A}  (primary, default: kms-opa-test):
#     kms-opa-super-admin    SuperAdmin      ${PASSWORD}
#     kms-opa-officer        CryptoOfficer   ${PASSWORD}
#     kms-opa-user           User            ${PASSWORD}
#     kms-opa-auditor        Auditor         ${PASSWORD}
#     kms-opa-no-roles       (no roles)      ${PASSWORD}   — OPA deny edge-case
#     kms-opa-unknown-role   Hacker          ${PASSWORD}   — OPA deny edge-case
#
#   Realm ${REALM_B}  (cross-domain, default: kms-opa-other):
#     kms-opa-domain-admin-other   DomainAdmin    ${PASSWORD}
#     kms-opa-other-officer        CryptoOfficer  ${PASSWORD}
#
# Outputs shell export statements to STDOUT (suitable for `eval "$(…)"`):
#
#   export KMS_TEST_OPA_SUPER_ADMIN_JWT="…"
#   export KMS_TEST_OPA_OFFICER_JWT="…"
#   export KMS_TEST_OPA_USER_ROLE_JWT="…"
#   export KMS_TEST_OPA_AUDITOR_JWT="…"
#   export KMS_TEST_OPA_NO_ROLES_JWT="…"
#   export KMS_TEST_OPA_UNKNOWN_ROLE_JWT="…"
#   export KMS_TEST_OPA_DOMAIN_ADMIN_OTHER_JWT="…"
#   export KMS_TEST_OPA_OTHER_DOMAIN_JWT="…"
#
# Human-readable status messages are written to STDERR so they do not
# interfere with `eval "$(…)"`.  Every value printed on STDOUT is checked to be a
# JWT (three base64url segments) first, so the output can never carry shell
# metacharacters into the caller's `eval`.  TLS verification is always on: the
# server certificate must chain to ${CA_CERT}.
#
# ── Usage ─────────────────────────────────────────────────────────────────────
#
#   CI (mise test:opa_rbac) — default realms, evaluate exports:
#     eval "$(AUTH_URL=… CA_CERT=… bash provision_opa_users.sh)"
#
#   Manual (opa.toml setup) — custom realms, read the summary table:
#     REALM_A=acme.com REALM_B=partner.acme.com \
#       bash ../test_data/configs/auth_verifier/provision_opa_users.sh
#     # Then login in the KMS Web UI with:
#     #   realm: acme.com   username: kms-opa-officer   password: change_me
#
# ── Environment ───────────────────────────────────────────────────────────────
#
#   AUTH_URL   — auth verifier HTTPS URL          (default: https://127.0.0.1:8443)
#   REALM_A    — primary realm ID                 (default: kms-opa-test)
#   REALM_B    — secondary realm ID               (default: kms-opa-other)
#   PASSWORD   — password for all provisioned users (default: change_me)
#   ADMIN_PASSWORD — password of the built-in `admin` super-admin (default: change_me)
#   CA_CERT    — path to the server CA certificate
#                (default: authentication/server/src/tests/certificates/ec/auth.ca.pem
#                 relative to the repo root; override via env when running from an
#                 arbitrary directory)
#   REPO_ROOT  — repository root path              (default: auto-detected)
#
# Requires `curl` and `jq`. The request bodies follow the auth verifier 0.5.0 API
# (`password_input`; the realm ID is emitted as the `as_rid` JWT claim).

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
AUTH_URL="${AUTH_URL:-https://127.0.0.1:8443}"
REALM_A="${REALM_A:-kms-opa-test}"
REALM_B="${REALM_B:-kms-opa-other}"
# Obviously fake fixture credentials for a throw-away test auth verifier.
PASSWORD="${PASSWORD:-change_me}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-change_me}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../../../.." && pwd)}"
CA_CERT="${CA_CERT:-${REPO_ROOT}/authentication/server/src/tests/certificates/ec/auth.ca.pem}"

COOKIE_JAR=$(mktemp /tmp/opa-admin-XXXXXX.txt)
trap 'rm -f "${COOKIE_JAR}"' EXIT

# ── Helpers ───────────────────────────────────────────────────────────────────

# All status messages go to STDERR so STDOUT stays clean for `eval "$(…)"`.
log()  { echo "$*" >&2; }
warn() { echo "  ⚠  $*" >&2; }
fail() { echo "  ✗  $*" >&2; exit 1; }

command -v jq >/dev/null || fail "jq is required to build the JSON request bodies"

# Call the admin API with the super-admin session cookie. The HTTP status must match the
# regular expression in $4, otherwise the script aborts with the server's message: a changed
# API must never be swallowed silently.
admin_call() {
    local method="$1" path="$2" body="$3" accepted="$4"
    local response status
    local args=(-s --cacert "${CA_CERT}" -b "${COOKIE_JAR}" -c "${COOKIE_JAR}"
        -w $'\n%{http_code}' -X "${method}")
    if [[ -n "${body}" ]]; then
        args+=(-H "Content-Type: application/json" -d "${body}")
    fi
    response=$(curl "${args[@]}" "${AUTH_URL}${path}") \
        || fail "${method} ${path}: the request could not be sent to ${AUTH_URL}"
    status="${response##*$'\n'}"
    if [[ ! "${status}" =~ ${accepted} ]]; then
        local message="${response%$'\n'*}"
        fail "${method} ${path} → HTTP ${status}: ${message:0:200}"
    fi
}

# Login and return the JWT from the `_ea_` cookie via STDOUT.
user_login_jwt() {
    local realm="$1" username="$2" password="$3"
    local cookie_output
    cookie_output=$(mktemp /tmp/opa-login-XXXXXX.txt)
    # shellcheck disable=SC2064
    trap "rm -f '${cookie_output}'" RETURN

    local http_status
    http_status=$(curl -s --cacert "${CA_CERT}" \
        -c "${cookie_output}" \
        -o /dev/null -w "%{http_code}" \
        -u "${username}:${password}" \
        -H "Content-Type: application/json" \
        -X POST "${AUTH_URL}/login?realm=${realm}" \
        -d '{"public_key_pem":null,"totp_code":null}')

    if [[ "${http_status}" != 2* ]]; then
        fail "login '${username}' in realm '${realm}' → HTTP ${http_status}"
    fi

    local jwt
    jwt=$(awk '/\t_ea_\t/{print $NF}' "${cookie_output}" | head -1)
    if [[ -z "${jwt}" ]]; then
        fail "no '_ea_' cookie in login response for '${username}' in '${realm}'"
    fi
    # The value ends up inside the caller's `eval "$(…)"`: refuse anything that is
    # not exactly three base64url segments rather than trusting the server's cookie.
    if [[ ! "${jwt}" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
        fail "'_ea_' cookie for '${username}' in '${realm}' is not a JWT"
    fi
    printf '%s' "${jwt}"
}

# ── Step 1: super-admin login ─────────────────────────────────────────────────
log ""
log "Auth Verifier: ${AUTH_URL}"
log "Realms: ${REALM_A} (primary)  ${REALM_B} (cross-domain)"
log ""

http_status=$(curl -s --cacert "${CA_CERT}" \
    -c "${COOKIE_JAR}" -b "${COOKIE_JAR}" \
    -o /dev/null -w "%{http_code}" \
    -u "admin:${ADMIN_PASSWORD}" \
    -H "Content-Type: application/json" \
    -X POST "${AUTH_URL}/login?realm=_" \
    -d '{"public_key_pem":null,"totp_code":null}')
if [[ "${http_status}" != 2* ]]; then
    fail "super-admin login → HTTP ${http_status}. Is the auth verifier running at ${AUTH_URL}?"
fi
log "  ✓ super-admin authenticated"

# ── Step 2: Create realms (idempotent: 409 means the realm already exists) ──
for realm in "${REALM_A}" "${REALM_B}"; do
    body=$(jq -nc --arg id "${realm}" \
        '{id: $id, auth_params: {username_password_params: {allow_expired_passwords: false}},
          session_max_age_seconds: 3600, session_max_stale_age_seconds: 7200}')
    admin_call POST "/admins/realms" "${body}" '^(201|409)$'
    log "  ✓ realm '${realm}' ready"
done

# No realm admin is created on purpose: since auth verifier 0.5.0 an admin scoped to a realm
# owns it exclusively, and the built-in super admin then gets HTTP 403 when it manages that
# realm's users (which would also break re-running this script).

# ── Step 3: Create users (delete-then-create for idempotency) ────────────────
#
# Format: "username:realm:roles_json_array"; every user gets ${PASSWORD}.
# The realm ID is the user's domain: the auth verifier emits it as the `as_rid` JWT claim.
# Empty roles array ("[]") → OPA deny edge-case.
# Unknown role ("Hacker") → OPA deny edge-case (no matching rule in kms.rego).
USERS=(
    "kms-opa-super-admin:${REALM_A}:[\"SuperAdmin\"]"
    "kms-opa-officer:${REALM_A}:[\"CryptoOfficer\"]"
    "kms-opa-user:${REALM_A}:[\"User\"]"
    "kms-opa-auditor:${REALM_A}:[\"Auditor\"]"
    "kms-opa-no-roles:${REALM_A}:[]"
    "kms-opa-unknown-role:${REALM_A}:[\"Hacker\"]"
    "kms-opa-domain-admin-other:${REALM_B}:[\"DomainAdmin\"]"
    "kms-opa-other-officer:${REALM_B}:[\"CryptoOfficer\"]"
)

for entry in "${USERS[@]}"; do
    IFS=: read -r username realm roles <<< "${entry}"
    admin_call DELETE "/realms/${realm}/userpass/${username}" "" '^204$'
    body=$(jq -nc --arg realm "${realm}" --arg username "${username}" \
        --arg password "${PASSWORD}" --argjson roles "${roles}" \
        '{realm: $realm, username: $username, password_input: {plaintext: $password},
          change_password: false, roles: $roles}')
    admin_call POST "/realms/${realm}/userpass" "${body}" '^201$'
    log "  ✓ ${username} (${roles}) → realm '${realm}'"
done

# ── Step 4: Login as each user, capture JWTs ─────────────────────────────────
log ""
log "Obtaining JWTs…"

SUPER_ADMIN_JWT=$(user_login_jwt "${REALM_A}" "kms-opa-super-admin"       "${PASSWORD}")
OFFICER_JWT=$(user_login_jwt    "${REALM_A}" "kms-opa-officer"            "${PASSWORD}")
USER_JWT=$(user_login_jwt       "${REALM_A}" "kms-opa-user"               "${PASSWORD}")
AUDITOR_JWT=$(user_login_jwt    "${REALM_A}" "kms-opa-auditor"            "${PASSWORD}")
NO_ROLES_JWT=$(user_login_jwt   "${REALM_A}" "kms-opa-no-roles"           "${PASSWORD}")
UNKNOWN_JWT=$(user_login_jwt    "${REALM_A}" "kms-opa-unknown-role"       "${PASSWORD}")
DOM_ADMIN_OTHER_JWT=$(user_login_jwt "${REALM_B}" "kms-opa-domain-admin-other" "${PASSWORD}")
OTHER_OFFICER_JWT=$(user_login_jwt   "${REALM_B}" "kms-opa-other-officer"       "${PASSWORD}")

log "  ✓ all JWTs obtained"

# ── Step 5: Summary table (to STDERR) ────────────────────────────────────────
log ""
log "  Realm           Username                      Password      Role"
log "  ──────────────  ────────────────────────────  ────────────  ─────────────────────"
log "  ${REALM_A}  kms-opa-super-admin          ${PASSWORD}  SuperAdmin"
log "  ${REALM_A}  kms-opa-officer              ${PASSWORD}  CryptoOfficer"
log "  ${REALM_A}  kms-opa-user                 ${PASSWORD}  User"
log "  ${REALM_A}  kms-opa-auditor              ${PASSWORD}  Auditor"
log "  ${REALM_A}  kms-opa-no-roles             ${PASSWORD}  (none)"
log "  ${REALM_A}  kms-opa-unknown-role         ${PASSWORD}  Hacker (invalid)"
log "  ${REALM_B}  kms-opa-domain-admin-other   ${PASSWORD}  DomainAdmin"
log "  ${REALM_B}  kms-opa-other-officer        ${PASSWORD}  CryptoOfficer"
log ""

# ── STDOUT: shell exports (caller does `eval "$(this script)"`) ──────────────
printf "export KMS_TEST_OPA_SUPER_ADMIN_JWT='%s'\n"        "${SUPER_ADMIN_JWT}"
printf "export KMS_TEST_OPA_OFFICER_JWT='%s'\n"            "${OFFICER_JWT}"
printf "export KMS_TEST_OPA_USER_ROLE_JWT='%s'\n"          "${USER_JWT}"
printf "export KMS_TEST_OPA_AUDITOR_JWT='%s'\n"            "${AUDITOR_JWT}"
printf "export KMS_TEST_OPA_NO_ROLES_JWT='%s'\n"           "${NO_ROLES_JWT}"
printf "export KMS_TEST_OPA_UNKNOWN_ROLE_JWT='%s'\n"       "${UNKNOWN_JWT}"
printf "export KMS_TEST_OPA_DOMAIN_ADMIN_OTHER_JWT='%s'\n" "${DOM_ADMIN_OTHER_JWT}"
printf "export KMS_TEST_OPA_OTHER_DOMAIN_JWT='%s'\n"       "${OTHER_OFFICER_JWT}"
