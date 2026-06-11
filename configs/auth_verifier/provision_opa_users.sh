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
# interfere with `eval "$(…)"`.
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
#   CA_CERT    — path to the server CA certificate
#                (default: authentication/server/src/tests/certificates/ec/auth.ca.pem
#                 relative to the repo root; override via env when running from an
#                 arbitrary directory)
#   REPO_ROOT  — repository root path              (default: auto-detected)

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
AUTH_URL="${AUTH_URL:-https://127.0.0.1:8443}"
REALM_A="${REALM_A:-kms-opa-test}"
REALM_B="${REALM_B:-kms-opa-other}"
PASSWORD="${PASSWORD:-change_me}"
REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../../../.." && pwd)}"
CA_CERT="${CA_CERT:-${REPO_ROOT}/authentication/server/src/tests/certificates/ec/auth.ca.pem}"

COOKIE_JAR=$(mktemp /tmp/opa-admin-XXXXXX.txt)
trap 'rm -f "${COOKIE_JAR}"' EXIT

# ── Helpers ───────────────────────────────────────────────────────────────────

# All status messages go to STDERR so STDOUT stays clean for `eval "$(…)"`.
log()  { echo "$*" >&2; }
warn() { echo "  ⚠  $*" >&2; }
fail() { echo "  ✗  $*" >&2; exit 1; }

# Convert a plain-text password to a JSON byte-array for the auth verifier API.
# The UserPass endpoint expects Vec<u8> (Rust serde_json → array of integers).
str_to_json_bytes() {
    printf '%s' "$1" \
        | od -v -tu1 -An \
        | tr -s ' \n' ' ' \
        | sed 's/^ //; s/ $//' \
        | tr ' ' ','
}

# POST with admin session cookie; non-2xx responses are ignored (idempotent).
admin_post_idempotent() {
    local path="$1" body="$2"
    curl -sk --cacert "${CA_CERT}" \
        -b "${COOKIE_JAR}" -c "${COOKIE_JAR}" \
        -o /dev/null \
        -H "Content-Type: application/json" \
        -X POST "${AUTH_URL}${path}" \
        -d "${body}" || true
}

# DELETE — idempotent (404 is fine).
admin_delete_idempotent() {
    local path="$1"
    curl -sk --cacert "${CA_CERT}" \
        -b "${COOKIE_JAR}" -c "${COOKIE_JAR}" \
        -o /dev/null \
        -X DELETE "${AUTH_URL}${path}" || true
}

# Login and return the JWT from the `_ea_` cookie via STDOUT.
user_login_jwt() {
    local realm="$1" username="$2" ******
    local cookie_output
    cookie_output=$(mktemp /tmp/opa-login-XXXXXX.txt)
    # shellcheck disable=SC2064
    trap "rm -f '${cookie_output}'" RETURN

    local http_status
    http_status=$(curl -sk --cacert "${CA_CERT}" \
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
    printf '%s' "${jwt}"
}

# ── Step 1: super-admin login ─────────────────────────────────────────────────
log ""
log "Auth Verifier: ${AUTH_URL}"
log "Realms: ${REALM_A} (primary)  ${REALM_B} (cross-domain)"
log ""

http_status=$(curl -sk --cacert "${CA_CERT}" \
    -c "${COOKIE_JAR}" -b "${COOKIE_JAR}" \
    -o /dev/null -w "%{http_code}" \
    -u "admin:change_me" \
    -H "Content-Type: application/json" \
    -X POST "${AUTH_URL}/login?realm=_" \
    -d '{"public_key_pem":null,"totp_code":null}')
if [[ "${http_status}" != 2* ]]; then
    fail "super-admin login → HTTP ${http_status}. Is the auth verifier running at ${AUTH_URL}?"
fi
log "  ✓ super-admin authenticated"

# ── Step 2: Create realms (idempotent) ───────────────────────────────────────
for realm in "${REALM_A}" "${REALM_B}"; do
    admin_post_idempotent "/admins/realms" \
        "{\"id\":\"${realm}\",\"auth_params\":{\"username_password_params\":{\"allow_expired_passwords\":false}},\"session_max_age_seconds\":3600,\"session_max_stale_age_seconds\":7200}"
    log "  ✓ realm '${realm}' ready"
done

# ── Step 3: Create realm admins (idempotent) ─────────────────────────────────
admin_post_idempotent "/admins" \
    '{"id":"kms-opa-officer","realms":["'"${REALM_A}"'"],"userpass":"kms-opa-officer"}'
admin_post_idempotent "/admins" \
    '{"id":"kms-opa-other-officer","realms":["'"${REALM_B}"'"],"userpass":"kms-opa-other-officer"}'

# ── Step 4: Create users (delete-then-create for idempotency) ────────────────
#
# Format: "username:password:realm:roles_json_array"
# Empty roles array ("[]") → OPA deny edge-case.
# Unknown role ("Hacker") → OPA deny edge-case (no matching rule in kms.rego).
USERS=(
    "kms-opa-super-admin:${PASSWORD}:${REALM_A}:[\"SuperAdmin\"]"
    "kms-opa-officer:${PASSWORD}:${REALM_A}:[\"CryptoOfficer\"]"
    "kms-opa-user:${PASSWORD}:${REALM_A}:[\"User\"]"
    "kms-opa-auditor:${PASSWORD}:${REALM_A}:[\"Auditor\"]"
    "kms-opa-no-roles:${PASSWORD}:${REALM_A}:[]"
    "kms-opa-unknown-role:${PASSWORD}:${REALM_A}:[\"Hacker\"]"
    "kms-opa-domain-admin-other:${PASSWORD}:${REALM_B}:[\"DomainAdmin\"]"
    "kms-opa-other-officer:${PASSWORD}:${REALM_B}:[\"CryptoOfficer\"]"
)

for entry in "${USERS[@]}"; do
    IFS=: read -r username password realm roles <<< "${entry}"
    admin_delete_idempotent "/realms/${realm}/userpass/${username}"
    password_bytes="[$(str_to_json_bytes "${password}")]"
    admin_post_idempotent "/realms/${realm}/userpass" \
        "{\"realm\":\"${realm}\",\"username\":\"${username}\",\"password\":${password_bytes},\"change_password\":false,\"roles\":${roles}}"
    log "  ✓ ${username} (${roles}) → realm '${realm}'"
done

# ── Step 5: Login as each user, capture JWTs ─────────────────────────────────
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

# ── Step 6: Summary table (to STDERR) ────────────────────────────────────────
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
