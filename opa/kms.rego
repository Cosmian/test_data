# KMS RBAC policy for the Open Policy Agent server.
#
# Endpoint evaluated by KMS: POST /v1/data/kms/allow
#
# Input document (all fields are strings unless noted):
#   input.user            — authenticated identity (JWT sub, TLS CN, API-token id)
#   input.user_domain     — domain from `as_domain` JWT private claim; "" for non-JWT
#   input.roles           — array of role strings from JWT `roles` claim (RFC 9068).
#                           For non-JWT auth schemes (mTLS, API token) this is []
#                           and all role-based rules deny (fail-closed).
#   input.is_super_admin  — boolean: true when KMS ceremony super-admin is activated
#                           (SA3: Shamir ceremony, separate from JWT "SuperAdmin" role)
#   input.operation       — KMIP operation name in lowercase snake_case, e.g. "create", "get_attributes"
#   input.object_uid      — UID of the target KMIP object ("*" for object-less ops)
#   input.object_domain   — domain the target object belongs to ("" for object-less ops)
#   input.is_owner        — boolean: true when the caller owns the object
#
# Role names (defined in the auth server's realm configuration, carried in JWT):
#   SuperAdmin    — unrestricted, cross-domain (JWT-granted by auth admin)
#   DomainAdmin   — full access within own domain
#   CryptoOfficer — key lifecycle operations within own domain
#   Auditor       — read-only metadata within own domain
#   User          — crypto-use only (no lifecycle, no export)
#
# Response shape: { "result": true | false }
#
# Normative references:
#   FIPS 140-3 §7.4            — CryptoOfficer and User mandatory module roles
#   NIST SP 800-57 Part 2 §4.3 — Key management role definitions
#   ANSI/INCITS 359-2004  §4.2 — Hierarchical + Constrained RBAC
#   NIST SP 800-53 Rev 5  AC-5, AC-6, AU-9 — Separation of duties, least privilege

package kms

import rego.v1

# ---------------------------------------------------------------------------
# Default: deny everything unless a rule explicitly allows.
# ---------------------------------------------------------------------------
default allow := false

# ---------------------------------------------------------------------------
# Owners always have full access to their own objects.
# ---------------------------------------------------------------------------
allow if {
    input.is_owner == true
}

# ---------------------------------------------------------------------------
# Ceremony super-admin (SA3) — Shamir-activated, cross-domain.
# This is distinct from the JWT "SuperAdmin" role: ceremony activation is a
# KMS-internal state (split-key ceremony) mapped into OPA input for auditability.
# ---------------------------------------------------------------------------
allow if {
    input.is_super_admin == true
}

# ---------------------------------------------------------------------------
# SuperAdmin role (JWT-granted) — unrestricted, cross-domain.
# (ANSI/INCITS 359 §4.2: top of the role hierarchy)
# ---------------------------------------------------------------------------
allow if {
    input.roles[_] == "SuperAdmin"
}

# ---------------------------------------------------------------------------
# DomainAdmin — full control, but only within their own domain.
# (ANSI/INCITS 359 §4.2: senior role scoped to one namespace)
# ---------------------------------------------------------------------------
allow if {
    input.roles[_] == "DomainAdmin"
    same_domain
}

# ---------------------------------------------------------------------------
# CryptoOfficer — key lifecycle operations, scoped to domain.
# (FIPS 140-3 §7.4; NIST SP 800-57 Part 2 §4.3 "Key Management Officer")
# ---------------------------------------------------------------------------
crypto_officer_ops := {
    # Key creation and ingest
    "create",
    "create_key_pair",
    "import",
    # Key retrieval and export
    "get",
    "export",
    "locate",
    "get_attributes",
    # Attribute management (no key-material exposure)
    "set_attribute",
    "modify_attribute",
    "delete_attribute",
    "add_attribute",
    # Key lifecycle management
    "activate",
    "revoke",
    "archive",
    "recover",
    "destroy",
    # Re-keying
    "rekey",
    "rekey_key_pair",
}

allow if {
    input.roles[_] == "CryptoOfficer"
    same_domain
    crypto_officer_ops[input.operation]
}

# ---------------------------------------------------------------------------
# Auditor — read-only, metadata and access inspection only.
# (NIST SP 800-57 Part 2 §4.3 "Audit and Compliance Officer";
#  NIST SP 800-53 AU-9; PCI-DSS v4.0 Req 10)
#
# SSD constraint: must not be the same identity as CryptoOfficer in the same
# domain — enforced at role-assignment time, not in this policy.
# ---------------------------------------------------------------------------
auditor_ops := {
    "locate",
    "get",
    "get_attributes",
    "list_access",
    "query_access",
    # MAC/verify operations expose no key material
    "mac_verify",
}

allow if {
    input.roles[_] == "Auditor"
    same_domain
    auditor_ops[input.operation]
}

# ---------------------------------------------------------------------------
# User — cryptographic-use operations only; no key lifecycle, no export.
# (FIPS 140-3 §7.4 "User" role; PKCS#11 v3.0 CKU_USER)
# ---------------------------------------------------------------------------
user_ops := {
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "mac",
    "mac_verify",
    "derive_key",
    # Locating and reading attributes of delegated objects is necessary
    # for the User to build valid KMIP requests
    "locate",
    "get_attributes",
}

allow if {
    input.roles[_] == "User"
    same_domain
    user_ops[input.operation]
}

# ---------------------------------------------------------------------------
# Helper: the caller's domain and the object's domain are the same.
# SuperAdmin rules and object-less operations (object_domain == "") are
# handled by their own rules above and do not rely on this helper.
# ---------------------------------------------------------------------------
same_domain if {
    input.user_domain == input.object_domain
}

# ---------------------------------------------------------------------------
# Debug rule: reason for the access decision.
# Query via POST /v1/data/kms/reason
# Returns a set of matching reasons (avoids Rego "complete rule" conflicts).
# ---------------------------------------------------------------------------
reasons contains "owner"                  if { input.is_owner == true }
reasons contains "super_admin_ceremony"   if { input.is_super_admin == true; not input.is_owner }
reasons contains "super_admin_role"       if { input.roles[_] == "SuperAdmin"; not input.is_super_admin; not input.is_owner }
reasons contains "domain_admin"           if { input.roles[_] == "DomainAdmin"; same_domain; not input.is_owner }
reasons contains "crypto_officer"         if { input.roles[_] == "CryptoOfficer"; same_domain; crypto_officer_ops[input.operation]; not input.is_owner }
reasons contains "auditor"                if { input.roles[_] == "Auditor"; same_domain; auditor_ops[input.operation]; not input.is_owner }
reasons contains "user"                   if { input.roles[_] == "User"; same_domain; user_ops[input.operation]; not input.is_owner }
reasons contains "no_role"                if { count(input.roles) == 0; not input.is_super_admin; not input.is_owner }
reasons contains "denied"                 if { not allow }
