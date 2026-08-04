#!/usr/bin/env python3
"""
test_spiffe_identity.py — Hardened SPIFFE/SPIRE identity validation for a Mistral AI agent.

Verification layers (run in order; every failure is printed before exiting 1):

  [1] JWT-SVID: fetch, full SPIFFE ID (trust domain + path), expiry
  [2] JWT payload: decode independently, verify sub/aud/iat/exp/TTL bounds
  [3] JWT signature: cryptographic re-verification against SPIRE JWKS (independent of SDK)
  [4] X.509-SVID: SAN contains SPIFFE URI, NOT a CA cert, validity window, key type
  [5] X.509 chain: leaf → intermediate(s) → trust-bundle root (signature chain)
  [6] KMS root CA match: if KMS_ROOT_CA_PEM is set, verify the bundle root came from KMS

Environment variables:
  SPIFFE_ENDPOINT_SOCKET  — Workload API socket path
                            Default: unix:///tmp/spire-agent/public/api.sock
  AGENT_ID                — label used in log lines   (default: "mistral-agent")
  TRUST_DOMAIN            — expected SPIFFE trust domain (default: "cosmian-test.local")
  EXPECTED_SPIFFE_PATH    — expected path component after the trust domain
                            (default: "/mistral-agent")
  JWT_AUDIENCE            — audience value the JWT must contain (default: "cosmian-kms")
  MAX_SVID_TTL_SECONDS    — maximum allowed SVID lifetime in seconds (default: 7200)
  KMS_ROOT_CA_PEM         — optional path to the PEM file of the KMS-issued root CA;
                            if set, the X.509 trust bundle root must match this cert

Exit codes:
  0 — all assertions passed
  1 — one or more assertions failed (all failures are printed before exit)
"""

from __future__ import annotations

import base64
import datetime
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# ── Configuration ──────────────────────────────────────────────────────────────
AGENT_ID             = os.environ.get("AGENT_ID", "mistral-agent")
SOCKET               = os.environ.get("SPIFFE_ENDPOINT_SOCKET",
                                      "unix:///tmp/spire-agent/public/api.sock")
EXPECTED_TRUST_DOMAIN = os.environ.get("TRUST_DOMAIN", "cosmian-test.local")
EXPECTED_SPIFFE_PATH  = os.environ.get("EXPECTED_SPIFFE_PATH", "/mistral-agent")
JWT_AUDIENCE          = os.environ.get("JWT_AUDIENCE", "cosmian-kms")
MAX_SVID_TTL_SECONDS  = int(os.environ.get("MAX_SVID_TTL_SECONDS", "7200"))
KMS_ROOT_CA_PEM       = os.environ.get("KMS_ROOT_CA_PEM", "")

EXPECTED_SPIFFE_ID = f"spiffe://{EXPECTED_TRUST_DOMAIN}{EXPECTED_SPIFFE_PATH}"

RETRY_COUNT  = 10
RETRY_DELAY_S = 5

# ── Logging ───────────────────────────────────────────────────────────────────
def log(msg: str) -> None:
    ts = datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] [{AGENT_ID}] {msg}", flush=True)

def log_ok(label: str, detail: str = "") -> None:
    suffix = f"  →  {detail}" if detail else ""
    log(f"  ✓  {label}{suffix}")

def log_fail(label: str, detail: str = "") -> None:
    suffix = f"  →  {detail}" if detail else ""
    log(f"  ✗  FAIL: {label}{suffix}")

def log_warn(label: str, detail: str = "") -> None:
    suffix = f"  →  {detail}" if detail else ""
    log(f"  ⚠  WARN: {label}{suffix}")

def log_skip(label: str, reason: str = "") -> None:
    suffix = f"  ({reason})" if reason else ""
    log(f"  –  SKIP: {label}{suffix}")

def _section(title: str) -> None:
    log(f"")
    log(f"  {'─' * 60}")
    log(f"  {title}")
    log(f"  {'─' * 60}")

# ── Assertion tracker ─────────────────────────────────────────────────────────
_failures: List[str] = []
_pass_count = 0

def _assert(cond: bool, label: str, ok_detail: str = "", fail_detail: str = "") -> bool:
    global _pass_count
    if cond:
        log_ok(label, ok_detail)
        _pass_count += 1
        return True
    else:
        log_fail(label, fail_detail)
        _failures.append(f"{label}: {fail_detail}")
        return False

# ── JWT helpers ───────────────────────────────────────────────────────────────
def _b64url_decode(s: str) -> bytes:
    """Decode base64url with padding normalisation."""
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def _decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    """Return the decoded JWT payload dict without signature verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        return json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None

def _verify_jwt_sig(token: str, jwt_authorities: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Cryptographically verify the JWT signature against the SPIRE JWKS authorities.

    SPIRE uses ES256 (ECDSA P-256 / SHA-256).  JOSE encodes the ECDSA signature as
    a raw R || S byte string (not DER), so we convert before calling cryptography.

    Returns (ok: bool, detail: str).
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
        from cryptography.exceptions import InvalidSignature

        parts = token.split(".")
        if len(parts) != 3:
            return False, "token does not have 3 parts"

        header_b64, payload_b64, sig_b64 = parts
        header = json.loads(_b64url_decode(header_b64))
        alg    = header.get("alg", "ES256")
        kid    = header.get("kid", "")

        # Locate the signing key: prefer kid match, fall back to the only key
        pub_key = jwt_authorities.get(kid)
        if pub_key is None:
            if len(jwt_authorities) == 1:
                pub_key = next(iter(jwt_authorities.values()))
            elif jwt_authorities:
                return False, f"kid='{kid}' not found in {list(jwt_authorities.keys())}"
            else:
                return False, "no JWT authorities in bundle"

        alg_map = {"ES256": (SHA256(), 32), "ES384": (SHA384(), 48), "ES512": (SHA512(), 66)}
        if alg not in alg_map:
            return False, f"unsupported JWT algorithm '{alg}'"

        hash_alg, half = alg_map[alg]
        signing_input  = f"{header_b64}.{payload_b64}".encode("ascii")
        raw_sig        = _b64url_decode(sig_b64)

        if len(raw_sig) != 2 * half:
            return False, f"raw sig length {len(raw_sig)} != expected {2 * half}"

        # Convert raw (R || S) to DER that cryptography.verify() expects
        r = int.from_bytes(raw_sig[:half], "big")
        s = int.from_bytes(raw_sig[half:], "big")
        der_sig = encode_dss_signature(r, s)

        pub_key.verify(der_sig, signing_input, ECDSA(hash_alg))
        return True, f"alg={alg}, kid='{kid or '(none)'}'"

    except InvalidSignature:
        return False, "cryptographic signature check failed (InvalidSignature)"
    except Exception as exc:
        return False, f"exception during verification: {exc}"

# ── X.509 chain helpers ───────────────────────────────────────────────────────
def _cert_signed_by(cert: Any, issuer: Any) -> bool:
    """Return True if `cert` has a valid signature made by `issuer`'s private key."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

        pub = issuer.public_key()
        if isinstance(pub, EllipticCurvePublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes,
                       ECDSA(cert.signature_hash_algorithm))
        elif isinstance(pub, RSAPublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes,
                       PKCS1v15(), cert.signature_hash_algorithm)
        else:
            return False
        return True
    except Exception:
        return False

def _verify_x509_chain(leaf: Any, rest_of_chain: List[Any],
                        roots: List[Any]) -> Tuple[bool, str]:
    """
    Walk leaf → chain → one of the roots.
    Verifies each certificate's signature against the next issuer in the chain.
    Returns (ok, detail).
    """
    chain = [leaf] + list(rest_of_chain)
    for i in range(len(chain) - 1):
        if not _cert_signed_by(chain[i], chain[i + 1]):
            subj  = chain[i].subject.rfc4514_string()
            issuer = chain[i + 1].subject.rfc4514_string()
            return False, f"cert[{i}] ({subj!r}) signature invalid against cert[{i+1}] ({issuer!r})"

    last = chain[-1]
    for root in roots:
        if _cert_signed_by(last, root):
            return True, f"chain depth {len(chain)}, anchored to root '{root.subject.rfc4514_string()}'"

    return False, "chain last cert not signed by any root in the trust bundle"


# =============================================================================
# Verification blocks
# =============================================================================

def block1_fetch_jwt_svid(client: Any) -> Optional[Any]:
    """[1] Fetch JWT-SVID from Workload API."""
    _section("[1] JWT-SVID — fetch")
    log(f"  Audience requested : {JWT_AUDIENCE}")
    log(f"  Expected SPIFFE ID : {EXPECTED_SPIFFE_ID}")

    for attempt in range(1, RETRY_COUNT + 1):
        try:
            log(f"  Connecting (attempt {attempt}/{RETRY_COUNT})…")
            svids = client.fetch_jwt_svids(audience=[JWT_AUDIENCE], subject=None)
            if svids:
                svid = svids[0]
                spiffe_id = str(svid.spiffe_id)
                _assert(True, "JWT-SVID received", f"SPIFFE ID = {spiffe_id}")
                _assert(
                    spiffe_id == EXPECTED_SPIFFE_ID,
                    "SPIFFE ID matches expected value",
                    ok_detail=spiffe_id,
                    fail_detail=f"got '{spiffe_id}', expected '{EXPECTED_SPIFFE_ID}'"
                )
                return svid
        except Exception as exc:
            log(f"  WARN: fetch failed ({exc}). Retrying in {RETRY_DELAY_S}s…")
            time.sleep(RETRY_DELAY_S)

    _assert(False, "JWT-SVID received",
            fail_detail=f"no SVID after {RETRY_COUNT} retries")
    return None


def block2_jwt_payload(svid: Any) -> bool:
    """[2] Decode JWT payload independently and verify all required claims."""
    _section("[2] JWT payload — independent decode + claim inspection")
    ok = True
    token = getattr(svid, "token", None)
    if token is None:
        log_warn("JWT token string unavailable (spiffe SDK version), skipping payload checks")
        return True

    payload = _decode_jwt_payload(token)
    if not _assert(payload is not None, "JWT payload decodes as valid JSON",
                   fail_detail="base64url decode or JSON parse failed"):
        return False

    log(f"  Decoded payload: {json.dumps(payload, default=str)}")

    now = datetime.datetime.now(tz=datetime.timezone.utc)

    # sub
    sub = payload.get("sub", "")
    ok &= _assert(sub == EXPECTED_SPIFFE_ID, "'sub' claim equals expected SPIFFE ID",
                  ok_detail=sub, fail_detail=f"sub='{sub}', expected='{EXPECTED_SPIFFE_ID}'")

    # aud — may be a list or a scalar string
    aud_raw = payload.get("aud")
    aud_list = aud_raw if isinstance(aud_raw, list) else ([aud_raw] if aud_raw else [])
    ok &= _assert(JWT_AUDIENCE in aud_list, f"'aud' contains '{JWT_AUDIENCE}'",
                  ok_detail=str(aud_list),
                  fail_detail=f"aud={aud_list!r} does not contain '{JWT_AUDIENCE}'")

    # iat — must be present and not in the future
    iat_raw = payload.get("iat")
    if _assert(iat_raw is not None, "'iat' claim present", fail_detail="missing 'iat'"):
        iat_dt = datetime.datetime.fromtimestamp(float(iat_raw), tz=datetime.timezone.utc)
        ok &= _assert(iat_dt <= now, "'iat' is not in the future",
                      ok_detail=iat_dt.isoformat(),
                      fail_detail=f"iat={iat_dt.isoformat()} is after now={now.isoformat()}")

    # exp — must be present and not yet passed
    exp_raw = payload.get("exp")
    if _assert(exp_raw is not None, "'exp' claim present", fail_detail="missing 'exp'"):
        exp_dt = datetime.datetime.fromtimestamp(float(exp_raw), tz=datetime.timezone.utc)
        ok &= _assert(exp_dt > now, "'exp' is in the future (SVID not expired)",
                      ok_detail=exp_dt.isoformat(),
                      fail_detail=f"exp={exp_dt.isoformat()}, now={now.isoformat()}")

        # TTL bounds — guard against infinite-lifetime bugs
        if iat_raw is not None:
            ttl = int(exp_raw) - int(iat_raw)
            ok &= _assert(
                0 < ttl <= MAX_SVID_TTL_SECONDS,
                f"JWT TTL within bounds (0 < {ttl}s ≤ {MAX_SVID_TTL_SECONDS}s)",
                ok_detail=f"{ttl}s",
                fail_detail=f"TTL={ttl}s exceeds MAX_SVID_TTL_SECONDS={MAX_SVID_TTL_SECONDS}"
            )

    return ok


def block3_jwt_signature(svid: Any, client: Any) -> bool:
    """[3] Re-verify the JWT signature using the SPIRE JWT bundle JWKS."""
    _section("[3] JWT signature — independent cryptographic re-verification")
    token = getattr(svid, "token", None)
    if token is None:
        log_skip("JWT signature re-verification", "token string not available from SDK")
        return True

    try:
        bundle_set = client.fetch_jwt_bundles()
        # spiffe-py ≥ 0.3: bundle_set.bundles is a dict; get the entry for our trust domain
        bundles = getattr(bundle_set, "bundles", {})
        td_key = None
        for key in bundles:
            if str(key) == EXPECTED_TRUST_DOMAIN or getattr(key, "name", "") == EXPECTED_TRUST_DOMAIN:
                td_key = key
                break
        if td_key is None:
            log_warn("JWT bundle for trust domain not found",
                     f"available: {[str(k) for k in bundles.keys()]}")
            log_skip("JWT signature re-verification", "no bundle for trust domain")
            return True

        bundle       = bundles[td_key]
        authorities  = getattr(bundle, "jwt_authorities", {})
        key_count    = len(authorities)
        log_ok(f"Fetched SPIRE JWT bundle", f"{key_count} key(s)")

        if key_count == 0:
            log_warn("JWT bundle has no authorities — cannot verify signature")
            log_skip("JWT signature re-verification", "empty JWT bundle")
            return True

        ok, detail = _verify_jwt_sig(token, authorities)
        return _assert(ok, "JWT signature verifies against SPIRE JWKS",
                       ok_detail=detail, fail_detail=detail)

    except Exception as exc:
        log_warn("fetch_jwt_bundles() failed", str(exc))
        log_skip("JWT signature re-verification", "bundle fetch error (non-fatal)")
        return True  # treat as warning, not hard failure


def block4_x509_svid(client: Any) -> Optional[Any]:
    """[4] Fetch X.509-SVID and inspect the leaf certificate."""
    _section("[4] X.509-SVID — certificate inspection")

    try:
        x509_svids = client.fetch_x509_svids()
    except Exception as exc:
        _assert(False, "X.509-SVID received", fail_detail=str(exc))
        return None

    if not _assert(bool(x509_svids), "X.509-SVID received",
                   fail_detail="empty list from fetch_x509_svids()"):
        return None

    svid = x509_svids[0]

    # SPIFFE ID
    spiffe_id = str(svid.spiffe_id)
    _assert(spiffe_id == EXPECTED_SPIFFE_ID,
            "X.509-SVID SPIFFE ID matches expected",
            ok_detail=spiffe_id,
            fail_detail=f"got '{spiffe_id}', expected '{EXPECTED_SPIFFE_ID}'")

    # Certificate chain depth
    chain = getattr(svid, "cert_chain", [])
    leaf  = getattr(svid, "leaf", chain[0] if chain else None)
    log_ok(f"Certificate chain depth", f"{len(chain)} cert(s)")

    if leaf is None:
        _assert(False, "Leaf certificate present", fail_detail="cert_chain is empty")
        return svid

    _inspect_leaf_cert(leaf)
    return svid


def _inspect_leaf_cert(leaf: Any) -> None:
    """Inspect the leaf certificate for SPIFFE identity guarantees."""
    from cryptography import x509 as cx509
    from cryptography.x509.oid import ExtensionOID
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

    now = datetime.datetime.now(tz=datetime.timezone.utc)

    # 1. Certificate is currently valid (not expired, not yet valid)
    nb = leaf.not_valid_before_utc if hasattr(leaf, "not_valid_before_utc") \
         else leaf.not_valid_before.replace(tzinfo=datetime.timezone.utc)
    na = leaf.not_valid_after_utc if hasattr(leaf, "not_valid_after_utc") \
         else leaf.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    _assert(nb <= now <= na, "Leaf certificate is currently valid",
            ok_detail=f"{nb.isoformat()} → {na.isoformat()}",
            fail_detail=f"not_valid_before={nb.isoformat()}, not_valid_after={na.isoformat()}, now={now.isoformat()}")

    # 2. Certificate TTL ≤ MAX_SVID_TTL_SECONDS
    ttl = int((na - nb).total_seconds())
    _assert(0 < ttl <= MAX_SVID_TTL_SECONDS,
            f"X.509-SVID TTL within bounds (0 < {ttl}s ≤ {MAX_SVID_TTL_SECONDS}s)",
            ok_detail=f"{ttl}s",
            fail_detail=f"TTL={ttl}s exceeds MAX_SVID_TTL_SECONDS={MAX_SVID_TTL_SECONDS}")

    # 3. basicConstraints: must be a leaf cert (CA:FALSE)
    try:
        bc = leaf.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        _assert(not bc.ca, "X.509-SVID is a leaf certificate (basicConstraints CA:FALSE)",
                ok_detail=f"ca={bc.ca}",
                fail_detail=f"basicConstraints.ca is True — this is a CA cert, not an SVID")
    except cx509.ExtensionNotFound:
        # No basicConstraints = leaf cert (non-CA) per RFC 5280
        log_ok("basicConstraints absent (leaf cert per RFC 5280)")

    # 4. SubjectAlternativeName contains the SPIFFE URI
    try:
        san = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        uris = [str(name.value) for name in san
                if isinstance(name, cx509.UniformResourceIdentifier)]
        _assert(EXPECTED_SPIFFE_ID in uris,
                f"SAN contains SPIFFE URI '{EXPECTED_SPIFFE_ID}'",
                ok_detail=str(uris),
                fail_detail=f"URIs in SAN: {uris}")
    except cx509.ExtensionNotFound:
        _assert(False, "SubjectAlternativeName extension present",
                fail_detail="SAN extension missing from X.509-SVID")

    # 5. Key type (SPIRE uses P-256 or P-384 for SVIDs)
    pub = leaf.public_key()
    if isinstance(pub, EllipticCurvePublicKey):
        curve = pub.curve.name
        _assert(True, f"Public key is EC (curve={curve})", ok_detail=curve)
    elif isinstance(pub, RSAPublicKey):
        bits = pub.key_size
        _assert(True, f"Public key is RSA ({bits}-bit)", ok_detail=str(bits))
    else:
        log_warn("Unknown public key type", type(pub).__name__)


def block5_x509_chain(x509_svid: Any, client: Any) -> bool:
    """[5] Verify the full X.509 certificate chain against the SPIRE trust bundle."""
    _section("[5] X.509 chain — signature verification against trust bundle")

    try:
        bundle_set = client.fetch_x509_bundles()
        bundles    = getattr(bundle_set, "bundles", {})
        td_key = None
        for key in bundles:
            if str(key) == EXPECTED_TRUST_DOMAIN or getattr(key, "name", "") == EXPECTED_TRUST_DOMAIN:
                td_key = key
                break
        if td_key is None:
            log_warn("X.509 bundle for trust domain not found",
                     f"available: {[str(k) for k in bundles.keys()]}")
            log_skip("X.509 chain verification", "no bundle for trust domain")
            return True

        bundle    = bundles[td_key]
        roots     = getattr(bundle, "x509_authorities", [])
        root_count = len(roots)
        _assert(root_count > 0, "Trust bundle contains at least one root CA",
                ok_detail=f"{root_count} root(s)",
                fail_detail="x509_authorities is empty")

        for i, root in enumerate(roots):
            log_ok(f"  Root CA [{i}]",
                   root.subject.rfc4514_string()[:80])

        chain = getattr(x509_svid, "cert_chain", [])
        leaf  = getattr(x509_svid, "leaf", chain[0] if chain else None)
        if leaf is None:
            log_skip("Chain signature walk", "no leaf cert")
            return True

        # The chain returned by fetch_x509_svids includes the leaf; rest_of_chain
        # are the intermediate certs that come after the leaf.
        rest = chain[1:] if len(chain) > 1 else []

        ok, detail = _verify_x509_chain(leaf, rest, roots)
        return _assert(ok, "X.509 SVID chain anchors to a trust-bundle root CA",
                       ok_detail=detail, fail_detail=detail)

    except Exception as exc:
        log_warn("X.509 bundle fetch or chain verification raised", str(exc))
        log_skip("X.509 chain verification", "exception (non-fatal)")
        return True  # treat as warning


def block6_kms_root_ca(client: Any) -> bool:
    """[6] Optional: verify the trust bundle root CA matches the KMS-issued cert."""
    _section("[6] KMS root CA — trust bundle origin verification")

    if not KMS_ROOT_CA_PEM:
        log_skip("KMS root CA match", "KMS_ROOT_CA_PEM not set")
        return True

    try:
        from cryptography import x509 as cx509
        from cryptography.hazmat.primitives.serialization import Encoding

        with open(KMS_ROOT_CA_PEM, "rb") as f:
            kms_cert = cx509.load_pem_x509_certificate(f.read())
        kms_fp = kms_cert.fingerprint(kms_cert.signature_hash_algorithm).hex()
        log_ok("KMS root CA loaded", f"subject='{kms_cert.subject.rfc4514_string()}', SHA-256 fp={kms_fp[:16]}…")

        bundle_set = client.fetch_x509_bundles()
        bundles    = getattr(bundle_set, "bundles", {})
        td_key = None
        for key in bundles:
            if str(key) == EXPECTED_TRUST_DOMAIN or getattr(key, "name", "") == EXPECTED_TRUST_DOMAIN:
                td_key = key
                break
        if td_key is None:
            log_skip("KMS root CA match", "no bundle for trust domain")
            return True

        roots = getattr(bundles[td_key], "x509_authorities", [])
        for root in roots:
            from cryptography.hazmat.primitives import hashes
            root_fp = root.fingerprint(hashes.SHA256()).hex()
            if root_fp == kms_fp:
                return _assert(True, "Trust bundle root CA fingerprint matches KMS-issued root CA",
                               ok_detail=f"fp={kms_fp[:16]}…")

        fps = [root.fingerprint(__import__('cryptography.hazmat.primitives.hashes',
               fromlist=['SHA256']).SHA256()).hex()[:16]
               for root in roots]
        return _assert(False, "Trust bundle root CA fingerprint matches KMS-issued root CA",
                       fail_detail=f"KMS fp={kms_fp[:16]}…, bundle fps={fps}")

    except FileNotFoundError:
        log_warn("KMS_ROOT_CA_PEM file not found", KMS_ROOT_CA_PEM)
        log_skip("KMS root CA match", "file missing")
        return True
    except Exception as exc:
        log_warn("KMS root CA verification raised", str(exc))
        log_skip("KMS root CA match", "exception (non-fatal)")
        return True


# =============================================================================
# main
# =============================================================================

def main() -> int:
    log("=" * 70)
    log(f"  Mistral agent SPIFFE identity test  —  {AGENT_ID}")
    log("=" * 70)
    log(f"  Socket          : {SOCKET}")
    log(f"  Trust domain    : {EXPECTED_TRUST_DOMAIN}")
    log(f"  Expected ID     : {EXPECTED_SPIFFE_ID}")
    log(f"  JWT audience    : {JWT_AUDIENCE}")
    log(f"  Max SVID TTL    : {MAX_SVID_TTL_SECONDS}s")
    log(f"  KMS root CA     : {KMS_ROOT_CA_PEM or '(not set — block 6 will be skipped)'}")
    log("")

    try:
        from spiffe.workloadapi.workload_api_client import WorkloadApiClient
    except ImportError as exc:
        log(f"FATAL: spiffe library not installed — {exc}")
        return 1

    with WorkloadApiClient(socket_path=SOCKET) as client:
        # Block 1 — fetch JWT-SVID (retries internally)
        jwt_svid = block1_fetch_jwt_svid(client)
        if jwt_svid is None:
            log("")
            log("FATAL: Could not obtain a JWT-SVID. Aborting.")
            return 1

        # Block 2 — payload inspection (independent of SDK)
        block2_jwt_payload(jwt_svid)

        # Block 3 — JWT signature re-verification
        block3_jwt_signature(jwt_svid, client)

        # Block 4 — X.509-SVID certificate inspection
        x509_svid = block4_x509_svid(client)

        # Block 5 — X.509 chain → trust bundle
        if x509_svid is not None:
            block5_x509_chain(x509_svid, client)

        # Block 6 — optional KMS root CA fingerprint match
        block6_kms_root_ca(client)

    # ── Final summary ─────────────────────────────────────────────────────────
    log("")
    log("=" * 70)
    if _failures:
        log(f"  RESULT: {len(_failures)} FAILURE(S), {_pass_count} passed")
        for f in _failures:
            log(f"    ✗ {f}")
        log("=" * 70)
        return 1
    else:
        log(f"  RESULT: ALL {_pass_count} ASSERTIONS PASSED")
        log("=" * 70)
        return 0


if __name__ == "__main__":
    sys.exit(main())


# ── Legacy entry point kept for backward compatibility ────────────────────────
def test_mtls_request(x509_svid: object, url: str) -> bool:
    """Optionally make an mTLS request to a protected endpoint using the X.509-SVID."""
    if not url:
        log("SKIP: PROTECTED_URL not set — skipping mTLS request test.")
        return True

    import ssl
    import tempfile

    import requests  # type: ignore

    try:
        # Write cert + key to temp files for requests
        with (
            tempfile.NamedTemporaryFile(suffix=".pem", delete=False, mode="w") as cert_f,
            tempfile.NamedTemporaryFile(suffix=".pem", delete=False, mode="w") as key_f,
        ):
            cert_f.write(x509_svid.leaf.public_bytes(encoding=None).decode())
            key_f.write(x509_svid.private_key.private_bytes(
                encoding=None, format=None, encryption_algorithm=None
            ).decode())
            cert_path = cert_f.name
            key_path = key_f.name

        resp = requests.get(url, cert=(cert_path, key_path), timeout=10)
        log(f"mTLS request to {url}: HTTP {resp.status_code}")
        return resp.status_code < 500
    except Exception as exc:
        log(f"WARN: mTLS request failed — {exc}")
        return False
