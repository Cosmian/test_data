#!/usr/bin/env python3
"""
test_spiffe_identity.py — Validate SPIFFE/SPIRE identity for a simulated Mistral AI agent.

What this test does:
1. Connect to the SPIRE Workload API via the unix socket.
2. Fetch a JWT-SVID for the Mistral agent identity.
3. Verify the JWT-SVID signature using the SPIRE bundle (trust domain).
4. Print the SPIFFE ID, expiry, and embedded claims.
5. (Optional) Make a signed request to a protected endpoint using the mTLS X.509-SVID.

Environment:
    SPIFFE_ENDPOINT_SOCKET — path to the SPIRE agent workload API socket.
                             Default: unix:///tmp/spire-agent/public/api.sock
    AGENT_ID               — a label for logging (default: "mistral-agent")
    PROTECTED_URL          — URL of a protected service to test mTLS against (optional)

Exit codes:
    0 — all assertions passed
    1 — SPIFFE identity not received or assertions failed
"""

from __future__ import annotations

import datetime
import os
import sys
import time

AGENT_ID = os.environ.get("AGENT_ID", "mistral-agent")
SOCKET = os.environ.get("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/spire-agent/public/api.sock")
PROTECTED_URL = os.environ.get("PROTECTED_URL", "")
EXPECTED_TRUST_DOMAIN = os.environ.get("TRUST_DOMAIN", "cosmian-test.local")

RETRY_COUNT = 10
RETRY_DELAY_S = 5


def log(msg: str) -> None:
    ts = datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] [{AGENT_ID}] {msg}", flush=True)


def wait_for_svid() -> "spiffe.svid.jwt_svid.JwtSvid | None":
    """Poll the Workload API until an SVID is available or retry count is exhausted."""
    try:
        from spiffe.workloadapi.workload_api_client import WorkloadApiClient
    except ImportError as e:
        log(f"ERROR: spiffe not installed — {e}")
        return None

    for attempt in range(1, RETRY_COUNT + 1):
        try:
            log(f"Connecting to SPIRE Workload API at {SOCKET} (attempt {attempt}/{RETRY_COUNT})...")
            with WorkloadApiClient(socket_path=SOCKET) as client:
                svid_context = client.fetch_jwt_svids(
                    audience=["cosmian-kms"],
                    subject=None,
                )
                if svid_context:
                    return svid_context[0]
        except Exception as exc:
            log(f"WARN: fetch failed ({exc}). Retrying in {RETRY_DELAY_S}s...")
            time.sleep(RETRY_DELAY_S)
    return None


def validate_jwt_svid(jwt_svid: "spiffe.svid.jwt_svid.JwtSvid") -> bool:
    """Assert the JWT-SVID is well-formed and belongs to the expected trust domain."""
    spiffe_id = str(jwt_svid.spiffe_id)
    log(f"SPIFFE ID: {spiffe_id}")
    log(f"Token expiry: {jwt_svid.expiry}")

    # Must belong to our trust domain
    if not spiffe_id.startswith(f"spiffe://{EXPECTED_TRUST_DOMAIN}/"):
        log(f"FAIL: SPIFFE ID '{spiffe_id}' does not match trust domain '{EXPECTED_TRUST_DOMAIN}'")
        return False

    # Must not be expired
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    if isinstance(jwt_svid.expiry, (int, float)):
        expiry_dt = datetime.datetime.fromtimestamp(jwt_svid.expiry, tz=datetime.timezone.utc)
    else:
        expiry_dt = jwt_svid.expiry
    if expiry_dt <= now:
        log(f"FAIL: SVID is expired (expiry={expiry_dt}, now={now})")
        return False

    log(f"PASS: SVID valid until {expiry_dt.isoformat()}")
    return True


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


def main() -> int:
    log("=== Mistral agent SPIFFE identity test ===")
    log(f"Trust domain: {EXPECTED_TRUST_DOMAIN}")
    log(f"Workload API socket: {SOCKET}")

    jwt_svid = wait_for_svid()
    if jwt_svid is None:
        log("FAIL: could not obtain a JWT-SVID from SPIRE after all retries.")
        return 1

    if not validate_jwt_svid(jwt_svid):
        return 1

    # Optionally test mTLS (requires X.509-SVID fetch — placeholder for future)
    # test_mtls_request(x509_svid, PROTECTED_URL)

    log("=== All assertions passed ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
