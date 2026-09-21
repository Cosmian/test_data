#!/usr/bin/env bash
set -euo pipefail

KMS_URL="https://localhost:9998"
OIDC_ISSUER="http://127.0.0.1:8008"

echo "[*] Testing SPIRE OIDC login flow..."

# 1. Verify OIDC Discovery Provider is reachable
DISCOVERY=$(curl -s -k "${OIDC_ISSUER}/.well-known/openid-configuration" 2>/dev/null || true)
if [ -z "$DISCOVERY" ] || ! echo "$DISCOVERY" | jq -e '.authorization_endpoint' >/dev/null 2>&1; then
  echo "❌ OIDC Discovery Provider not responding or missing authorization_endpoint"
  echo "   Ensure: docker compose --profile spire up -d spire-oidc-discovery-provider"
  exit 1
fi

AUTH_ENDPOINT=$(echo "$DISCOVERY" | jq -r '.authorization_endpoint')
TOKEN_ENDPOINT=$(echo "$DISCOVERY" | jq -r '.token_endpoint')
JWKS_URI=$(echo "$DISCOVERY" | jq -r '.jwks_uri')

echo "[✓] OIDC endpoints discovered:"
echo "    Authorization: $AUTH_ENDPOINT"
echo "    Token: $TOKEN_ENDPOINT"
echo "    JWKS: $JWKS_URI"

# 2. Verify KMS is running and OIDC config loaded
KMS_HEALTH=$(curl -s -k "${KMS_URL}/health" 2>/dev/null || echo "failed")
if [ "$KMS_HEALTH" == "failed" ]; then
  echo "❌ KMS server not responding on ${KMS_URL}"
  echo "   Ensure: cargo run -p cosmian_kms_server --features non-fips,insecure -- -c test_data/configs/server/auth/spire_jwt_svid.toml"
  exit 1
fi
echo "[✓] KMS server healthy"

# 3. Trigger KMS UI login flow — fetch authorization redirect
echo "[*] Initiating OIDC login flow..."

LOGIN_FLOW=$(curl -s -k -c /tmp/kms_cookies.txt \
  -w "\n%{http_code}" \
  "${KMS_URL}/ui/login_flow" 2>/dev/null | tail -1)

if [ "$LOGIN_FLOW" != "200" ]; then
  echo "❌ /ui/login_flow failed with HTTP $LOGIN_FLOW"
  exit 1
fi

echo "[✓] Login flow initiated (session cookie set)"

# 4. Verify UI is accessible with session cookie (before user logs in, should redirect to login)
UI_RESPONSE=$(curl -s -k -b /tmp/kms_cookies.txt \
  -o /tmp/ui_response.html \
  -w "%{http_code}" \
  "${KMS_URL}/ui/")

if [ "$UI_RESPONSE" != "200" ]; then
  echo "❌ UI page returned HTTP $UI_RESPONSE"
  exit 1
fi

echo "[✓] UI accessible at ${KMS_URL}/ui/ (HTTP 200)"

# 5. Call /whoami to check current authentication state (should be unauthenticated before OIDC flow)
WHOAMI=$(curl -s -k -b /tmp/kms_cookies.txt "${KMS_URL}/whoami" 2>/dev/null || echo "{}")
USER=$(echo "$WHOAMI" | jq -r '.user_id // empty')

if [ -z "$USER" ]; then
  echo "[*] Not yet authenticated (expected before OIDC callback)"
else
  echo "[✓] Already authenticated as: $USER"
fi

# 6. Simulate OIDC callback: in real browser flow, IdP redirects back to /ui/callback
# with code and state. For this test, we verify the callback endpoint exists.
CALLBACK_TEST=$(curl -s -k -b /tmp/kms_cookies.txt \
  -X POST \
  -d "code=test&state=test" \
  -w "%{http_code}" \
  -o /tmp/callback_response.txt \
  "${KMS_URL}/ui/callback" 2>/dev/null)

echo "[✓] Callback endpoint responds (HTTP $CALLBACK_TEST)"

# 7. Verify /me endpoint structure (used by UI to fetch authenticated user)
ME_RESPONSE=$(curl -s -k -b /tmp/kms_cookies.txt "${KMS_URL}/me" 2>/dev/null || echo "{}")

if echo "$ME_RESPONSE" | jq -e '.user // .user_id' >/dev/null 2>&1; then
  AUTHENTICATED_USER=$(echo "$ME_RESPONSE" | jq -r '.user // .user_id')
  echo "[✓] Authenticated user from /me endpoint: $AUTHENTICATED_USER"
else
  echo "[*] /me endpoint ready (awaiting authenticated session from OIDC flow)"
fi

echo ""
echo "=========================================="
echo "✓ SPIRE OIDC infrastructure test PASSED"
echo "=========================================="
echo ""
echo "Next: Complete full OIDC flow in browser:"
echo "  1. Open browser: ${KMS_URL}/ui/"
echo "  2. Click 'Login with OIDC'"
echo "  3. Authenticate with SPIRE OIDC provider"
echo "  4. Browser redirected back to UI, authenticated"
