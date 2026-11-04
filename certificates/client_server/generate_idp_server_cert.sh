#!/usr/bin/env bash
set -euo pipefail

# Issues the TLS server certificate shared by the Keycloak IdP and the KMS HTTPS listener of the
# RBAC demo stack (deploy/rbac_rego in the Cosmian/kms repository).
#
# The certificate is signed by the existing Acme Test Root CA in ca/. Unlike generate_certs.sh,
# this script never regenerates the CA, so every certificate already signed by it stays valid.
#
# Run from any directory:
#   test_data/certificates/client_server/generate_idp_server_cert.sh [OPENSSL_BIN]
#
# Output (server/):
#   keycloak.localhost.key   RSA-3072 private key (mode 644: it is a public test key and must be
#                            readable by the non-root user of the Keycloak container)
#   keycloak.localhost.crt   leaf certificate, SAN: keycloak.localhost, localhost, 127.0.0.1, ::1

OPENSSL_BIN=${1:-openssl}
cd "$(dirname "${BASH_SOURCE[0]}")"

NAME="keycloak.localhost"
KEY="server/${NAME}.key"
CSR="server/${NAME}.csr"
CRT="server/${NAME}.crt"

mkdir -p server

echo "── Generating ${NAME} server certificate ──"
"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$KEY"

"$OPENSSL_BIN" req -new -key "$KEY" \
  -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=${NAME}" \
  -addext "subjectAltName=DNS:${NAME},DNS:localhost,IP:127.0.0.1,IP:::1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  -out "$CSR"

# 3000 days keeps the leaf inside the validity period of the CA (expires in April 2035).
"$OPENSSL_BIN" x509 -req -sha256 -days 3000 \
  -in "$CSR" -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial \
  -copy_extensions copy \
  -out "$CRT"

rm -f "$CSR"
# Keycloak runs as a non-root user and reads both files through a bind mount, so they must be
# world-readable whatever the caller's umask (test-only key).
chmod 644 "$CRT" "$KEY"

"$OPENSSL_BIN" verify -CAfile ca/ca.crt "$CRT"
echo "Done."
