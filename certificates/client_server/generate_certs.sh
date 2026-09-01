#!/bin/bash
set -euo pipefail

# On macOS, pass the path to a modern OpenSSL binary as the first argument.
# The system `libressl` generates PKCS12 files with the deprecated RC2 algorithm.
OPENSSL_BIN=${1:-openssl}

# ---------------------------------------------------------------------------
# generate_cert BASENAME CN OUTDIR [CADIR] [PASSOUT]
#
# Issues a CA-signed RSA-2048 certificate and writes four files under OUTDIR:
#   BASENAME.key   private key
#   BASENAME.csr   certificate signing request
#   BASENAME.crt   signed certificate
#   BASENAME.p12   PKCS12 bundle (password = PASSOUT, empty string = no password)
#
# Arguments:
#   BASENAME  filename stem, e.g. "owner.client.acme.com"
#   CN        X.509 Common Name, e.g. "owner.client@acme.com"
#   OUTDIR    output directory, e.g. "owner"
#   CADIR     directory containing ca.crt / ca.key (default: "ca")
#   PASSOUT   PKCS12 export password (default: empty = no password)
# ---------------------------------------------------------------------------
generate_cert() {
    local basename="$1"
    local cn="$2"
    local outdir="$3"
    local cadir="${4:-ca}"
    local passout="${5:-password}"

    mkdir -p "$outdir"

    local key="${outdir}/${basename}.key"
    local csr="${outdir}/${basename}.csr"
    local crt="${outdir}/${basename}.crt"
    local p12="${outdir}/${basename}.p12"

    echo "── Generating ${cn} (${outdir}) ──"

    "$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "$key"

    "$OPENSSL_BIN" req -new -key "$key" \
        -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=${cn}" \
        -out "$csr"

    "$OPENSSL_BIN" x509 -req -days 3650 \
        -in "$csr" -CA "${cadir}/ca.crt" -CAkey "${cadir}/ca.key" -CAcreateserial \
        -out "$crt"

    "$OPENSSL_BIN" pkcs12 -export \
        -out "$p12" -inkey "$key" -in "$crt" -certfile "${cadir}/ca.crt" \
        -passout "pass:${passout}"
}


# ---------------------------------------------------------------------------
# CA
# ---------------------------------------------------------------------------
mkdir -p ca
echo "── Generating CA ──"
"$OPENSSL_BIN" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca/ca.key
"$OPENSSL_BIN" req -new -x509 -days 3650 -key ca/ca.key \
    -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=Acme Test Root CA" \
    -out ca/ca.crt


# ---------------------------------------------------------------------------
# Server cert
# ---------------------------------------------------------------------------
generate_cert "kmserver.acme.com" "kmserver.acme.com" "server"


# ---------------------------------------------------------------------------
# Client certs
# ---------------------------------------------------------------------------
generate_cert "owner.client.acme.com" "owner.client@acme.com" "owner"
generate_cert "user.client.acme.com"  "user.client@acme.com"  "user"
generate_cert "co3.client.acme.com"   "co3.client@acme.com"   "co3"

echo "Done."
