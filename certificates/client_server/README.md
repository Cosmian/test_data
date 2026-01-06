# SSL/TLS Certificates for Client-Server Mutual Authentication Tests

The file test_data/certificates/client_server/ca/stack_of_ca.pem is the result of concat of:

- test_data/mozilla_IncludedRootsPEM.txt
- test_data/certificates/client_server/ca/ca.crt
- test_data/certificates/p12/root.pem
- test_data/certificates/another_p12/root.crt

## Server 3072 (FIPS-friendly) certificate generation

The files in `server-3072/` were generated with OpenSSL using a 3072‑bit RSA key and explicit TLS server extensions. This aligns with FIPS guidance (RSA ≥ 2048, SHA‑256 signatures, proper EKU/KeyUsage).

Generated artifacts:

- `server-3072/server.key`: RSA‑3072 private key
- `server-3072/server.csr`: CSR for CN `kmserver3072.acme.com`
- `server-3072/server.crt`: Leaf certificate signed by the local test CA (`ca/ca.crt`)
- `server-3072/openssl-ext-server.cnf`: X.509 v3 extensions used at signing time

Commands (run from `test_data/certificates/client_server`):

```sh
# 1) Generate a 3072-bit RSA private key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
 -out server-3072/server.key

# 2) Create a CSR (adjust subject as needed)
openssl req -new -key server-3072/server.key \
 -subj "/C=FR/ST=IdF/L=Paris/O=AcmeTest/CN=kmserver3072.acme.com" \
 -out server-3072/server.csr

# 3) Create the v3 extensions file (already present as openssl-ext-server.cnf)
cat > server-3072/openssl-ext-server.cnf <<'EOF'
[ v3_server ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

# 4) Sign the CSR with the local CA (SHA-256, 10 years)
openssl x509 -req -days 3650 -sha256 \
 -in server-3072/server.csr \
 -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial \
 -extfile server-3072/openssl-ext-server.cnf -extensions v3_server \
 -out server-3072/server.crt
```

Notes:

- Issuer CA material lives in `ca/` (`ca.crt`, `ca.key`).
- SANs were not added for these tests; the CN is `kmserver3072.acme.com`.
- For strict browser validation, add a DNS Subject Alternative Name via `subjectAltName = @alt_names` and an `[alt_names]` section in the ext file.
- If generating under a FIPS-enforced OpenSSL, ensure the default+fips providers are active; the above commands do not rely on non‑approved algorithms.
