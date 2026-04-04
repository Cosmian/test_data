
The [generate.sh](./generate_certs.sh) script will generate

- a CA certificate
- a server certificate in a PKCS12 file to enable HTTPS on the server
- a client certificate to authenticate to the server with CN being <test.client@cosmian.com>

Since the PKCS12 password is `password` (see script), the following command will start the server:

```sh
# For FIPS mode (default build) - use PEM certificates:
RUST_LOG="cosmian=debug" cargo run --bin cosmian_kms -- \
    --tls-cert-file ./test_data/certificates/kmserver.cosmian.com.crt \
    --tls-key-file ./test_data/certificates/kmserver.cosmian.com.key \
    --clients-ca-cert-file ./test_data/certificates/ca.crt

# For non-FIPS mode - use PKCS#12:
# RUST_LOG="cosmian=debug" cargo run --features non-fips --bin cosmian_kms -- \
#     --tls-p12-file ./test_data/certificates/kmserver.cosmian.com.p12 \
#     --tls-p12-password password \
#     --clients-ca-cert-file ./test_data/certificates/ca.crt
```

The following command will test a client connection with client cert authentication:

```sh
curl -k --cert ./test_data/certificates/owner.client.cosmian.com.crt --key ./test_data/certificates/owner.client.cosmian.com.key https://localhost:9998/objects/owned
```
