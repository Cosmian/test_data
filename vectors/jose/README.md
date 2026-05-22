# JOSE Test Vectors

This directory contains JSON test vector files for the JOSE (JSON Object Signing and Encryption) REST crypto endpoints (`/v1/crypto/{encrypt,decrypt,sign,verify,mac}`).

## Sources

- **RFC 7515** — JSON Web Signature (JWS): Appendix A examples (HS256 KAT, RS256, ES256, ES512)
- **RFC 7516** — JSON Web Encryption (JWE): Security edge cases (AAD binding, tampered tag/ciphertext, empty plaintext)
- **RFC 7518** — JSON Web Algorithms (JWA): Section 3/5 algorithms (RS384, RS512, PS256, PS384, PS512, ES384, HS384, HS512, A128GCM, A192GCM, A256GCM)
- **RFC 7520** — Examples of Protecting Content Using JOSE (Cookbook): Sections 4.1–4.4

## Vector Types

| `type` field                     | Description                                           |
| -------------------------------- | ----------------------------------------------------- |
| `mac_kat`                        | Known-answer test: import key, compute MAC, assert exact output |
| `mac_round_trip`                 | Generate key, compute MAC, verify MAC                 |
| `mac_wrong_key_reject`           | Compute MAC with key A, verify with key B → must fail |
| `sign_verify_round_trip`         | Generate key pair, sign, verify                       |
| `encrypt_decrypt_round_trip`     | Generate key, encrypt, decrypt, assert plaintext match |
| `encrypt_decrypt_tamper_reject`  | Encrypt, tamper with a field, decrypt must fail       |
| `key_lifecycle`                  | Create key → use (mac/sign/encrypt) → delete → verify gone |

## Algorithms Covered

### Signing (JWS)
- RS256, RS384, RS512 (RSASSA-PKCS1-v1_5)
- PS256, PS384, PS512 (RSASSA-PSS)
- ES256 (P-256), ES384 (P-384), ES512 (P-521)

### MAC (JWS)
- HS256, HS384, HS512 (HMAC-SHA2)

### Encryption (JWE)
- `dir` + A128GCM, A192GCM, A256GCM (direct key agreement with AES-GCM)

## Not Covered (unsupported by server)

- RSA-OAEP, RSA1_5 key management (RFC 7516 A.1, A.2)
- AES Key Wrap: A128KW, A192KW, A256KW (RFC 7518 §4.4)
- AES-CBC-HMAC: A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 (RFC 7518 §5.2)
- ECDH-ES key agreement (RFC 7518 §4.6)

## Test Runner

The test runner is located at:
`crate/server/src/tests/rest_crypto/jose_vectors.rs`

It loads these JSON files at test time, provisions keys, calls the appropriate REST endpoints, and asserts expected behavior.
