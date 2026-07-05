# KMIP Version Matrix — Coverage Rationale

These 153 vectors test a deliberate **subset** of KMIP operations across protocol
versions 1.0–2.1. The purpose is to validate **wire format and enum serialization
compatibility** across versions, not to exhaustively exercise every operation
(that is already covered by the 500+ regression vectors in `test_data/vectors/fips/`
and `test_data/vectors/non-fips/`).

## Test scenario coverage matrix

**153 vectors across 7 KMIP versions and 30 distinct scenarios.**

| # | Scenario | Cat | St | 1.0 | 1.1 | 1.2 | 1.3 | 1.4 | 2.0 | 2.1 |
|---|----------|-----|----|-----|-----|-----|-----|-----|-----|-----|
| 1 | `check` | Gen | 3 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 2 | `query` | Gen | 1 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 3 | `discover_versions` | Gen | 1 | — | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 4 | `get_attributes` | Gen | 4 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 5 | `locate_by_name` | Gen | 3 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 6 | `rng_retrieve` | Gen | 1 | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| 7 | `aes128_cbc` | Sym | 6 | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| 8 | `aes128_ecb` | Sym | 6 | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| 9 | `aes128_gcm` | Sym | 6 | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| 10 | `aes192_cbc` | Sym | 6 | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| 11 | `aes192_gcm` | Sym | 6 | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| 12 | `aes256_cbc` | Sym | 6 | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| 13 | `aes256_ecb` | Sym | 6 | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| 14 | `aes256_gcm` | Sym | 6 | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| 15 | `ec_p256_ecdsa_sign` | AsymS | 9 | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| 16 | `ec_p384_ecdsa_sign` | AsymS | 9 | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| 17 | `rsa2048_pss_sha256_sign` | AsymS | 9 | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| 18 | `rsa2048_sha256_sign` | AsymS | 9 | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| 19 | `rsa2048_oaep_sha256` | AsymE | 9 | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| 20 | `rsa4096_oaep_sha256` | AsymE | 9 | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| 21 | `mac_hmac_sha256` | MAC | 6 | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| 22 | `mac_hmac_sha384` | MAC | 6 | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| 23 | `mac_hmac_sha512` | MAC | 6 | — | — | ✓ | ✓ | ✓ | ✓ | ✓ |
| 24 | `hash_sha256` | Hash | 1 | — | — | — | ✓ | ✓ | ✓ | ✓ |
| 25 | `hash_sha384` | Hash | 1 | — | — | — | ✓ | ✓ | ✓ | ✓ |
| 26 | `hash_sha512` | Hash | 1 | — | — | — | ✓ | ✓ | ✓ | ✓ |
| 27 | `hash_sha3_256` | Hash | 1 | — | — | — | ✓ | ✓ | ✓ | ✓ |
| 28 | `hash_sha3_512` | Hash | 1 | — | — | — | ✓ | ✓ | ✓ | ✓ |
| 29 | `derive_pbkdf2_sha256` | Derive | 6 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| 30 | `derive_hkdf_sha256` | Derive | 6 | — | — | — | — | — | ✓ | ✓ |

> **Categories:** Gen = Generic lifecycle | Sym = Symmetric encrypt/decrypt | AsymS = Asymmetric sign/verify | AsymE = Asymmetric encrypt/decrypt | MAC | Hash | Derive
> **St** = step count per vector (JSON request files)

### Per-version summary

| Version | Vectors | New vs previous |
|---------|---------|-----------------|
| 1.0 | 5 | Foundation: Check, Query, GetAttributes, Locate, PBKDF2 |
| 1.1 | 6 | + DiscoverVersions |
| 1.2 | 24 | + AES-128/192/256 (GCM/CBC/ECB), EC-P256/P384 sign, RSA-2048 OAEP/PSS/PKCS1.5 sign, RSA-4096 OAEP, HMAC-SHA256/384/512, RNGRetrieve |
| 1.3 | 29 | + Hash SHA256/384/512, SHA3-256/512 |
| 1.4 | 29 | (same matrix as 1.3 — wire format unchanged) |
| 2.0 | 30 | + HKDF derivation |
| 2.1 | 30 | (same matrix as 2.0 — wire format unchanged) |

---

## Operations with dedicated version-matrix vectors

| Operation(s) | Why |
|---|---|
| Encrypt / Decrypt (AES-GCM/CBC/ECB) | Validates `BlockCipherMode` enum codes; GCM auth tag handling differs in KMIP ≤1.2 (appended to `Data`) vs 1.3+ (separate `AuthenticatedEncryptionTag` field) |
| Sign / SignatureVerify (EC, RSA) | Validates `DigitalSignatureAlgorithm` enum serialization — this enum was missing from the binary TTLV lookup table (bug found) |
| Hash | Validates `HashingAlgorithm` enum codes — `SHA3256` name collides with `CryptographicAlgorithm::SHA3256` which has a different code (bug found) |
| MAC / MACVerify | Validates `CryptographicAlgorithm` HMAC variant codes in binary TTLV |
| DeriveKey (PBKDF2, HKDF) | Validates `DerivationMethod` enum; HKDF (0x0A) only valid in KMIP 2.0+ |
| Query | Validates server capability reporting per version |
| DiscoverVersions | Validates version negotiation (absent in 1.0) |
| RNGRetrieve | Validates random number generation across wire formats |
| Locate | Validates `Name` attribute query format (TemplateAttribute in 1.x vs Attributes in 2.x) |
| Check | Validates usage limits check across versions |
| GetAttributes | Validates attribute response format differences |

## Operations tested implicitly

These are steps within the lifecycle vectors above, not standalone vectors:

| Operation | Where |
|---|---|
| Create | First step of every symmetric lifecycle vector |
| CreateKeyPair | First step of every asymmetric sign/encrypt vector |
| Get | Used in DeriveKey vectors to fetch the derived key |
| Activate | Step 2 in every lifecycle vector (before cryptographic use) |
| Revoke | Step N-1 in every lifecycle vector |
| Destroy | Last step of every lifecycle vector |

## Operations deliberately omitted

| Omitted | Reason |
|---|---|
| Register, Import, Export | Key import/export format is version-independent; covered by dedicated regression vectors (`import_key`, `register_export`) |
| ReKey, ReKeyKeyPair | Complex multi-step logic with 20+ dedicated regression vectors already |
| Certify, Validate | Certificate chain operations; covered by `certify_validate`, `certify_chain`, `certify_revoke_validate` regression vectors |
| AddAttribute, ModifyAttribute, DeleteAttribute, SetAttribute | Attribute management; covered by the `attribute_management` regression vector |
| GetAttributeList | Covered by the `get_attribute_list` regression vector |
| RNGSeed | Trivial; no version-specific serialization path |

## Bugs found by these vectors

Running this suite against the server uncovered two genuine server bugs in
`crate/kmip/src/ttlv/enum_lookup.rs`:

1. **`DigitalSignatureAlgorithm` not in forward/reverse lookup tables** — all
   Sign/SignatureVerify vectors for KMIP 1.2–1.4 binary mode failed with
   `"invalid value: integer 0, expected valid DigitalSignatureAlgorithm value"`.
   The enum was not registered in `insert_forward!` / `insert_reverse!`.

2. **`HashingAlgorithm` SHA3 name collision** — `"SHA3256"` appears in both
   `CryptographicAlgorithm` (code 0x20) and `HashingAlgorithm` (code 0x0F).
   The global lookup table returned the wrong code. Fixed by adding a
   tag-aware lookup function (`lookup_enum_code_for_tag`) with a per-tag
   override table.

Two test vector corrections were also made:

- **HKDF not valid in KMIP < 2.0** — `DerivationMethod::HKDF` (0x0A) was added
  in KMIP 2.0; pre-2.0 vectors now use PBKDF2 only.

- **KMIP ≤1.2 GCM auth tag** — `AuthenticatedEncryptionTag` did not exist as a
  separate response field until KMIP 1.3. The server correctly concatenates it
  to `Data` for ≤1.2 responses; vectors for those versions no longer try to
  capture it as a separate field.
