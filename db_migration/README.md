# SQLite migration fixtures

These databases were populated through the `ckms` and `/kmip/2_1` endpoint of each released `ghcr.io/cosmian/kms` image, plus `junk_*` malformed rows injected via SQL after stopping the server. The generator pins the image digests and verifies the schema, objects, tags, permissions, and migration markers.

From the parent KMS checkout:

```bash
MISE_CONFIG_ROOT="$(pwd)" bash .mise/scripts/test/generate_db_migration_fixtures.sh
```

Pass a version, such as `5.29.0`, to generate just that fixture. The generator refuses to overwrite an existing `kms.db`. To regenerate a fixture, remove only that version's database first. Generation requires Docker and Python 3; it uses randomly assigned loopback host ports and removes its containers and scratch directories on exit.

## Versions and migration steps

| Released image | Database | Steps exercised |
|---|---|---|
| `5.20.0` | [SQLite database](5.20.0/sqlite/kms.db) | Wrapping-key ID backfill at `5.25.0`, then certificate serial-tag backfill at `5.29.0` |
| `5.24.0` | [SQLite database](5.24.0/sqlite/kms.db) | Both steps, immediately before the wrapping-key ID change |
| `5.28.0` | [SQLite database](5.28.0/sqlite/kms.db) | Certificate serial-tag backfill only; the wrapping-key ID marker is already `true` |
| `5.29.0` | [SQLite database](5.29.0/sqlite/kms.db) | No data step; both completion markers and the certificate serial tag are already present |

All four databases are unversioned: none has a `db_version` row. The first two have neither a `wrapping_key_id` column nor its completion marker. Only `5.29.0` has the certificate serial-tag completion marker and `_serial=` tags on `mig_cert` and `bulk_cert_2`.

## Stored data

Every database contains 32 objects owned by `admin`, split into three tiers:

### Migration pain-point objects (`mig` tag, 8 objects)

| Identifier | Object | State |
|---|---|---|
| `mig_kek` | AES-256 wrapping key | Active |
| `mig_wrapped` | AES-256 key wrapped by `mig_kek` | Active |
| `mig_rsa` | RSA-2048 private key | Active |
| `mig_rsa_pk` | Corresponding RSA public key | Active |
| `mig_revoked` | AES-256 key, revoked after creation | Deactivated |
| `mig_cert` | Self-signed X.509 certificate | Active |
| Two release-generated UUIDs | `mig_cert`'s RSA-2048 private and public keys | Active |

### Broad KMS population (`bulk` tag, 19 objects)

- Symmetric keys: `bulk_aes_128`, `bulk_aes_192`, `bulk_aes_256` (also tagged `env:prod/eu` and `émoji-🔐`), `bulk_sym_wrapped` (wrapped by `mig_kek`), and `bulk_wrapped_2` (wrapped by `bulk_aes_256`).
- Asymmetric key pairs: `bulk_rsa_3072` / `bulk_rsa_3072_pk`, `bulk_ec_p256` / `bulk_ec_p256_pk`, `bulk_ec_p384` / `bulk_ec_p384_pk`.
- Other KMIP objects: `bulk_secret_data` (`SecretData`), `bulk_opaque` (`OpaqueObject`), and `bulk_cert_2` (second X.509 certificate plus its two release-generated RSA-2048 key-pair UUIDs).
- Lifecycle states: `bulk_preactive` (`PreActive`), `bulk_compromised` (`Compromised`), and `bulk_destroyed` (`Destroyed`).

### Damaged / junk rows (`junk` tag, 5 objects plus orphan tag and grant)

- `junk_bad_json` (corrupt JSON, also tagged `_cert`), `junk_wrong_shape_json` (valid JSON that is not a KMIP `Object`), `junk_bad_cert_der` (`Object::Certificate` with invalid DER bytes, tagged `_cert`), `junk_non_cert_tagged_cert` (`Object::OpaqueObject` tagged `_cert`), `junk_dangling_wrapped` (wrapped key referencing non-existent `junk_missing_kek`), and orphan rows for `junk_orphan_object` in `tags` and `read_access`.

`mig_user` has `get`, `encrypt`, and `decrypt` access to `mig_kek` and `encrypt` and `decrypt` access to `bulk_aes_256`; `bulk_auditor` has `get` and `locate` access to `bulk_aes_256`. The fixed IDs above are shared across releases; certificate key-pair UUIDs and cryptographic material differ.

Each fixture is a self-contained `VACUUM INTO` copy taken after stopping the server. Only `kms.db` is stored, never WAL or shared-memory sidecars. Tests must copy the database into a temporary directory before opening it.
