# SQLite migration fixtures

These databases were populated through the `ckms` bundled with each released `ghcr.io/cosmian/kms` image. The generator pins the image digests and verifies the schema, objects, tags, permissions, and migration markers.

From the parent KMS checkout:

```bash
MISE_CONFIG_ROOT="$(pwd)" bash .mise/scripts/test/generate_db_migration_fixtures.sh
```

The generator refuses to overwrite an existing `kms.db`. To regenerate a fixture, remove only that version's database first. Generation requires Docker and Python 3; it uses randomly assigned loopback host ports and removes its containers and scratch directories on exit.

## Versions and migration steps

| Released image | Database | Steps exercised |
|---|---|---|
| `5.20.0` | [SQLite database](5.20.0/sqlite/kms.db) | Wrapping-key ID backfill at `5.25.0`, then certificate serial-tag backfill at `5.29.0` |
| `5.24.0` | [SQLite database](5.24.0/sqlite/kms.db) | Both steps, immediately before the wrapping-key ID change |
| `5.28.0` | [SQLite database](5.28.0/sqlite/kms.db) | Certificate serial-tag backfill only; the wrapping-key ID marker is already `true` |

All three databases are unversioned: none has a `db_version` row. The first two have neither a `wrapping_key_id` column nor its completion marker. None has the certificate serial-tag completion marker or a `_serial=` tag on `mig_cert`.

## Stored data

Every database contains eight objects owned by `admin`, all tagged `mig`:

| Identifier | Object | State |
|---|---|---|
| `mig_kek` | AES-256 wrapping key | Active |
| `mig_wrapped` | AES-256 key wrapped by `mig_kek` | Active |
| `mig_rsa` | RSA-2048 private key | Active |
| `mig_rsa_pk` | Corresponding RSA public key | Active |
| `mig_revoked` | AES-256 key, revoked after creation | Deactivated |
| `mig_cert` | Self-signed X.509 certificate | Active |
| Two release-generated UUIDs | Certificate's RSA-2048 private and public keys | Active |

`mig_user` has `get`, `encrypt`, and `decrypt` access to `mig_kek`. The fixed IDs above are shared across releases; certificate key-pair UUIDs and cryptographic material differ.

Each fixture is a self-contained `VACUUM INTO` copy taken after stopping the server. Only `kms.db` is stored, never WAL or shared-memory sidecars. Tests must copy the database into a temporary directory before opening it.
