# Database migration fixtures

These databases were populated through the `ckms` bundled with each released `ghcr.io/cosmian/kms` image. The `5.14.0` image ships no `ckms`, so the `ckms` of the pinned `5.20.0` image populates it. The generator pins the KMS and database image digests and verifies the schema, objects, tags, permissions, and migration markers.

From the parent KMS checkout:

```bash
MISE_CONFIG_ROOT="$(pwd)" bash .mise/scripts/test/generate_db_migration_fixtures.sh \
  [sqlite|postgresql|mysql|all] [VERSION]
```

The backend defaults to `all`. Pass a version as the second argument, such as
`sqlite 5.29.0`, to generate only that fixture. The generator refuses to
overwrite an existing `kms.db` or `dump.sql`. To regenerate a fixture, remove
only that file first. Generation requires Docker, plus Python 3 for SQLite.
Every container joins a Docker network created for the run, and the generator
removes its containers, network, and scratch directory on exit.

## Versions and migration steps

| Released image | SQLite | PostgreSQL | MySQL | Steps exercised |
|---|---|---|---|---|
| `5.14.0` | — | [dump](5.14.0/postgresql/dump.sql) | — | `json` to `jsonb` attributes conversion at `5.15.0`, then the two steps below |
| `5.20.0` | [database](5.20.0/sqlite/kms.db) | [dump](5.20.0/postgresql/dump.sql) | [dump](5.20.0/mysql/dump.sql) | Wrapping-key ID backfill at `5.25.0`, then certificate serial-tag backfill at `5.29.0` |
| `5.24.0` | [database](5.24.0/sqlite/kms.db) | [dump](5.24.0/postgresql/dump.sql) | [dump](5.24.0/mysql/dump.sql) | Both backfills, immediately before the wrapping-key ID change |
| `5.28.0` | [database](5.28.0/sqlite/kms.db) | [dump](5.28.0/postgresql/dump.sql) | [dump](5.28.0/mysql/dump.sql) | Certificate serial-tag backfill only; the wrapping-key ID marker is already `true` |
| `5.29.0` | [database](5.29.0/sqlite/kms.db) | — | — | No data step; both completion markers and the certificate serial tag are already present |

The `5.20.0`, `5.24.0`, `5.28.0`, and `5.29.0` SQLite databases are
unversioned: none has a `db_version` row. The `5.20.0` and `5.24.0`
databases have neither a `wrapping_key_id` column nor its completion marker.
Only the `5.29.0` SQLite database has the certificate serial-tag completion
marker and a `_serial=` tag on `mig_cert`.

The `5.14.0` PostgreSQL database is versioned below the `5.20.0` baseline: it
records `db_version = 5.14.0` and `db_state = "ready"`, stores `attributes` as
`json`, and has no `wrapping_key_id` column. Only PostgreSQL has a step older
than `5.20.0`, so `5.14.0` exists for PostgreSQL alone. No PostgreSQL or MySQL
fixture has the certificate serial-tag completion marker or a `_serial=` tag on
`mig_cert`. On PostgreSQL, every fixture except `5.14.0` already stores
`attributes` as `jsonb`.

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

`mig_user` has `get`, `encrypt`, and `decrypt` access to `mig_kek`. The fixed IDs above are shared across releases and backends; certificate key-pair UUIDs and cryptographic material differ.

## SQLite databases

Each SQLite fixture is a self-contained `VACUUM INTO` copy taken after stopping the server. Only `kms.db` is stored, never WAL or shared-memory sidecars. Tests must copy the database into a temporary directory before opening it.

## PostgreSQL and MySQL dumps

The servers run `postgres:18` and `mysql:8.0`. Each dump is taken after stopping the KMS server, then restored into a fresh server of the same image and checked before it is written.

- PostgreSQL: `pg_dump --no-owner --no-privileges --inserts`. `pg_dump` 17.6 and later bracket the dump in `\restrict` and `\unrestrict` psql meta-commands, which no SQL driver can execute: the generator deletes them and fails on any other line starting with `\`. The dump sets `search_path` to an empty string, so restore it on a dedicated connection, never on a pooled one.
- MySQL: `mysqldump --no-tablespaces --skip-add-locks --skip-lock-tables --skip-comments --set-gtid-purged=OFF`. Percona XtraDB Cluster rejects `LOCK TABLES` with `pxc_strict_mode = ENFORCING`. The dumps restore unchanged on MySQL 8.0, MariaDB 11.4, and Percona XtraDB Cluster 8.0 with `pxc_strict_mode = ENFORCING`.
