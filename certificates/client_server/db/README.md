# mTLS Database Testing Setup

This directory contains real mTLS integration tests for PostgreSQL and MySQL database connections.

## What Has Been Implemented

### 1. Certificate Generation (`test_data/certificates/client_server/db/`)
- Created `generate_certs.sh` script to generate database mTLS certificates
- Uses the existing CA from `../ca/` to sign certificates
- Generates for both PostgreSQL and MySQL:
  - Server certificates (postgres-server.{key,crt}, mysql-server.{key,crt})
  - Client certificates (postgres-client.{key,crt}, mysql-client.{key,crt})
  - MySQL PKCS12 bundle (mysql-client.p12) for native-tls

### 2. Docker Compose Services (`docker-compose.yml`)
Added two new services:
- **postgres-mtls**: PostgreSQL 18 with TLS enabled on port 5433
  - Configured with `ssl=on`, `ssl_cert_file`, `ssl_key_file`, `ssl_ca_file`
  - Requires client certificates for authentication
  
- **mysql-mtls**: MySQL latest with TLS enabled on port 3309
  - Configured with `--require-secure-transport=ON`
  - SSL certificates mounted from test_data

### 3. mTLS Implementation

#### PostgreSQL (`crate/server_database/src/stores/sql/pgsql.rs`)
- Modified `instantiate()` to parse TLS parameters from URL
- Strips custom SSL parameters (`sslrootcert`, `sslcert`, `sslkey`) before passing to deadpool-postgres
- Builds OpenSSL `SslConnector` with:
  - CA certificate verification
  - Client certificate for mTLS
  - Verification mode based on `sslmode` parameter
- URL format: `postgres://user:pass@host:port/db?sslmode=verify-ca&sslrootcert=/path/to/ca.crt&sslcert=/path/to/client.crt&sslkey=/path/to/client.key`

#### MySQL (`crate/server_database/src/stores/sql/mysql.rs`)
- URL-driven TLS configuration via native-tls
- Supports parameters: `ssl-mode`, `ssl-ca`, `ssl-client-identity`, `ssl-client-identity-password`
- Uses PKCS12 format for client certificates (native-tls requirement)
- URL format: `mysql://user:pass@host:port/db?ssl-mode=VERIFY_CA&ssl-ca=/path/to/ca.crt&ssl-client-identity=/path/to/client.p12&ssl-client-identity-password=secret`

### 4. Integration Tests (`crate/server/src/tests/mtls_db.rs`)
- `test_postgresql_mtls_connection()`: Tests PostgreSQL mTLS via KMS instantiation
- `test_mysql_mtls_connection()`: Tests MySQL mTLS via KMS instantiation
- Both tests are marked with `#[ignore]` and require Docker services running

## Running the Tests

### 1. Generate Certificates
```bash
cd test_data/certificates/client_server/db
./generate_certs.sh
```

### 2. Start Database Services
```bash
docker compose up -d postgres-mtls mysql-mtls
```

### 3. Run Tests
```bash
# PostgreSQL mTLS test
cargo test --package cosmian_kms_server --lib test_postgresql_mtls_connection -- --ignored --nocapture

# MySQL mTLS test
cargo test --package cosmian_kms_server --lib test_mysql_mtls_connection -- --ignored --nocapture
```

## Technical Details

### PostgreSQL TLS Implementation
- Uses `postgres-openssl` crate for TLS support
- Parses custom URL parameters for certificate paths
- Creates clean URL (without cert paths) for deadpool-postgres
- Configures TLS via `MakeTlsConnector` with OpenSSL `SslConnector`
- Supports all PostgreSQL `sslmode` values: disable, prefer, require, verify-ca, verify-full

### MySQL TLS Implementation
- Uses `mysql_async` with `native-tls-tls` feature
- native-tls wraps system OpenSSL (FIPS-compatible)
- Requires PKCS12 format for client certificates (not PEM)
- Supports `ssl-mode`: DISABLED, PREFERRED, REQUIRED, VERIFY_CA, VERIFY_IDENTITY
- Alternative underscore syntax: `ssl_mode`, `ssl_ca`, etc.

### Certificate Formats
- **PostgreSQL**: PEM format for all certificates (ca.crt, client.crt, client.key)
- **MySQL**: PEM for CA, PKCS12 for client identity (includes cert + key)

## Known Limitations

1. The tests currently have a configuration issue with `ServerParams::try_from` that needs to be resolved
2. Tests are marked as ignored and need manual execution
3. Certificate generation requires OpenSSL (not LibreSSL on macOS)

## Future Work

- Resolve ServerParams configuration validation
- Add certificate rotation tests
- Test with different SSL verification modes
- Add performance benchmarks for TLS vs non-TLS
