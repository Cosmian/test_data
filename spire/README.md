# SPIRE + Cosmian KMS Integration Test

End-to-end test stack that validates the full SPIRE → Cosmian KMS/auth-verifier integration
described in `documentation/docs/adr/2026-07-26-spire-spiffe-via-vault-api.md`.

## Architecture

```
SPIRE plugins ─────► nginx proxy (vault-proxy:8200)
                          │
               ┌──────────┴──────────────────┐
               ▼                             ▼
  auth-verifier:8443             cosmian-kms:9998
  /v1/auth/approle/*             /v1/transit/*
  /v1/auth/token/*               /v1/pki/*
```

## Quick start

### 1. Generate test TLS certificates

```bash
bash tests/spire/certs/generate-test-certs.sh
```

### 2. Start the stack

```bash
docker compose -f tests/spire/docker-compose.yml up -d
```

Wait for all services to become healthy:

```bash
docker compose -f tests/spire/docker-compose.yml ps
```

### 3. Provision credentials (run once)

```bash
docker compose -f tests/spire/docker-compose.yml \
  exec cosmian-auth bash /setup/provision.sh
```

This creates:
- AppRole `spire-server` — dedicated role for SPIRE's KeyManager and UpstreamAuthority plugins
- AppRole `mistral-agents` — dedicated role for Mistral AI agent workloads
- CA key pair in KMS tagged `vault_pki_ca`

### 4. Watch SPIRE start up

```bash
docker compose -f tests/spire/docker-compose.yml logs -f spire-server spire-agent
```

A successful startup shows SPIRE registering its transit key with the KMS, then fetching
the public key via `GET /v1/transit/keys/<key-name>`.

### 5. Verify Mistral agent identities

```bash
docker compose -f tests/spire/docker-compose.yml logs mistral-agent-1 mistral-agent-2
```

Expected output (each agent):
```
[...] [mistral-agent-1] SPIFFE ID: spiffe://cosmian-test.local/mistral-agent
[...] [mistral-agent-1] PASS: SVID valid until ...
[...] [mistral-agent-1] === All assertions passed ===
```

## Services

| Service | Port | Purpose |
|---------|------|---------|
| postgres | 5432 | Shared DB for auth-verifier and KMS |
| cosmian-auth | 8443 | Vault /v1/auth/* API |
| cosmian-kms | 9998 | Vault /v1/transit/* and /v1/pki/* API |
| vault-proxy | 8200 | nginx — single `vault_addr` for SPIRE |
| spire-server | 8081 | SPIRE server (gRPC) |
| spire-agent | — | SPIRE agent (unix workload attestation) |
| mistral-agent-1 | — | Simulated Mistral AI agent #1 |
| mistral-agent-2 | — | Simulated Mistral AI agent #2 |

## Gap fixes implemented

| Gap | Status | Description |
|-----|--------|-------------|
| G1 | ✅ | `GET /keys/{name}` now returns `latest_version` + `keys["1"].public_key` PEM |
| G2 | ✅ | `POST /keys/{name}/config` no-op added (SPIRE delete worker) |
| G3 | ✅ | `type` field derived from stored KMIP attributes (not `"unknown"`) |
| G4 | ✅ | `ttl` field parsed and forwarded as `requested_validity_days` to Certify |
| G5 | ✅ | Two separate AppRoles: `spire-server` and `mistral-agents` |

## Troubleshooting

**SPIRE startup fails with "key not found"**  
→ Run the provision script (step 3). SPIRE cannot create its own transit key until
   `provision.sh` has set up AppRole credentials.

**nginx `502 Bad Gateway`**  
→ Check that `cosmian-auth` and `cosmian-kms` are healthy before vault-proxy starts:
   `docker compose -f tests/spire/docker-compose.yml ps`

**Mistral agent can't get an SVID**  
→ Verify the SPIRE workload entry is registered:
   `docker compose exec spire-server /opt/spire/bin/spire-server entry show`
   See the workload registration commands printed by `provision.sh`.
