# SPIRE + Cosmian KMS Integration Test

End-to-end test stack that validates the full SPIRE → Cosmian KMS/auth-verifier integration
described in `documentation/docs/adr/2026-07-26-spire-spiffe-via-vault-api.md`.

The stack is **multi-tenant**: two INDEPENDENT SPIRE deployments (tenants `a` and `b`), each
with its own trust domain, its own AppRole, its own agent, and two Mistral AI agent workloads,
run against the **same** Cosmian KMS. Both tenants sign their own intermediate CA via the KMS
PKI engine, chaining to the same KMS root CA (tag `vault_pki_ca`). This proves the KMS is a
valid multi-tenant Vault upstream authority.

## Architecture

```
                         cosmian-kms:9998  (single, shared)
                         /v1/auth/*  → auth-verifier:8443 (AppRole login, token lookup)
                         /v1/transit/*, /v1/pki/*  → handled natively
                                    ▲                    ▲
              AppRole spire-server-a│                    │AppRole spire-server-b
        ┌───────────────────────────┴──┐      ┌──────────┴───────────────────────┐
        │ tenant a: cosmian-test-a.local│      │ tenant b: cosmian-test-b.local   │
        │ spire-server-a (:8081)        │      │ spire-server-b (:8091)           │
        │   └─ spire-agent-a            │      │   └─ spire-agent-b               │
        │        ├─ mistral-agent-a1    │      │        ├─ mistral-agent-b1       │
        │        └─ mistral-agent-a2    │      │        └─ mistral-agent-b2       │
        └───────────────────────────────┘      └──────────────────────────────────┘
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

> The recommended entry point is `mise run test:spire --variant non-fips`, which builds the
> KMS + auth-verifier, provisions credentials, starts both tenants, runs all four Mistral
> agents, and gates on the SPIRE server logs. The steps below describe the underlying flow.

This creates:
- AppRole `spire-server-a` — SPIRE tenant `a` KeyManager/UpstreamAuthority plugins
- AppRole `spire-server-b` — SPIRE tenant `b` KeyManager/UpstreamAuthority plugins
- AppRole `mistral-agents` — shared role used by the transit smoke test
- CA key pair in KMS tagged `vault_pki_ca` (the shared root both tenants chain to)

### 4. Watch SPIRE start up

```bash
docker compose --profile spire logs -f spire-server-a spire-agent-a
docker compose --profile spire logs -f spire-server-b spire-agent-b
```

A successful startup shows each SPIRE server signing its intermediate CA via the KMS PKI
engine (`POST /v1/pki/...`) and each agent attesting with its one-time join token.

### 5. Verify Mistral agent identities

```bash
docker compose --profile spire logs mistral-agent-a1 mistral-agent-a2 \
                                     mistral-agent-b1 mistral-agent-b2
```

Expected output (tenant `a` agents; tenant `b` uses `cosmian-test-b.local`):
```
[...] [mistral-agent-a1] SPIFFE ID: spiffe://cosmian-test-a.local/mistral-agent
[...] [mistral-agent-a1] PASS: SVID valid until ...
[...] [mistral-agent-a1] === All assertions passed ===
```

## Services

| Service | Port | Purpose |
|---------|------|---------|
| cosmian-auth (host) | 8443 | Vault /v1/auth/* API |
| cosmian-kms (host) | 9998 | Vault /v1/transit/* and /v1/pki/* API (shared by both tenants) |
| spire-server-a | 8081 | SPIRE server, tenant `a` (trust domain `cosmian-test-a.local`) |
| spire-agent-a | — | SPIRE agent, tenant `a` (unix workload attestation) |
| mistral-agent-a1 | — | Simulated Mistral AI agent #1 (tenant `a`) |
| mistral-agent-a2 | — | Simulated Mistral AI agent #2 (tenant `a`) |
| spire-server-b | 8091 | SPIRE server, tenant `b` (trust domain `cosmian-test-b.local`) |
| spire-agent-b | — | SPIRE agent, tenant `b` (unix workload attestation) |
| mistral-agent-b1 | — | Simulated Mistral AI agent #1 (tenant `b`) |
| mistral-agent-b2 | — | Simulated Mistral AI agent #2 (tenant `b`) |

## Test scripts

The `mise run test:spire --variant non-fips` orchestrator runs three layers of assertions
against the live stack:

| Script / step | Purpose |
|---------------|---------|
| `setup/test_vault_api.sh` | Happy-path Vault wire-contract conformance (auth §3, PKI §4, transit §5). |
| SPIRE-server log gate | Fails the run if any SPIRE server logs `level=error`/`level=fatal`. |
| `setup/test_negative_scenarios.sh` | Adversarial / negative scenarios (see `reviews_spire_live.md`): cross-tenant transit isolation (11), proxy path traversal + unauth admin CRUD (9), `secret_id` `num_uses` race (1), exportable bypass + sensitive-key export refusal (5), sign-intermediate input validation (4), revoke-vs-cache trade-off (3), AppRole login fuzzing (8), Kubernetes login rejection (7), delete/recreate lifecycle (12). |
| Inline mise steps | Scenario 6 (transit allow-list + FIPS SKIP note), scenario 10 (bad PKI CA label → clean 5xx), scenario 2 (auth-verifier outage → HTTP 502 + recovery). |

## Gap fixes implemented

| Gap | Status | Description |
|-----|--------|-------------|
| G1 | ✅ | `GET /keys/{name}` now returns `latest_version` + `keys["1"].public_key` PEM |
| G2 | ✅ | `POST /keys/{name}/config` no-op added (SPIRE delete worker) |
| G3 | ✅ | `type` field derived from stored KMIP attributes (not `"unknown"`) |
| G4 | ✅ | `ttl` field parsed and forwarded as `requested_validity_days` to Certify |
| G5 | ✅ | Per-tenant AppRoles: `spire-server-a`, `spire-server-b`, plus `mistral-agents` |

## Troubleshooting

**SPIRE startup fails with "key not found"**  
→ Run the provision script (step 3). SPIRE cannot sign its intermediate CA until
   `provision.sh` has set up the per-tenant AppRole credentials.

**SPIRE server logs an error (log gate fails)**  
→ Inspect the captured logs written by the mise task: `/tmp/spire-server-a.log`,
   `/tmp/spire-server-b.log`. The gate fails on any `level=error`/`level=fatal` line.

**Mistral agent can't get an SVID**  
→ Verify the tenant's SPIRE workload entry is registered (replace `-a` with `-b` for
   tenant `b`):
   `docker compose --profile spire exec spire-server-a /opt/spire/bin/spire-server entry show -socketPath /tmp/spire-server/private/api.sock`
