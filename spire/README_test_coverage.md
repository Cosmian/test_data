# KMS Test Coverage Mapping

This document maps every test case from the
**Aembit Capability Validation Test Plan** to its coverage status in this repository.

Quick command reference:
```bash
# Run all KMS-owned PKI tests (standalone):
mise run test:spire-pki

# Run PKI tests as part of the full SPIRE integration suite (step 16):
mise run test:spire

# Run KMS algorithm policy unit tests:
cargo test -p cosmian_kms_server -- kmip_policy
```

---

## Section 2 — PKI Integration & Certificate Lifecycle

| Test ID | Objective | Priority | KMS Coverage | File / Step |
|---------|-----------|----------|--------------|-------------|
| **PKI-01** | External Root CA integration | High | ✅ Existing | `mise run test:spire` step 5 (`self_signed=false` log gate) + `test_vault_api.sh §4` |
| **PKI-02** | Private key handling (never leaves origin) | High | ✅ Existing | SPIRE KeyManager `"memory"` (architectural); Scenario 5 (Sensitive export denied) |
| **PKI-06** | Self-signed certificate prohibition | High | ✅ **New** (M-01) | `test_pki.sh` M-01 — pathlen:0 verified on all issued intermediates |
| **PKI-03** | Client/server certificate parity | Medium | ✅ Existing | Architectural: every SPFFE SVID uses the same `Certify`/`ReCertify` path regardless of TLS role |
| **PKI-04** | Zero-downtime trust bundle rotation | High | ✅ **New** (M-04) | `test_pki.sh` M-04 — new CA key created, old CA continues signing during overlap |
| **PKI-05** | Crypto agility — centrally configured algorithms | Medium | ✅ Existing | `cargo test -p cosmian_kms_server -- kmip_policy` (basic, e2e_signature, overrides) |
| **PKI-07** | Approved algorithm restriction | High | ✅ Existing | `mise run test:spire` step 13 (bogus transit key type → 4xx) + unit tests above |
| **PKI-08** | Storage policy enforcement | Medium | ✅ Existing | `mise run test:spire` step 12 Scenario 5 (Sensitive key export denied) |
| **PKI-09** | PAM integration for long-lived secrets | Medium | 🔶 Joint workshop | Requires live Segura instance; see `client.txt` I-3 for integration design |
| **PKI-10** | Service mesh SDS delivery | Medium | 🔶 Aembit/Envoy | Envoy SDS is the delivery layer; KMS provides the SVID via SPIRE |
| **PKI-11** | TLS 1.3 enforcement | High | ✅ **New** (M-02) | `test_pki.sh` M-02 — TLS 1.2 curl → connection failure |
| **PKI-12** | Algorithm policy change without redeploy | High | ✅ **New** (M-03) | `test_pki.sh` M-03 — second KMS with restricted allowlist, P-256 → 4xx, P-384 → 200 |
| **PKI-13** | Documented PKI responsibility split | High | 📄 Documentation | See `client.txt` PKI-2 section (written answer) |
| **PKI-14** | Programmatic Intermediate CA issuance/renewal | High | ✅ Existing | `mise run test:spire` step 5 (`sign-intermediate` via Vault REST API, no manual step) |
| **PKI-16** | Automated trust bootstrapping | High | ✅ Existing | `mise run test:spire` steps 1–9 (full automated provision from zero) |
| **PKI-17** | Trust re-establishment | High | ✅ **New** (M-05) | `test_pki.sh` M-05 — AppRole secret_id expired → new secret_id → fresh login succeeds |

---

## Section 1 — Workload Identity Foundation

| Test ID | Objective | Priority | Coverage |
|---------|-----------|----------|----------|
| WI-01 | Multi-platform SVID issuance | High | 🔶 Aembit — requires multi-cloud SPIRE deployment |
| WI-02 | Workload attestation coverage | High | 🔶 Aembit — PSAT/MSI/IID attestors |
| WI-03 | Trust domain interoperability | High | 🔶 Aembit — SPIFFE federation |
| WI-04 | Credential rotation under load | High | 🔶 Aembit — SPIRE built-in rotation at 50% TTL |
| WI-05 | Revocation propagation | Medium | ✅ Existing (partial) — `test_negative_scenarios.sh` Scenario 3 (token revocation cache); short-lived SVIDs (1h TTL) are the revocation mechanism |
| WI-06 | Dual credential type (X.509 + JWT) | High | ✅ Existing — `mise run test:spire` step 10 issues both X.509-SVID and JWT-SVID per workload |
| WI-07 | Node attestation per platform | High | 🔶 Aembit — requires K8s/Azure/AWS/on-prem nodes |
| WI-08 | Cloud IdP federation (Entra ID) | High | 🔶 Aembit — Entra ID Workload Identity Federation |
| WI-09 | High availability | High | 🔶 Aembit/KMS joint — KMS HA: `mise run test:spire` Scenario 2 (auth-verifier outage → 502); full SPIRE HA requires cloud infra |
| WI-10 | Identity namespacing per environment | Medium | ✅ Existing — `mise run test:spire` (two tenant trust domains A and B, isolated namespaces) |

---

## Sections 3–7 — Token Security, NHI Governance, AI Identity, Migration, SDK

All test cases in these sections are **Aembit's responsibility**.  The KMS provides
key material and certificate lifecycle; Aembit provides DPoP, token exchange, NHI
discovery, AI agent authorization, M2M SDK, and migration tooling.

---

## Section 8 — Observability & Monitoring

| Test ID | Objective | Priority | Coverage |
|---------|-----------|----------|----------|
| OBS-01 | Prometheus / OTel metrics export | Medium | ✅ Existing — `mise run test:otel`; KMS exports `/metrics` (Prometheus) and OTLP |
| OBS-02 | Distributed tracing | Low | 🔶 Aembit — correlation across Aembit + KMS requires Aembit tracing layer |
| OBS-03 | Alerting on issuance failures | Medium | 🔶 Aembit — alerting is in the Aembit/Grafana/OBSERVEIAM layer |
| OBS-04 | Structured logging | Medium | ✅ Existing — KMS emits structured JSON logs via cosmian_logger; format verified by log gate in `mise run test:spire` step 11 |
| OBS-05 | Issuance latency < 500 ms (NFR-2) | High | ✅ **New** (M-06) | `test_pki.sh` M-06 — 5× timed `sign-intermediate` calls, each < 500ms |

---

## Section 9 — Protocol Coverage Beyond HTTP

| Test ID | Objective | Priority | Coverage |
|---------|-----------|----------|----------|
| PROTO-01 | gRPC | High | ✅ Existing — SPIRE Server↔Agent is gRPC/mTLS (demonstrated in `mise run test:spire`) |
| PROTO-02 | Message queue / event streaming | Medium | 📄 Documentation — Not KMS scope; Aembit/Kafka mTLS with SPIFFE SVIDs |
| PROTO-03 | Database connections | Medium | 📄 Documentation — mTLS for DB is application-layer; SVID delivered by SPIRE |

---

## Section 10 — Resilience, Disaster Recovery & Compliance

| Test ID | Objective | Priority | Coverage |
|---------|-----------|----------|----------|
| RES-01 | Disaster recovery drill (RTO/RPO) | High | 🔶 Infra — KMS HA architecture is documented (RPO <1h, RTO <4h); full DR drill requires multi-region infra |
| RES-02 | Third-party security certification | High | 📄 Documentation — ISO 27001 / TISAX / SOC 2 evidence provided separately |
| RES-03 | Multi-region data residency | Medium | 📄 Documentation — separate regional KMS deployments (one per segment, per T-20 fix) |
| RES-04 | Scale and throughput | High | ✅ Existing — `mise run bench` (load tests); transit signing: >1,000 req/s per KMS node |
| RES-05 | Uptime SLA evidence | High | 📄 Documentation — contractual SLA provided separately |
| RES-06 | No-plaintext-secrets verification | High | ✅ Existing — `test_negative_scenarios.sh` Scenario 5 (Sensitive key export blocked; KMIP export denied) |
| RES-07 | Audit log retention | Medium | 📄 Documentation — configurable; OTel/stdout shipped to OBSERVEIAM for ≥12-month retention |
| RES-08 | Backwards compatibility / phased migration | High | ✅ **New** (M-08) | `test_pki.sh` M-08 — legacy + SPIFFE keys coexist in same KMS namespace |
| RES-09 | Vendor neutrality / portability | Medium | ✅ Existing — SPIFFE/KMIP 2.1 open standards; no proprietary SVID format |

---

## Section 11 — Informational Appendix (Not Scored)

| Ref | Question | Answer |
|-----|----------|--------|
| INFO-1 | RFC 8705 mTLS certificate-bound tokens (distinct from DPoP)? | **Not implemented in KMS.** This is an OAuth AS feature (GAS/PingFederate). KMS manages the mTLS certificate lifecycle via SPIRE; certificate-binding of tokens is done at the authorization server layer. |
| INFO-2 | Independent signing key lifecycle for message-signing keys? | **Yes.** KMS manages DPoP/message-signing key pairs via KMIP `CreateKeyPair` / `ReKeyKeyPair` / `Revoke` / `Destroy` on `/kmip/2_1`. These are completely separate from workload SVID transit keys. Demonstrated in `test_pki.sh` M-07. |
| INFO-3 | Intermediate CA segmentation by platform, region, environment? | **Yes — as separate KMS deployments** (one KMS = one `vault_pki_ca_key_label`). Recommended topology: 6–9 KMS HA clusters (`prod-eu`, `prod-us`, `prod-apac`, `staging-eu`, …). Segmentation axes are orthogonal and independently configurable. |
| INFO-4 | Multi-agent orchestration (AI agent invokes another)? | Each AI agent receives its own SPIFFE SVID (unique identity). Agent-to-agent calls are mTLS-authenticated using independent SVIDs. Delegation chain preservation (OAuth Token Exchange `act` claims) is Aembit's layer. |
| INFO-5 | Algorithm policy propagation time? | **≤ 1 hour** — bounded by the SVID TTL (default 1h). Policy takes effect immediately for new key creations; existing SVIDs expire and are re-issued (with the new algorithm constraints) within one rotation cycle. No workload restart needed. |
| INFO-6 | Post-quantum / hybrid algorithm support? | **Pure PQC:** ML-DSA-65 (FIPS 204) transit key type + pure ML-DSA/SLH-DSA/ML-KEM X.509 certs (RFC 9881/9909/9935/9608) — available today in non-FIPS mode. **Composite/hybrid certs** (e.g. ECDSA+ML-DSA in one cert) are **NOT yet supported** — roadmap item pending IETF composite-sigs RFC finalisation. **Hybrid TLS KEM** (ML-KEM + ECDH) is a TLS-stack concern (Envoy/BoringSSL), outside KMS scope. |

---

## New Tests Summary

| Scenario | Test ID Covered | Location |
|----------|-----------------|----------|
| M-01 | PKI-06 | `test_data/spire/setup/test_pki.sh` |
| M-02 | PKI-11 | `test_data/spire/setup/test_pki.sh` |
| M-03 | PKI-12 | `test_data/spire/setup/test_pki.sh` |
| M-04 | PKI-04 | `test_data/spire/setup/test_pki.sh` |
| M-05 | PKI-17 | `test_data/spire/setup/test_pki.sh` |
| M-06 | OBS-05 | `test_data/spire/setup/test_pki.sh` |
| M-07 | INFO-2 | `test_data/spire/setup/test_pki.sh` |
| M-08 | RES-08 | `test_data/spire/setup/test_pki.sh` |

How to run:
```bash
# Standalone (starts its own KMS + auth-verifier):
mise run test:spire-pki

# As part of full SPIRE test suite (step 16, reuses running servers):
mise run test:spire
```
