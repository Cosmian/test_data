# Apple SCEP capture: macOS 26.6.2 (25G83)

Captured on 2026-10-16 by `mise run test:scep-apple` from the native macOS SCEP client
(`com.apple.security.scep` payload, see `enroll.mobileconfig`).

- `ca.crt`, `ca.key`: throwaway test CA the requests are encrypted to. Test-only, never trust it.
- `pkcsreq.der`: signed `pkiMessage` (`PKCSReq`, challenge `SecretChallenge123`, CN `mac-01.iot.example`).
- `renewal.der` (if present): what Apple sends on `profiles renew -type configuration`.
- CAFingerprint algorithm: sha256; content encryption: aes-128-cbc.
- Renewal observation: inconclusive. `sudo profiles renew -type configuration -identifier <id>`
  produced no SCEP traffic within 1800s; the only `profiles` log entry was an XPC
  `GetManagementStatus ... Sandbox restriction` error. Renewal for a manually installed profile is
  not established; the step is now opt-in (`SCEP_APPLE_RENEW=1`).

Parsed by `apple_scep_fixtures_parse` in `crate/server/src/tests/enrollment_tests.rs`.
