# Security Policy

Report suspected vulnerabilities privately to the maintainers. Do not include keys, invitation tickets, decrypted records, or production database archives in an issue.

## Release Checklist

- Run format, strict Clippy, all workspace tests, documentation, MSRV, and dependency/advisory checks.
- Replay every retained fuzz corpus, inspect the latest scheduled mutation
  artifacts, and run the exact-duration reconnect/partition/restart soak.
  Production qualification uses
  `IROH_DB_SOAK_DURATION_SECS=259200`; accelerated rounds are not equivalent
  evidence.
- Minimize every crashing fuzz input, fix it without weakening strict
  validation, and promote the minimized input into `fuzz/corpus/<target>/`
  before closing the regression.
- Review every package-scoped license or advisory exception in `deny.toml`;
  exceptions must identify an exact package/version or advisory ID, explain the
  current upstream path, and be removed as soon as it no longer applies.
- Review changes to signature contexts, canonical codecs, AEAD nonce/AAD construction, capability narrowing, control succession, epoch cuts, invitation targeting, and bounded protocol inputs.
- Confirm secrets remain redacted and key-vault files are owner-only after create, backup, and restore.
- Confirm repair and restore use a new/in-memory candidate and never overwrite the only known-good copy before verification.
- Confirm gossip and errors contain no keys, capabilities, record identifiers, collection values, or plaintext.

The confidentiality boundary excludes compromised unlocked devices, traffic analysis, denial of service, and plaintext already obtained by a previously authorized member.
