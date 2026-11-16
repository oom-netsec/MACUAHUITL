# Security policy

## Promises

MACUAHUITL makes four promises that anyone can verify with the [auditor's guide](docs/security/AUDIT_GUIDE.md):

1. No credential is ever written to disk in clear text.
2. No vault credential appears in logs, the audit log, outputs, error messages or memory dumps. Secrets that devices print inside the evidence (configuration, logs, terminal recordings) are masked; masking has documented limits, listed in the notes of the [latest release](https://github.com/oom-netsec/MACUAHUITL/releases/latest) and in the [threat model](docs/security/THREAT_MODEL.md).
3. The app only connects to destinations the engineer typed. No telemetry, no update checks.
4. The master password is never stored. If it is lost, the vault cannot be recovered, by design.

The known limits of these promises are declared in the [threat model](docs/security/THREAT_MODEL.md#declared-limits).

## Supported versions

Only the [latest release](https://github.com/oom-netsec/MACUAHUITL/releases/latest) receives security fixes. Update before you report a problem, and check that it still happens.

## Verify a release

Every release ships a `SHA256SUMS` file. In the folder you downloaded to:

```sh
sha256sum -c --ignore-missing SHA256SUMS
```

`SHA256SUMS` catches a broken download. To check that a file was built by this repository's release workflow (from v0.7.0 on), verify its signed provenance with the [GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify macuahuitl_*.deb --repo oom-netsec/MACUAHUITL \
  --signer-workflow oom-netsec/MACUAHUITL/.github/workflows/release.yml
```

It works the same for the `.rpm`, the binaries and the packs published with each core release; packs-only releases rely on the pack signature. Official content packs are signed with Ed25519: the core refuses a pack with an invalid signature and an unsigned `oom/*` pack, and installs an unsigned third-party pack only after you confirm it.

## Report a vulnerability

Do not open a public issue. Use GitHub's private vulnerability reporting in this repository (*Security → Report a vulnerability*).

Include the version, steps to reproduce and the impact. We answer within 7 days.
