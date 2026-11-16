# Threat model

Reference: [architecture design](../architecture/2026-11-02-macuahuitl-architecture-design.md), §10–§12.

## Assets

| Asset | Where it lives | Impact if leaked |
|---|---|---|
| Device credentials | Encrypted `vault.mcv`; plaintext only in memory during authentication | Administrative access to the customer's network |
| DEK (data key) | Locked core memory while the vault is open or armed | Decrypts all credentials |
| Master password | Only in memory during `Unlock`, `Create` and `ChangeMasterPassword` | Same as the DEK |
| Outputs | Folder chosen by the engineer, with or without masking | Customer configuration, and secrets if masking is off or misses a format |
| Audit log | Local SQLite | Loss of traceability |

## Actors

| Actor | Assumed capability |
|---|---|
| Laptop thief | Access to the powered-off disk |
| Malware running as another user's UID | May try to connect to the socket or read files |
| Malware running as the engineer's UID | Same as the engineer, while it runs |
| Man in the middle | Intercepts or spoofs SSH/HTTPS to devices |
| Compromised dependency | Malicious code in a library |
| External auditor | Reads the code, builds it and observes execution |

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Disk theft | Vault encrypted with Argon2id + AES-256-GCM; the DEK never touches disk in plaintext |
| Brute force of the master password | Argon2id calibrated to ~1 s, 256 MiB of memory |
| Tampering with the vault file | AES-GCM with associated data (vault ID, entry ID, version) |
| Another local user uses the socket | 0600 permissions and `SO_PEERCRED` UID check |
| Core memory dump | `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0` |
| Secret in a log by accident | `Secret` type with redaction in every formatter; no-leak test with a marker password |
| Connection to an unauthorized destination | `noegress` in CI, `EgressGuard` at runtime, no telemetry or update checks |
| SSH spoofing | Trust on first use with confirmation; a changed key blocks by default |
| External tool used to exfiltrate | Validated arguments, no shell, no options that read destinations from files or scripts; everything in the audit log |
| Compromised dependency | `govulncheck` in CI, SBOM, versions pinned in `go.sum`, reproducible build |
| Configuration command in a collection | Per-platform denylist in `internal/playbook` |

## Declared limits

These are the things MACUAHUITL does **not** guarantee. They are declared so that nobody assumes them.

1. **Password copy in `x/crypto/ssh`.** The SSH library receives the password as a Go `string`, which cannot be erased. It is created at the moment it is sent, once per connection, and lives until the garbage collector frees it. A private SSH key, if used, stays parsed in normal memory for the length of the session.
2. **Swap and hibernation.** The core tries `mlockall`, but if it fails, the operating system could write memory containing secrets to swap or to the hibernation image. The core warns if unencrypted swap or hibernation is active.
3. **Malware running as the engineer's UID.** While the vault is open or armed, a process of the same user can debug the core or use the socket. No user application can defend itself from its own user.
4. **Local rewrite of the audit log.** The hash chain detects accidental damage. Whoever controls the user can rewrite the whole chain. The anchor in each `manifest.json` protects what has already been delivered to third parties.
5. **"Accept changed host keys" checkbox.** If the engineer ticks it on a job, a man in the middle could receive the credential. Each acceptance is recorded in the audit log and in the manifest.
6. **Masking off.** If the engineer turns masking off, the outputs contain the devices' secrets.
7. **DEK in memory during armed windows.** Up to 96 h with the DEK in core memory.
8. **Static network analysis.** `noegress` checks the imports of our own code, not those of dependencies, nor calls such as `os.StartProcess`. A malicious dependency could open connections. Mitigation: minimal dependencies, `govulncheck`, SBOM and the runtime observation in the audit guide.
9. **Deletion or rollback of vault entries.** Whoever has disk access can delete an entry or revert it to its `vault.mcv.bak` version without detection. They cannot read it or move it to another position.
10. **Expanded AES key in normal memory.** `crypto/aes` copies the key into its own structure (expanded rounds and GHASH table) in garbage-collected memory, which is not locked and cannot be erased. It applies to the KEK during each derivation and to the DEK while the vault is open or armed. Mitigation: a single expansion of the DEK per DEK lifetime (not one per operation), `PR_SET_DUMPABLE=0` and limits 2 and 3.
11. **Masking is best effort.** Masking recognizes the secret formats it knows. A format it does not know, an abbreviation it does not expand or an echo it does not follow stays in clear text in the outputs and terminal recordings. The known gaps are listed in the notes of each [release](https://github.com/oom-netsec/MACUAHUITL/releases/latest). In the terminal, a password prompt is recognized by the text before it (`Password:`, `Secret:` and similar): a secret typed at a prompt it does not recognize is recorded.
12. **Reconnect identity after an SSO switchover.** When a Patrol command is cut, the session is reopened and the device must be the same one: the sets of serial numbers in `show version` of both sessions must intersect (a changed set is audited as `serial set changed`); disjoint sets stop the device as "different device", so two units behind one IP (an ASA failover pair) are never mixed in one evidence folder. After an SSO switchover a reconnect may stop with "different device"; re-run the job. This applies to VSS/SVL, 9800 HA SSO and Nexus 7000 with two supervisors when the `show version` of the active unit does not list the serial of the other. It fails on the safe side and still has to be validated in a lab. Without a serial in either session, the hostname and platform are compared.
