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

## Windows

The Windows build (beta, [ADR 0012](../adr/0012-multiplataforma.md)) keeps the same assets and actors. What changes is how each threat is mitigated, and which limits are different.

| Threat | Mitigation on Windows |
|---|---|
| Another local user uses the channel | The core listens on a named pipe `\\.\pipe\macuahuitl-<user SID>` with a protected DACL that grants access only to the user's SID (no Everyone, no Users, no inheritance), and `PIPE_REJECT_REMOTE_CLIENTS`. For each connection the core reads the client's PID (`GetNamedPipeClientProcessId`) and compares the SID of its token with its own; if it differs, the connection is closed before any gRPC. This is the equivalent of the `SO_PEERCRED` UID check |
| Another user creates the pipe first (squatting) | The first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`: if the name already exists, the core does not start and says so. The check also runs the other way: `mctl` and the app verify the owner of the pipe object and the PID and SID of the server before sending anything, so the master password is never sent to a pipe another user created. The squatting case is exercised in a Windows VM with two users |
| Files and folders of the core read by another user | Private folders and files are created with an explicit security descriptor: owner is the user and the DACL is protected (user, SYSTEM and Administrators, the same accounts that can take ownership of the profile anyway). Files are created already private, never protected afterwards, so there is no window with the inherited ACL. The outputs folder is accepted only if it is not a link or junction, the user owns it and no other SID has access (the ACL rule that replaces the `0700` check) |
| Core memory dump | Keys live in memguard buffers locked with `VirtualLock` (the working-set minimum is raised without privileges; if it cannot be, the core does not start). The core is excluded from Windows Error Reporting dumps (`WerAddExcludedApplication`). The rest of the heap is not locked |
| Core running with excess privilege | The core refuses to run elevated (token with `TokenElevation`), as it refuses to run as root on Linux. An account with UAC off, or the built-in Administrator, always runs elevated and cannot use the app; the message says to use a standard account, or an administrator account with UAC on. `mctl` also refuses to talk to the core from an elevated terminal. There is no Windows service: it would run as SYSTEM, against ADR 0004 |
| Tampered binary | The beta is **unsigned** (decision of the owner, 2026-11-16). Verification relies on `SHA256SUMS`, the SLSA attestation (`gh attestation verify`), the open source code and the reproducible build. SmartScreen warns on the first downloads of each version, and Smart App Control, when active on Windows 11, blocks an unsigned executable outright |

Declared limits specific to Windows, in addition to the ones above:

13. **Another process of the same user can read the core's memory.** Windows has no equivalent of Yama or of a non-dumpable process without admin rights or a special signature: any process of the same user can call `OpenProcess` and `ReadProcessMemory`. Malware running in the user's session reads the open vault. This is limit 3 made worse, and it is declared as it is.
14. **Memory locking is partial.** `VirtualLock` covers the key material (memguard buffers), not the whole process like `mlockall` on Linux. Swap and `hiberfil.sys` warnings are best effort: they are read without admin rights where possible, and if they cannot be read the app says it could not check.
15. **ACLs are not evaluated against group membership.** The outputs-folder rule reads the ACEs as the system stores them and does not run `AccessCheck` for another SID's groups. File systems without ACLs (FAT, exFAT) ignore the descriptor; vault backups there are recorded as "no permissions".
16. **Unsigned beta.** Without a code signature, the installer and the executables have no publisher identity; trust rests on the checksums and the attestation above.
