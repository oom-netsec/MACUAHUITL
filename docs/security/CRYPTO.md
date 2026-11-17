# Vault cryptography

Reference: design §10.2–§10.4. Standard primitives only: `crypto/aes`, `crypto/cipher`, `crypto/rand`, `golang.org/x/crypto/argon2`.

## Key hierarchy

```
master password ──Argon2id(salt, m, t, p)──► KEK (32 B)
                                                │
                                   AES-256-GCM  ▼
DEK (32 random bytes) ◄──── decrypts ──── encrypted DEK (in the header)
   │
   └── AES-256-GCM ──► each credential entry
```

- Changing the master password only re-encrypts the DEK.
- The KEK exists only while the DEK is being decrypted and is wiped right after.

## `vault.mcv` format (version 1)

All integers are big-endian.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | Magic `MCV1` (`0x4D 0x43 0x56 0x31`) |
| 4 | 2 | Format version = 1 |
| 6 | 16 | Vault ID (random) |
| 22 | 4 | Argon2id memory in KiB |
| 26 | 4 | Argon2id iterations |
| 30 | 1 | Argon2id threads |
| 31 | 16 | Salt |
| 47 | 12 | Nonce of the encrypted DEK |
| 59 | 48 | Encrypted DEK (32 B + 16 B GCM tag) |
| 107 | 4 | Number of entries N |
| 111 | … | N entries |

Associated data of the encrypted DEK: header bytes 0–46. Changing any parameter invalidates the DEK.

### Entry

| Size | Field |
|---|---|
| 16 | Entry ID (random) |
| 12 | Nonce |
| 4 | Length L of the ciphertext, including the 16-byte GCM tag (L ≥ 16) |
| L | Ciphertext + GCM tag |

- Associated data: vault ID (16 B) ‖ entry ID (16 B) ‖ format version (2 B, big-endian).
- Plaintext: 6 fields `uint32 length (big-endian) ‖ bytes`, in the order label, user, password, enable, SSH key and one empty reserved field. Everything is encrypted, including the label. This format was chosen over Protocol Buffers to avoid depending on generated code inside the cryptographic package and to be able to wipe each field from memory.
- SSH key field (phase 44, [ADR 0013](../adr/0013-llaves-ssh-generadas-en-el-nucleo.md)): an ed25519 key generated in the core with `crypto/rand`, stored as an unencrypted OpenSSH private key (PEM, hand-built in `internal/vault/keygen.go` because `noegress` forbids `x/crypto/ssh` in `vault` and `core`; interoperability is tested with `x/crypto/ssh` in `internal/transport`), the same format `transport` reads with `ssh.ParsePrivateKey`. It lives only inside the encrypted entry: the vault file format and version do not change. A credential with an SSH key and no password or enable secret is of kind `key`; the kind is computed, not stored. The seed and the PEM intermediates are zeroed after use. A `.mcvault` backup carries the keys inside, encrypted with the backup passphrase.
- Field size limit: each field is at most `MaxFieldBytes` = 64 KiB (`internal/vault/entry.go`), because each secret lives in locked memory (`RLIMIT_MEMLOCK` is often 8 MiB) and memguard panics when it cannot lock. The limit applies only to what comes from outside: a backup opened with `OpenBackup` (a longer field gives `ErrFieldTooLong`, not "corrupt"), the user's entry boundary (`Put`, `PutBatch`, `PutUnlessKey`, the import) and the export. The vault's own entries and the reserved ones (the assist keeps the pending rollback, with the whole running-config, in a reserved entry) only have a sanity limit of 16 MiB, like `ipc.MaxMsg`, so a vault saved before the limit keeps working. There is no locked-memory bound on the number of credentials: `OpenBackup` only enforces sanity limits (64 MiB per file, `MaxBackupEntries` = 10000 entries, the 64 KiB per field and the Argon2id parameter limits), and nothing ever holds more than a few secrets decrypted at once, so no backup within those limits makes memguard panic. An opened backup keeps its entries encrypted in normal memory and only its 32-byte DEK in one locked buffer. The import preview decrypts the entries one at a time, computes each state (new, same, conflict) against the live vault, validates the SSH key, destroys the secret at once and keeps only non-secret metadata (ID, label, user, state) plus the opened backup, so a pending preview (up to 4, 10 minutes) costs one locked buffer, not one per credential, and the passphrase is not asked or derived twice. Applying (`Vault.ImportFrom`) decrypts and re-encrypts one credential at a time, validates each with the strict boundary (field limit, SSH key) and only replaces the entry list and writes the file once all passed: all or nothing, the vault file stays byte-identical if any step fails. The export encrypts in chunks of about 1 MiB of locked memory.
- SSH keys are validated with `x/crypto/ssh` (`internal/sshkey`, the only place besides `transport` allowed to import it) when saved and when a backup is imported: a private key that does not parse, or is protected by a passphrase, fails the whole operation naming the credential.
- The nonce is a random 96-bit value and is renewed on every write of the entry. At the volume of a single vault, the collision risk is negligible.

## Validation on read

Before deriving any key, the file is rejected as corrupt if:

- it is shorter than 111 bytes, the magic is not `MCV1` or the version is not 1;
- the Argon2id memory is outside [256 MiB, 4 GiB], the iterations outside [1, 10] or the threads outside [1, 16];
- the number of entries does not fit in the rest of the file, any entry has L < 16 or extends past the file, or bytes are left over at the end.

This way a tampered header cannot request terabytes of memory.

## Argon2id parameters

- Baseline: 256 MiB, 3 iterations, 4 threads.
- On `Create` they are calibrated to take about 1 s on the machine, without going below the memory baseline.
- The parameters are stored in the header, so a vault created on one machine opens on another.

## Writing

Temporary file in the same directory, `fsync`, `rename`, `fsync` of the directory. Before that, the current file is copied to `vault.mcv.bak`. Permissions 0600.

## Lifetime in memory

- The DEK lives in a locked buffer (`mlock`, guard pages) via `memguard`. Its AES expansion lives in normal memory: it is created once when the vault is opened and released when the DEK is destroyed (declared limit 10 of the threat model).
- When the master password is changed, `vault.mcv.bak` is also rewritten, so that no copy stays sealed with the old password.
- The `.bak` backup is written the same way as the main file: temporary file, `fsync`, `rename`.
- A credential is decrypted right before authenticating and wiped when done. See the declared limit on `x/crypto/ssh` in the [threat model](THREAT_MODEL.md#declared-limits).

## About `MCK1` (lab PKI keys)

The private keys generated by the PKI tool (CSR keys and the lab CA key) are stored in an envelope with the same scheme as the DEK, without going through the vault: `vault.Seal`/`vault.Unseal`.

| Size | Field |
|---|---|
| 4 | Magic `MCK1` |
| 4 | Argon2id memory in KiB |
| 4 | Argon2id iterations |
| 1 | Argon2id threads |
| 16 | Salt |
| 12 | Nonce |
| … | PKCS#8 DER encrypted with AES-256-GCM + tag |

- Associated data: the 29 bytes before the nonce; changing a parameter invalidates the envelope.
- Before deriving, the parameters are validated with stricter caps than those of `vault.mcv`, because the envelope arrives pasted by the user: memory between the vault minimum and 1 GiB, 1–10 iterations and 1–8 threads. An out-of-range envelope is rejected as corrupt without deriving anything.
- On disk it travels as PEM `MACUAHUITL SEALED PRIVATE KEY`. To move the key to another machine, it is exported to PKCS#12 with a password (or unencrypted PEM, only if explicitly requested).
