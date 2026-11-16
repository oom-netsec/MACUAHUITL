# Auditor's guide

How to verify each promise in [SECURITY.md](../../SECURITY.md) without taking our word for it.

## 1. No plaintext credentials on disk

- Read the format in [CRYPTO.md](CRYPTO.md) and compare it with `internal/vault`.
- Run the no-leak test: `go test ./internal/patrol/ -run TestNoLeakEndToEnd`. It creates a vault with a fixed marker password and enable secret, runs a full Patrol against the simulator and searches for the markers in raw, base64 and hex form in the outputs (including the zip) and in the app's data folder.
- On your own: create a credential with a unique value and search for that value with `grep -r` in `~/.local/share/macuahuitl`, `~/.local/state/macuahuitl`, `~/.config/macuahuitl` and the outputs folder.

## 2. No credentials in logs, audit, outputs or dumps

- Check that every secret uses the `Secret` type from `internal/secret` and that its `String`, `Format`, `MarshalJSON` and `LogValue` methods return `[REDACTED]`.
- The same no-leak test covers the data folder (SQLite and logs) and the outputs.
- Dumps: with the core running, `prlimit --pid $(pidof macuahuitld) --core` must show `0`. Also `stat -c %U /proc/$(pidof macuahuitld)/mem` must show `root`: this is the effect of `PR_SET_DUMPABLE=0`, which stops other processes of the same user from reading its memory without ptrace.

## 3. Only destinations typed by the engineer

- **Static:** `go run ./tools/noegress/cmd/noegress ./...` must exit with code 0. Outside the allowed packages it forbids: the `net/` family (except `net/netip`, `net/url` and `net/mail`), `golang.org/x/net/...`, `crypto/tls`, `log/syslog`, `syscall`, `golang.org/x/sys/unix`, `os/exec`, cgo (`import "C"`), `golang.org/x/crypto/ssh` and the gRPC root.
- **Allowed packages:** `internal/transport`, `internal/diag` and `internal/ipc` hold the product's networking; read them in full. `internal/sys` wraps `golang.org/x/sys/unix` and `syscall` for process hardening (`prctl`, `setrlimit`, `mlockall`), signals and safe file operations; it must not open sockets, and code review (not `noegress`) enforces that. Read it in full, it is short. `gen/` is generated gRPC code that also ships in the binary. `test/simulator` and `tools/` do not ship in the binary.
- **Limits of static analysis:** it does not see `os.StartProcess`, nor the code of external dependencies, which are reviewed with `go list -deps ./cmd/...` and `govulncheck` (CI runs `govulncheck` on every push).
- **No telemetry:** `grep -rn "http" --include=*.go internal/ cmd/` must not show hardcoded URLs.
- **At runtime:** run a job and watch with `ss -tnp | grep macuahuitld` or with an egress firewall. Only the job's destinations must appear. Attempts rejected by `EgressGuard` appear in the audit log.
- **External tools:** every run of nmap, ping, traceroute, iperf3 or dumpcap is recorded in the audit log with its full argument line.

## 4. The master password is never stored

- In [CRYPTO.md](CRYPTO.md) there is no field that contains it, nor a hash of it. Only the salt and the Argon2id parameters.
- The encrypted DEK is the only way to check that the password is correct: if GCM fails, the password is wrong.

## 5. The binary matches the code

Each release on GitHub publishes `SHA256SUMS`, `BUILD-INFO.txt` (Go version, tag and commit), an SPDX SBOM and the packages. To reproduce the core and the CLI:

```sh
git checkout vX.Y.Z
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -buildid= -X github.com/oom-netsec/MACUAHUITL/internal/version.Version=vX.Y.Z" -o verif/ ./cmd/macuahuitld ./cmd/mctl
sha256sum verif/macuahuitld verif/mctl   # must match SHA256SUMS in the release
```

You need the same Go version that `BUILD-INFO.txt` states. The UI (`macuahuitl`) is built with cgo against WebKitGTK and is not byte-for-byte reproducible; its checksum is still published. CI builds the core twice on every push and fails if the checksums differ.

## 6. Audit log integrity

- `mctl audit verify` walks the chain and reports the first broken record.
- Every delivered `manifest.json` includes the head hash of the chain at that moment. Compare that value with the matching record in the log.
