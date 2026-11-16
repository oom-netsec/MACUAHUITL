# Contributing

- **Tests first.** Every change in behavior comes with a test that failed before the change.
- **Network only where allowed.** Network code lives in `internal/transport`, `internal/diag` and `internal/ipc`. `internal/sys` wraps `golang.org/x/sys/unix` and `syscall` for process hardening, signals and safe file operations, and must not open sockets (code review, not the analyzer, enforces that). `gen/` (generated gRPC code, part of the binary), `test/simulator` and `tools/` (neither is part of the binary) may also import network packages. The `noegress` analyzer runs in CI and breaks the build if any other package imports network, low-level sockets, cgo or process execution.
- **`os.StartProcess`** starts processes without importing `os/exec`, and the analyzer does not see it. It is forbidden outside `internal/diag`; code review watches for it.
- **Secrets.** Never use a `string` for a secret outside `internal/secret`. Never log a secret, not even part of one.
- **Language.** Every visible text goes through i18n, with English (canonical) and Spanish (`ui/frontend/src/lib/i18n/en.ts` and `es.ts`, and the core's catalog in `internal/i18n`); a test fails on hard-coded text. Identifiers are in English. The project's code comments and commit messages are usually in Spanish; contributions with comments and commits in English are welcome. Design records (ADRs and plans) are written in Spanish.
- **Commits.** Pull requests are squash-merged into one commit on `main`. Its title follows the style in `git log`: `Area: summary`, for example `Patrol: …`, `packs: …` or `README: …`, and the body says what changed and why.
- **Decisions.** An architecture change comes with a new ADR in `docs/adr/`.

By contributing you agree that your contribution is published under the project's [Apache-2.0](LICENSE) license.

Before opening a pull request:

```sh
./dev.sh test                          # Go tests (with -race), noegress, archcheck and the UI tests
gofmt -l .                             # must print nothing (CI runs the same)
task lint                              # go vet, noegress, archcheck and staticcheck
task proto-lint                        # after changing api/proto; then task proto-gen and commit gen/
```
