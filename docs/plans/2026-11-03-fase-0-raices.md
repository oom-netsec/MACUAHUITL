# Fase 0 — Raíces: Plan de implementación

**Goal:** Dejar el repo con la estructura completa, un módulo Go que compila, el analizador `noegress` funcionando, los contratos gRPC v1, la documentación de seguridad y CI en verde. Sin funcionalidad de producto.

**Architecture:** Un solo módulo Go. Cada paquete de `internal/` existe con un `doc.go` que declara su responsabilidad y sus límites. Los contratos viven en `api/proto` y se validan con `buf lint`; la generación de código empieza en la Fase 1.

**Tech Stack:** Go 1.27, `golang.org/x/tools/go/analysis`, Protocol Buffers + buf, GitHub Actions, Taskfile.

**Spec:** `docs/architecture/2026-11-02-macuahuitl-architecture-design.md`

## Global Constraints

- Ruta del módulo: `github.com/oom-netsec/MACUAHUITL`.
- Directiva `go 1.27` en `go.mod`.
- Ningún proceso propio corre como root (spec §2).
- Red solo en `internal/transport`, `internal/diag`, `internal/ipc` (spec §10.5). `noegress` lo hace cumplir desde esta fase.
- Sin telemetría, sin actualizaciones automáticas (spec §2).
- Comentarios y documentación en español. Identificadores en inglés.
- Licencia: pendiente del dueño. No se agrega `LICENSE` en esta fase.

## Review Focus

1. **Import con alias o en bloque agrupado** (`import n "net"`) debe detectarse igual que uno simple. Test en Task 3.
2. **Subpaquetes de rutas permitidas** (`internal/transport/ssh`) deben estar permitidos; un prefijo parecido (`internal/transporter`) no. Test en Task 3.
3. **Archivos `_test.go`** fuera de rutas permitidas también se revisan: una prueba que abra red rompería la promesa de no-filtración. Test en Task 3.
4. **`--version` sin ldflags** debe imprimir `dev`, no una cadena vacía. Test en Task 1.
5. **Paquetes generados en `gen/`** pueden importar gRPC; el analizador no debe marcarlos. Test en Task 3.

---

### Task 1: Módulo, versión y binarios vacíos

**Files:**
- Create: `go.mod`, `.gitignore`, `Taskfile.yml`, `README.md`
- Create: `internal/version/version.go`, `internal/version/version_test.go`
- Create: `cmd/macuahuitld/main.go`, `cmd/mctl/main.go`

**Interfaces:**
- Produces: `version.Version string` (variable, valor por defecto `"dev"`, se sobrescribe con `-ldflags "-X github.com/oom-netsec/MACUAHUITL/internal/version.Version=..."`), `version.String() string` que devuelve `"macuahuitl " + Version`.

- [ ] **Step 1: Test** `TestStringDefault`: `String()` == `"macuahuitl dev"`.
- [ ] **Step 2:** `go test ./internal/version/` → FAIL (paquete no existe).
- [ ] **Step 3:** Implementar `internal/version`. Ambos `main.go` aceptan `--version` (paquete `flag`), imprimen `version.String()` y salen 0; sin argumentos imprimen "no implementado todavía" a stderr y salen 2.
- [ ] **Step 4:** `go test ./... && go build ./... && go run ./cmd/mctl --version` → `macuahuitl dev`.
- [ ] **Step 5:** `Taskfile.yml` con tareas `build`, `test` (`go test -race ./...`), `lint` (vet + noegress + staticcheck), `proto-lint`. `.gitignore`: `/bin/`, `/dist/`, `node_modules/`, `*.db`, `*.mcv`.
- [ ] **Step 6:** Commit `feat: módulo Go y binarios vacíos`.

### Task 2: Árbol de paquetes y carpetas

**Files:**
- Create: `internal/<pkg>/doc.go` para `core, ipc, secret, vault, audit, store, engine, transport, platform, playbook, patrol, mask, diag, acl` — cada uno con un comentario de paquete que copia su responsabilidad de la spec §15 y dice qué NO hace.
- Create: `playbooks/cisco/{ios-xe,cat9k,nx-os,wlc-9800,wlc-aireos,ftd,ise,sda}/README.md` (una línea: plataforma, acceso según spec §7.1, fase en que llega).
- Create: `ui/README.md`, `test/simulator/README.md`, `test/transcripts/README.md`, `test/e2e/README.md`, `deploy/systemd/README.md`, `deploy/packaging/README.md`, `gen/README.md` — cada uno dice qué irá ahí y en qué fase.

- [ ] **Step 1:** Crear archivos.
- [ ] **Step 2:** `go vet ./...` → sin errores; `go list ./internal/...` lista los 15 paquetes (14 + version).
- [ ] **Step 3:** Commit `chore: estructura de paquetes y carpetas`.

### Task 3: Analizador `noegress`

**Files:**
- Create: `tools/noegress/analyzer.go`, `tools/noegress/analyzer_test.go`, `tools/noegress/cmd/noegress/main.go`
- Create: `tools/noegress/testdata/src/...` (paquetes de prueba)
- Modify: `go.mod` (agrega `golang.org/x/tools`)

**Interfaces:**
- Produces: `noegress.Analyzer *analysis.Analyzer`; binario `go run ./tools/noegress/cmd/noegress ./...` (vía `singlechecker`).

Reglas:
- Imports prohibidos: `net`, `net/http`, `net/http/httputil`, `net/rpc`, `net/smtp`, `os/exec`, `golang.org/x/crypto/ssh`, `google.golang.org/grpc` (solo la raíz exacta; `grpc/codes` y `grpc/status` sí se permiten).
- Paquetes permitidos (ruta relativa al módulo, coincide la ruta exacta o `ruta/` como prefijo): `internal/transport`, `internal/diag`, `internal/ipc`, `gen`, `test/simulator`, `tools`.
- Paquetes fuera del módulo no se revisan.
- Mensaje: `noegress: <paquete> importa "<import>"; la red solo se permite en internal/transport, internal/diag e internal/ipc (spec §10.5)`.

- [ ] **Step 1: Tests** con `analysistest.Run` sobre testdata cuya ruta de módulo simulada es `github.com/oom-netsec/MACUAHUITL`:
  - `internal/vault`: `import "net/http"` → `// want "noegress: .* importa \"net/http\""`.
  - `internal/vault`: `import n "net"` (alias) → diagnóstico.
  - `internal/vault` archivo `x_test.go` con `os/exec` → diagnóstico.
  - `internal/transport/ssh`: `import "net"` → sin diagnóstico.
  - `internal/transporter`: `import "net"` → diagnóstico.
  - `gen/macuahuitl/v1`: `import "google.golang.org/grpc"` → sin diagnóstico (stub local en testdata).
  - `internal/patrol`: `import "google.golang.org/grpc/status"` → sin diagnóstico.
- [ ] **Step 2:** `go test ./tools/noegress/` → FAIL.
- [ ] **Step 3:** Implementar recorriendo `pass.Files[*].Imports`; la ruta del paquete se obtiene de `pass.Pkg.Path()`; la prueba cubre archivos de test porque el analizador corre con `-test` por defecto.
- [ ] **Step 4:** `go test ./tools/noegress/` → PASS y `go run ./tools/noegress/cmd/noegress ./...` sobre el repo → salida vacía, código 0.
- [ ] **Step 5:** Commit `feat(tools): analizador noegress`.

### Task 4: Contratos gRPC v1

**Files:**
- Create: `buf.yaml` (v2, lint `STANDARD`, breaking `FILE`), `buf.gen.yaml` (salida en `gen/`, plugins `go` y `go-grpc`; se usa desde la Fase 1)
- Create: `api/proto/macuahuitl/v1/{common,vault,patrol,inventory,audit,diag,acl,events}.proto`

Contenido mínimo (spec §5.2, §10, §11, §12). Mensajes con campos; ningún campo de secreto viaja de vuelta al cliente:
- `common.proto`: `Timestamp` vía `google/protobuf/timestamp.proto`, `enum DeviceState` (los 8 estados de spec §6 con `DEVICE_STATE_UNSPECIFIED`), `message Target { string address; uint32 port; string device_id; }`.
- `vault.proto`: `VaultService` — `Status`, `Create(master_password)`, `Unlock(master_password)`, `Lock`, `ChangeMasterPassword`, `ListCredentials` (solo id + etiqueta), `PutCredential` (entra secreto, sale solo id), `DeleteCredential`.
- `patrol.proto`: `PatrolService` — `CreateJob`, `LoginTest` (stream de resultados por equipo), `ArmJob`, `CancelJob`, `ListJobs`, `GetRun`. `JobSpec` con: targets, `default_credential_id`, overrides por equipo (`credential_id`, `fallback_credential_id`), `playbook_ids`, `custom_commands`, `output_dir`, `enum SplitStrategy {PER_ROUND, CONSOLIDATED}`, schedule (`interval_seconds`, `rounds`, `until`, `cron`), `enum ZipPolicy {NONE, PER_ROUND, AT_END}`, `delete_loose_files`, `mask_secrets` (por defecto true en la UI), `accept_changed_host_keys` (por defecto false), `window_hours` (máx 96, validado en servidor).
- `inventory.proto`, `audit.proto` (`Verify`, `Export` stream), `diag.proto`, `acl.proto`: servicio con RPCs declarados y mensajes mínimos; los detalles se completan en su fase.
- `events.proto`: `EventService.Subscribe` → stream de `Event` con `oneof` {`DeviceStateChanged`, `CommandProgress`, `Heartbeat`, `JobStateChanged`, `Warning`}.

- [ ] **Step 1:** Escribir archivos.
- [ ] **Step 2:** `buf lint` → sin errores. (Si buf no está instalado: `go run github.com/bufbuild/buf/cmd/buf@<versión fijada> lint`.)
- [ ] **Step 3:** Commit `feat(api): contratos gRPC v1`.

### Task 5: Documentación de seguridad y decisiones

**Files:**
- Create: `SECURITY.md` (cómo reportar, promesas de spec §10.1), `CONTRIBUTING.md` (TDD, noegress, idioma, commits)
- Create: `docs/security/THREAT_MODEL.md`, `docs/security/CRYPTO.md`, `docs/security/AUDIT_GUIDE.md`
- Create: `docs/adr/0001-servicio-mas-clientes.md`, `0002-wails-react.md`, `0003-grpc-socket-unix.md`, `0004-sin-codigo-privilegiado.md`, `0005-argon2id-aes-gcm.md`, `0006-sqlite-go-puro.md`

- THREAT_MODEL: activos (credenciales, DEK, outputs, auditoría), actores (malware de usuario, laptop robada, intermediario en red, auditor), amenazas y mitigaciones de spec §10–§12, y **límites declarados**: string de `x/crypto/ssh`, swap/hibernación, un atacante con el UID del ingeniero puede leer la DEK de un servicio desbloqueado, la cadena de auditoría es reescribible localmente salvo el ancla del manifest, casilla de aceptar llaves cambiadas.
- CRYPTO: formato de `vault.mcv` byte a byte (spec §10.2), jerarquía KEK/DEK, AAD, parámetros de Argon2id.
- AUDIT_GUIDE: cómo un auditor verifica cada promesa de spec §10.5, con los comandos que existirán.
- ADR: formato contexto / decisión / consecuencias, una página máximo.

- [ ] **Step 1:** Escribir archivos.
- [ ] **Step 2:** Verificar que cada promesa de spec §10.1 aparece en `AUDIT_GUIDE.md` con su método de verificación.
- [ ] **Step 3:** Commit `docs: modelo de amenazas, criptografía, guía de auditoría y ADRs`.

### Task 6: CI

**Files:**
- Create: `.github/workflows/ci.yml`

Jobs en `ubuntu-latest`, `actions/setup-go` con `go-version-file: go.mod`:
- `go vet ./...`, `go test -race ./...`, `go run ./tools/noegress/cmd/noegress ./...`, staticcheck y govulncheck con versión fijada vía `go run`, `buf lint` con `bufbuild/buf-action`.
- Compilación reproducible: `go build -trimpath -ldflags "-buildid=" ./cmd/...` dos veces y comparar SHA-256.

- [ ] **Step 1:** Escribir workflow.
- [ ] **Step 2:** Ejecutar localmente los mismos comandos → todos en verde.
- [ ] **Step 3:** Commit `ci: lint, pruebas, noegress, vulnerabilidades y build reproducible`, push a `main`, revisar con `gh run watch` → verde.
