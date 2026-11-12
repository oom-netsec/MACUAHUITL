# Fase 1c — Motor, Patrol, enmascarado y outputs: Plan de implementación

**Goal:** Ejecutar trabajos Patrol completos contra el simulador: Login Test, rondas programadas, un worker por equipo con límite global, eventos en vivo, outputs por ronda o consolidados, enmascarado, manifest con hashes y ancla de auditoría, y empaquetado .zip.

**Architecture:** `internal/playbook` carga datos. `internal/mask` es una función pura sobre texto. `internal/patrol` arma un trabajo y escribe outputs. `internal/engine` programa rondas y reparte equipos entre workers, sin saber de Cisco: recibe una función `RunDevice`. Los eventos salen por un `EventBus` con búfer acotado por suscriptor.

**Tech Stack:** Go 1.27, `gopkg.in/yaml.v3`, `github.com/santhosh-tekuri/jsonschema/v6`, `github.com/robfig/cron/v3`, `archive/zip`, `golang.org/x/sync/errgroup`.

**Spec:** `docs/architecture/2026-11-02-macuahuitl-architecture-design.md` (§6, §8, §10.4, §11, §12). Depende de 1a y 1b.

## Global Constraints

- Límite global de sesiones: 50 por defecto (spec §6).
- Nunca dos sesiones al mismo equipo dentro de un trabajo (spec §6).
- Reintentos solo por fallo de conexión, espera creciente 1 s, 2 s, 4 s, máximo 3; nunca por autenticación (spec §6).
- Latido por trabajo cada 5 s (spec §6).
- Los eventos de cambio de estado y de error nunca se descartan; los de progreso se combinan (spec §6).
- El enmascarado está encendido salvo que el trabajo traiga `disable_masking = true` (spec §12.5); el valor cero del contrato es el seguro.
- Reemplazo de enmascarado con forma `<MASKED:tipo>` conservando la línea (spec §12.5).
- Rondas perdidas por pausa se registran como omitidas, no se recuperan (spec §10.4).
- Lista de denegación de comandos de configuración (spec §8).

## Review Focus

1. **Comando pegado con espacios o mayúsculas raras** (`  CONF T`, `wr`, `copy run start`) debe rechazarlo la lista de denegación. Test en Task 1.
2. **Línea con secreto dentro de un banner o una descripción** (`description key 7 is broken`) no debe enmascararse por error; solo las formas sintácticas reales. Test en Task 2.
3. **Ruta de output inexistente o sin permisos** debe fallar en `CreateJob`, no a mitad de la primera ronda. Test en Task 3.
4. **Ronda que tarda más que el intervalo** no debe arrancar una ronda encimada; la siguiente se marca omitida. Test en Task 4.
5. **Suscriptor lento** no debe frenar el trabajo ni perder el evento `COMPLETED`. Test en Task 4.

---

### Task 1: Playbooks

**Files:**
- Create: `internal/playbook/playbook.go`, `internal/playbook/schema.json`, `internal/playbook/deny.go`, `internal/playbook/playbook_test.go`
- Create: `playbooks/cisco/ios-xe/tac-baseline.yaml`, `playbooks/cisco/ios-xe/cpu-alta.yaml`, `playbooks/cisco/ios-xe/errores-interfaz.yaml`, `playbooks/embed.go`

**Interfaces:**
- Produces:
  - `type Command struct { Text string; Timeout time.Duration; MaySecrets bool }`
  - `type Playbook struct { ID, Platform, Name string; Pre []string; Commands []Command }`
  - `func Load(fsys fs.FS) ([]Playbook, error)` — valida cada YAML contra `schema.json`; un archivo inválido devuelve error con su nombre.
  - `func Ephemeral(platform, text string) (Playbook, error)` — una línea por comando; ignora líneas vacías y las que empiezan con `!`; ID = `custom-` + primeros 12 hex del SHA-256 del texto.
  - `func CheckDenied(platform, cmd string) error` → `ErrDenied` con el comando. Normaliza espacios y minúsculas; deniega prefijos de `configure`, `conf`, `write`, `wr`, `copy`, `reload`, `delete`, `erase`, `format`, `clear`, `debug`, `undebug`, `test`, `install`, `request`, `license` (para plataformas IOS/IOS-XE). `copy` y `clear` en particular: cualquier forma.
  - `playbooks.FS embed.FS` con `cisco/**/*.yaml`.
  - YAML: `id`, `platform`, `name`, `pre: [..]`, `commands: [{cmd, timeout: "60s", may_contain_secrets: bool}]`.
  - `tac-baseline` incluye al menos: `show version`, `show inventory`, `show running-config` (may_contain_secrets), `show logging`, `show processes cpu sorted`, `show interfaces`, `show ip interface brief`, `show environment all`, `show tech-support` (timeout 600s, may_contain_secrets).

- [ ] **Step 1: Tests** `TestLoadEmbedded` (3 playbooks ios-xe, ninguno con comandos denegados), `TestInvalidYAMLNamed`, `TestEphemeralID` (mismo texto → mismo ID), `TestDenyVariants` (`conf t`, `  CONF T`, `configure terminal`, `wr`, `write mem`, `copy run start`, `reload in 5`, `clear counters`, `debug ip packet` → `ErrDenied`; `show running-config`, `show clock` → nil).
- [ ] **Step 2:** FAIL. **Step 3:** Implementar. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(playbook): carga, esquema y lista de denegación`.

### Task 2: Enmascarado

**Files:**
- Create: `internal/mask/mask.go`, `internal/mask/mask_test.go`

**Interfaces:**
- Produces: `func Apply(platform, text string) (masked string, counts map[string]int)`.
- Reglas IOS/IOS-XE (expresiones por línea, anclas al inicio de línea con sangría opcional):

| Tipo | Forma |
|---|---|
| `enable-secret` | `enable (secret\|password) [0-9 ]*<valor>` |
| `user-secret` | `username X ... (secret\|password) [0-9 ]*<valor>` |
| `snmp-community` | `snmp-server community <valor>` |
| `tacacs-key` | `tacacs-server key [0-9 ]*<valor>` y `key [0-9 ]*<valor>` dentro de `tacacs server` |
| `radius-key` | `radius-server key ...` y `key ...` dentro de `radius server` |
| `psk` | `crypto isakmp key <valor>`, `pre-shared-key ... <valor>` |
| `line-password` | `password [0-9 ]*<valor>` bajo `line` |
| `ntp-key` | `ntp authentication-key N md5 <valor>` |
| `ospf-key` | `ip ospf (authentication-key\|message-digest-key N md5) <valor>` |
| `private-key` | bloques `-----BEGIN ... PRIVATE KEY-----` … `-----END ...-----` y `crypto pki certificate chain` → `quit` |

- Solo se reemplaza `<valor>`; el resto de la línea queda igual.

- [ ] **Step 1: Tests** tabla con una línea de entrada y la esperada por cada tipo; `TestDescriptionNotMasked` (`description key 7 is broken` intacta); `TestRunningConfigFixture` (la transcripción `show_running-config.txt` de 1b no contiene `MARKER-SNMP` tras `Apply` y `counts["snmp-community"] == 1`); `TestIdempotent` (`Apply(Apply(x)) == Apply(x)`).
- [ ] **Step 2:** FAIL. **Step 3:** Implementar. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(mask): enmascarado de secretos IOS/IOS-XE`.

### Task 3: Patrol — trabajo, Login Test, outputs, manifest y zip

**Files:**
- Create: `internal/patrol/job.go`, `internal/patrol/logintest.go`, `internal/patrol/output.go`, `internal/patrol/manifest.go`, `internal/patrol/zip.go` y sus `_test.go`
- Create: `internal/store/migrations/0002_patrol.sql` (columnas necesarias en `jobs`, `job_runs`, `run_devices`)

**Interfaces:**
- Consumes: `transport.OpenSSH`, `transport.Guard`, `KnownHosts.Callback`, `iosxe.New`, `vault.(*Vault).Get`, `audit.(*Log).Append/Head`, `playbook.*`, `mask.Apply`.
- Produces:
  - `type Spec` — espejo Go de `JobSpec` de `patrol.proto` (mismos nombres de campo).
  - `func Validate(s Spec, now time.Time) error` — sin targets, sin credencial, `window_hours` 0 o > 96, `output_dir` inexistente o no escribible (prueba creando y borrando un archivo), comandos denegados → error con el campo.
  - `type LoginResult struct { Target string; Passed bool; FailedStep string; Detail, Platform, Fingerprint string }`
  - `func LoginTest(ctx context.Context, d Deps, jobID string, s Spec, interactive bool) []LoginResult` — pasos de spec §12.2; con `interactive=false` usa la política del trabajo (llave nueva → omitido).
  - `type Deps struct { Guard *transport.Guard; Hosts *transport.KnownHosts; Vault *vault.Vault; Audit *audit.Log; Now func() time.Time }`
  - `func RunDevice(ctx context.Context, d Deps, jobID string, s Spec, round int, target string, emit func(Event)) DeviceResult` — conecta, ejecuta pre + comandos, escribe output, emite progreso.
  - `type Writer` — `NewWriter(root string, s Spec, startedAt time.Time) (*Writer, error)` crea `<root>/<job>_<AAAAMMDD-HHMMSS>/`; `Write(host, ip string, round int, at time.Time, out platform.Output, masked bool) error` aplica estrategia: `PER_ROUND` → `<host>_<ip>/r%03d_<AAAAMMDD-HHMMSS>.txt`; `CONSOLIDATED` → `<host>_<ip>/<host>.txt` con encabezado `===== ronda N · <RFC3339> · <comando> =====`.
  - `func WriteManifest(dir string, m Manifest) error` — `manifest.json` con trabajo, versión, playbooks + hash, equipos, rondas, `masked`, SHA-256 de cada archivo, llaves aceptadas cambiadas, y `audit_head`.
  - `func Zip(dir string, name string, deleteLoose bool) (string, error)` — rutas relativas, sin seguir symlinks, `manifest.json` incluido.

- [ ] **Step 1: Tests** contra simulador y bóveda real con parámetros de prueba:
  - `TestValidateRejects`: cada condición de `Validate` produce error que nombra el campo; `output_dir` con `0500` → error.
  - `TestLoginTestPasses`, `TestLoginTestWrongPassword` (`FailedStep == "auth"`), `TestLoginTestUnknownHostKeyInteractive` (devuelve huella, no conecta comandos), `TestLoginTestChangedKeySilentSkips`.
  - `TestPerRoundFiles`, `TestConsolidatedFile` (2 rondas → 1 archivo con 2 encabezados).
  - `TestMaskedOutputHasNoMarker`: `Spec` sin tocar `DisableMasking` → ningún archivo contiene `MARKER-SNMP`; `DisableMasking=true` → sí, y `manifest.masked == false`.
  - `TestManifestHashes`: cada SHA-256 coincide; `audit_head` == `audit.Head()` al cerrar.
  - `TestZipContents`: zip contiene manifest y todos los archivos; con `deleteLoose` los sueltos desaparecen.
  - `TestNoLeakEndToEnd`: contraseña `MARKER-PW` y enable `MARKER-EN`; corre un trabajo completo; busca ambos en bruto, base64 y hex en outputs, zip, base de datos, archivo de bóveda y log técnico → ninguno.
- [ ] **Step 2:** FAIL. **Step 3:** Implementar. **Step 4:** PASS con `-race`.
- [ ] **Step 5:** Commit `feat(patrol): trabajos, Login Test, outputs, manifest y zip`.

### Task 4: Motor — scheduler, workers y EventBus

**Files:**
- Create: `internal/engine/bus.go`, `internal/engine/runner.go`, `internal/engine/scheduler.go` y sus `_test.go`

**Interfaces:**
- Produces:
  - `type Event struct { At time.Time; JobID string; Kind EventKind; DeviceID string; State string; Command string; Index, Total int; Bytes int64; Detail string }`; `EventKind`: `DeviceState`, `Progress`, `Heartbeat`, `JobState`, `Warning`.
  - `func NewBus(buffer int) *Bus`; `Subscribe(jobIDs []string) (<-chan Event, func())`; `Publish(Event)` nunca bloquea: si el búfer está lleno, un `Progress` reemplaza al `Progress` pendiente del mismo equipo; los demás tipos se encolan en una cola sin límite por suscriptor.
  - `type RunFunc func(ctx context.Context, round int, target string) error`
  - `func NewRunner(maxSessions int, bus *Bus) *Runner`; `RunRound(ctx context.Context, jobID string, round int, targets []string, f RunFunc) map[string]error` — semáforo global compartido por todos los trabajos; un target nunca corre dos veces a la vez.
  - `type Scheduler` — `NewScheduler(r *Runner, now func() time.Time)`; `type Schedule struct { Interval time.Duration; Rounds int; Until time.Time; Cron string }` (propio del motor; `patrol` lo traduce desde su `Spec`); `Arm(jobID string, sched Schedule, until time.Time, targets []string, f RunFunc) error`; `Cancel(jobID string)`; `Pause(jobID string)` (bóveda cerrada); `Resume(jobID string)`. Ronda aún corriendo cuando toca la siguiente → la siguiente se registra como omitida (evento `Warning` `round.skipped`).
  - Latido: evento `Heartbeat` cada 5 s por trabajo armado.

- [ ] **Step 1: Tests**
  - `TestGlobalLimit`: `maxSessions=3`, 10 targets con `RunFunc` que duerme 50 ms y cuenta concurrencia máxima → ≤ 3.
  - `TestOneSessionPerTarget`: dos `RunRound` simultáneos del mismo trabajo con el mismo target → nunca concurrentes.
  - `TestSlowSubscriberNeverBlocks`: suscriptor que no lee; 10 000 `Publish` de progreso terminan en < 1 s; al leer después, recibe el `JobState` `COMPLETED`.
  - `TestOverlappingRoundSkipped`: intervalo 100 ms, ronda que dura 250 ms → evento `round.skipped`.
  - `TestPauseResume`: `Pause` → no corren rondas; `Resume` → siguen; rondas del intervalo pausado aparecen como omitidas.
  - `TestHeartbeat`: con reloj real y latido configurable a 50 ms en la prueba, llegan ≥ 2 latidos en 150 ms.
- [ ] **Step 2:** FAIL. **Step 3:** Implementar. **Step 4:** `go test -race ./...` → PASS; noegress → 0.
- [ ] **Step 5:** Commit `feat(engine): scheduler, runner con límite global y EventBus`.
