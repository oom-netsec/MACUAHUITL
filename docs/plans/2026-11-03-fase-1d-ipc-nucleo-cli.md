# Fase 1d — IPC, núcleo, mctl y systemd: Plan de implementación

**Goal:** `macuahuitld` corre como servicio de usuario, expone los servicios gRPC v1 por socket Unix con verificación de UID, mantiene la laptop despierta durante ventanas armadas, y `mctl` maneja bóveda, Patrol y auditoría de punta a punta.

**Architecture:** `internal/ipc` es dueño del socket y del `Dial` de clientes. `internal/sys` concentra las llamadas al sistema de endurecimiento (`prctl`, `setrlimit`, `mlockall`), porque `noegress` prohíbe `golang.org/x/sys/unix` fuera de los paquetes permitidos; se agrega a la lista de `noegress` en la Task 2. `internal/core` arma todo y traduce gRPC ↔ paquetes de dominio. `internal/core/power` habla con logind por D-Bus. `mctl` es un cliente delgado.

**Tech Stack:** Go 1.27, `google.golang.org/grpc`, `google.golang.org/protobuf`, `github.com/godbus/dbus/v5`, `golang.org/x/sys/unix`, `github.com/spf13/cobra`, `golang.org/x/term`.

**Spec:** `docs/architecture/2026-11-02-macuahuitl-architecture-design.md` (§5, §10.3, §10.4, §11, §14). Depende de 1a, 1b y 1c.

## Global Constraints

- Socket en `$XDG_RUNTIME_DIR/macuahuitl/core.sock`; directorio `0700`, socket `0600` (spec §5.2).
- Rechazo de clientes cuyo UID por `SO_PEERCRED` difiere del UID del proceso (spec §5.2).
- Al arrancar: `prctl(PR_SET_DUMPABLE, 0)`, `RLIMIT_CORE = 0`, intento de `mlockall(MCL_CURRENT|MCL_FUTURE)` (spec §10.3).
- Aviso persistente y registro en auditoría si hay swap sin cifrar o hibernación activa (spec §10.3).
- Cierre por inactividad: 15 min (spec §10.3).
- Rutas de spec §14 respetando `XDG_*`.
- Bloqueos de logind `sleep:idle:handle-lid-switch:shutdown` en modo `block` mientras haya una ventana armada; se sueltan al cerrar la última (spec §10.4).
- Señales de logind: `Lock` de sesión → `Vault.Lock()`; `PrepareForSleep(true)` y `PrepareForShutdown(true)` → `Vault.LockAll()` y `Scheduler.Pause` de todo trabajo (spec §10.4).

## Review Focus

1. **Socket viejo de un núcleo muerto** en la ruta: el núcleo nuevo debe detectar que nadie escucha, borrarlo y arrancar; si alguien escucha, salir con error claro. Test en Task 1.
2. **Dos núcleos al mismo tiempo** (doble arranque): el segundo debe salir sin tocar la bóveda. Test en Task 1.
3. **`mctl vault unlock` con la entrada redirigida** (sin TTY): debe leer la contraseña de stdin sin eco, nunca de un argumento de línea de comandos. Test en Task 3.
4. **logind no disponible** (contenedor, sesión sin systemd): armar un trabajo debe avisar `missing_inhibitors` y continuar, no fallar. Test en Task 2.
5. **El cliente se desconecta a mitad de un `Subscribe`**: el núcleo debe liberar el suscriptor del EventBus. Test en Task 1.

---

### Task 1: `internal/ipc` y generación de código

**Files:**
- Create: `gen/macuahuitl/v1/*.pb.go`, `*_grpc.pb.go` (con `buf generate`)
- Create: `internal/ipc/server.go`, `internal/ipc/client.go`, `internal/ipc/peercred.go`, `internal/ipc/ipc_test.go`
- Modify: `buf.gen.yaml` si hace falta, `Taskfile.yml` (tarea `proto-gen`), CI (verifica que `gen/` está al día)

**Interfaces:**
- Produces:
  - `func SocketPath() (string, error)` — exige `XDG_RUNTIME_DIR`.
  - `func Listen(path string) (net.Listener, error)` — crea directorio `0700`; si el socket existe, intenta conectar: responde → `ErrAlreadyRunning`; no responde → lo borra. Crea con `umask` que deja `0600`.
  - `func NewServer() *grpc.Server` — con un `credentials.TransportCredentials` propio que en `ServerHandshake` lee `SO_PEERCRED` y rechaza UID distinto.
  - `func Dial(ctx context.Context) (*grpc.ClientConn, error)` — `unix://` + `SocketPath()`. UI y mctl solo usan esto.
- [ ] **Step 1: Tests** `TestSocketPerms` (dir `0700`, socket `0600`), `TestStaleSocketReplaced`, `TestSecondListenerRefused` (`ErrAlreadyRunning`), `TestPeerCredSameUIDAccepted`, `TestPeerCredCheckRejects` (se inyecta el UID esperado distinto → handshake rechazado), `TestSubscribeDisconnectReleases` (cancelar el stream deja 0 suscriptores en el Bus).
- [ ] **Step 2:** FAIL. **Step 3:** Implementar. **Step 4:** PASS; noegress → 0 (gen e ipc permitidos).
- [ ] **Step 5:** Commit `feat(ipc): socket Unix con verificación de UID y código generado`.

### Task 2: `internal/core` — arranque, servicios y energía

**Files:**
- Create: `internal/sys/harden.go`, `internal/sys/harden_test.go`, `internal/core/paths.go`, `internal/core/power/power.go`, `internal/core/services_*.go`, `internal/core/core.go` y sus `_test.go`
- Modify: `cmd/macuahuitld/main.go`
- Create: `deploy/systemd/macuahuitld.service`
- Modify: `tools/noegress/analyzer.go` (agrega `internal/sys` a `allowed`), `tools/noegress/testdata` (caso `internal/sys` con `golang.org/x/sys/unix` permitido), `CONTRIBUTING.md` y `docs/security/AUDIT_GUIDE.md` (lista de paquetes permitidos)

**Interfaces:**
- Produces:
  - `type Paths struct { Config, Data, State, Runtime, Outputs string }`; `func ResolvePaths(env func(string) string) Paths` según spec §14.
  - `sys.Harden() (warnings []string)` — `PR_SET_DUMPABLE`, `RLIMIT_CORE`, `mlockall`; revisa `/proc/swaps` contra `/dev/mapper/*` o `zram` (cifrado o en RAM se acepta) y `/sys/power/state` + `/sys/power/disk` para hibernación.
  - `type Inhibitor interface { Take(why string) (release func(), missing []string) }`; `power.NewLogind() Inhibitor` vía `org.freedesktop.login1.Manager.Inhibit`; `power.Noop` para pruebas.
  - `type Core struct` — `New(p Paths, opts Options) (*Core, error)`; `Serve(ctx context.Context, l net.Listener) error`; registra `VaultService`, `PatrolService`, `InventoryService`, `AuditService`, `EventService`. `DiagService` y `AclService` devuelven `codes.Unimplemented` hasta sus fases.
  - Cada RPC que cambia estado escribe en auditoría: `vault.create`, `vault.unlock`, `vault.unlock_failed`, `vault.lock`, `credential.put` (solo ID), `job.create`, `job.logintest`, `job.arm` (con fin de ventana y exclusiones), `job.cancel`, `round.start`, `round.end`, `power.inhibit`, `power.release`, `harden.warning`.
  - `macuahuitld.service`: `Type=notify` no; `Type=simple`, `ExecStart=%h/.local/bin/macuahuitld` (ruta real la fija el paquete), `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `NoNewPrivileges=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`, `RestrictRealtime=yes`, `SystemCallArchitectures=native`, `LimitCORE=0`, `LimitMEMLOCK=infinity` (si el usuario no puede, `mlockall` falla y solo se avisa).

- [ ] **Step 1: Tests** `TestResolvePathsXDG`, `TestResolvePathsDefaults`, `TestHardenSetsNotDumpable` (lee `prctl(PR_GET_DUMPABLE)` == 0 en un proceso hijo de prueba), `TestArmTakesAndReleasesInhibitor` (Inhibitor falso cuenta Take/release), `TestArmWithoutLogindWarns` (Inhibitor que devuelve `missing` → `ArmJobResponse.missing_inhibitors` no vacío y el trabajo queda armado), `TestPrepareForSleepLocksAll`, `TestAuditOnEveryStateChange` (secuencia create→unlock→put→create job→arm→cancel deja las acciones esperadas en orden), `TestWindowHoursOver96Rejected` (`codes.InvalidArgument`).
- [ ] **Step 2:** FAIL. **Step 3:** Implementar. **Step 4:** PASS con `-race`.
- [ ] **Step 5:** Commit `feat(core): núcleo, servicios gRPC, endurecimiento y bloqueo de suspensión`.

### Task 3: `mctl`

**Files:**
- Modify: `cmd/mctl/main.go`; Create: `cmd/mctl/cmd_*.go`, `cmd/mctl/mctl_test.go`

**Interfaces:**
- Comandos: `vault {status,create,unlock,lock,passwd}`, `cred {list,add,rm}`, `device {list,add,rm}`, `job {create -f job.yaml, logintest, arm, cancel, list, watch}`, `audit {verify,export}`.
- Contraseñas y secretos: solo por `golang.org/x/term.ReadPassword` si stdin es TTY, o una línea de stdin si no lo es. Nunca por argumentos ni variables de entorno.
- `job create -f`: YAML con los mismos campos que `JobSpec`.
- `job watch`: imprime eventos en una línea cada uno.

- [ ] **Step 1: Tests** con núcleo en proceso sobre socket temporal: `TestVaultCreateUnlockViaStdin`, `TestNoPasswordFlag` (`mctl vault unlock --password x` → error de flag desconocido), `TestJobLifecycleAgainstSimulator` (create → logintest → arm → watch hasta `COMPLETED` → existe zip), `TestAuditVerifyIntact`.
- [ ] **Step 2:** FAIL. **Step 3:** Implementar. **Step 4:** `go test -race ./...` → PASS; noegress → 0.
- [ ] **Step 5:** Commit `feat(mctl): CLI completa para bóveda, Patrol y auditoría`.

### Task 4: Validación en el laboratorio del dueño (requiere al dueño)

- [ ] Instalar `macuahuitld` como servicio de usuario y correr con `mctl` un trabajo `tac-baseline` contra el equipo IOS-XE y el switch IOS reales, 3 rondas cada 5 min, enmascarado encendido.
- [ ] Verificar a mano: zip con manifest, `mctl audit verify` íntegro, `ss -tnp` solo muestra los destinos del trabajo, `grep` de la contraseña real en `~/.local/share/macuahuitl`, `~/.local/state/macuahuitl` y outputs → nada.
- [ ] Grabar transcripciones reales y anonimizarlas (plan 1b, Task 5).
