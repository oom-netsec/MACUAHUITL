# Fase 1b — Transporte, driver IOS/IOS-XE y simulador: Plan de implementación

**Goal:** Conectar por SSH a un equipo IOS/IOS-XE pasando siempre por EgressGuard, verificar su llave de host, entrar a modo privilegiado, ejecutar comandos y detectar la plataforma; todo probado contra un simulador local.

**Architecture:** `internal/transport` es el único paquete que abre sockets salientes: EgressGuard, known_hosts y la sesión SSH. `internal/platform/iosxe` recibe un shell ya abierto y solo habla texto. `test/simulator` es un servidor SSH en `127.0.0.1` que reproduce transcripciones.

**Tech Stack:** Go 1.27, `golang.org/x/crypto/ssh`, `golang.org/x/crypto/ssh/knownhosts`.

**Spec:** `docs/architecture/2026-11-02-macuahuitl-architecture-design.md` (§6, §6.1, §7, §7.1, §12.2). Depende de la Fase 1a (`internal/secret`, `internal/vault.Credential`, `internal/audit.Entry`).

## Decisión: driver propio, no scrapligo

Revisado scrapligo v1.4.3: su transporte estándar llama `ssh.Dial` sin permitir inyectar la conexión, así que saltaría EgressGuard; además enlaza un transporte que ejecuta el binario `ssh` y otro de telnet. Un driver propio delgado sobre `x/crypto/ssh` es menos código que auditar. **[Decidido en planeación; cumple spec §7 "Builder decide"]**

## Global Constraints

- Todo `net.Conn` saliente nace en `transport.Guard.Dial`. Ningún otro código llama `net.Dial`, `ssh.Dial` ni resolvedores.
- Keepalive `keepalive@openssh.com` cada 15 s; 3 fallos seguidos cierran la sesión (spec §6).
- Algoritmos SSH heredados solo si el perfil del equipo lo permite, y se registra en auditoría (spec §3).
- Nunca se reintenta un fallo de autenticación (spec §6).
- Llave de host cambiada: se rechaza salvo `AcceptChanged` del trabajo (spec §12.2).
- Las credenciales se destruyen (`Secret.Destroy`) al terminar el handshake, exitoso o no.

## Review Focus

1. **Nombre DNS que resuelve a varias IPs** debe autorizar todas las IPs de esa resolución para ese trabajo y ninguna otra. Test en Task 1.
2. **Equipo que nunca muestra prompt** (cuelga tras el login) debe terminar con `ErrPromptTimeout`, no bloquear el worker. Test en Task 4.
3. **Salida con `--More--`** si `terminal length 0` falla debe completarse enviando espacio, no cortarse. Test en Task 4.
4. **Contraseña de enable incorrecta** debe dar `ErrEnableFailed` sin reintentar. Test en Task 4.
5. **El equipo cierra la conexión a mitad de un comando** debe dar error con la salida parcial conservada. Test en Task 4.

---

### Task 1: EgressGuard

**Files:**
- Create: `internal/transport/guard.go`, `internal/transport/guard_test.go`

**Interfaces:**
- Consumes: `audit.Entry`.
- Produces:
  - `type Guard struct` — `func NewGuard(resolve func(ctx context.Context, host string) ([]netip.Addr, error), onDeny func(audit.Entry)) *Guard`. `resolve` por defecto envuelve `net.DefaultResolver.LookupNetIP(ctx, "ip", host)`.
  - `func (g *Guard) Allow(ctx context.Context, jobID string, addresses []string) error` — cada dirección es IP, nombre DNS o CIDR. Los nombres se resuelven aquí y se guardan sus IPs. Dirección inválida → error.
  - `func (g *Guard) Revoke(jobID string)`
  - `func (g *Guard) Dial(ctx context.Context, jobID string, host string, port uint16) (net.Conn, error)` — resuelve `host` si es nombre, elige la primera IP autorizada para `jobID`; si ninguna → `ErrEgressDenied` y `onDeny(Entry{Action: "egress.denied", Target: host, Detail: jobID})`.
  - `var ErrEgressDenied = errors.New("transport: destino no autorizado")`

- [ ] **Step 1: Tests** (listener real en `127.0.0.1:0`; resolvedor falso inyectado)
  - `TestDialAllowedIP`: `Allow(j, ["127.0.0.1"])`; `Dial` al listener → conexión aceptada.
  - `TestDialDenied`: sin `Allow` → `ErrEgressDenied`; `onDeny` llamado una vez con `Target == "127.0.0.1"`.
  - `TestOtherJobCannotUse`: `Allow("j1", ...)`; `Dial("j2", ...)` → `ErrEgressDenied`.
  - `TestCIDR`: `Allow(j, ["127.0.0.0/30"])` → `127.0.0.1` ok; `Allow(j, ["10.0.0.0/30"])` no autoriza `127.0.0.1`.
  - `TestNameMultipleIPs`: resolvedor falso `sw1 → [127.0.0.1, 127.0.0.2]`; `Allow(j, ["sw1"])`; `Dial(j, "127.0.0.2", ...)` pasa la autorización (el error, si lo hay, es de conexión, no `ErrEgressDenied`); `Dial(j, "127.0.0.3", ...)` → `ErrEgressDenied`.
  - `TestRevoke`: `Allow`, `Revoke`, `Dial` → `ErrEgressDenied`.
- [ ] **Step 2:** `go test ./internal/transport/ -run Dial|CIDR|Name|Revoke|Other` → FAIL.
- [ ] **Step 3:** Implementar; guardar `netip.Prefix` por trabajo (una IP es un prefijo /32 o /128); `net.Dialer{Timeout: 10 * time.Second}` sobre la IP elegida.
- [ ] **Step 4:** `go test -race ./internal/transport/` → PASS.
- [ ] **Step 5:** Commit `feat(transport): EgressGuard`.

### Task 2: known_hosts con confianza en el primer uso

**Files:**
- Create: `internal/transport/hostkeys.go`, `internal/transport/hostkeys_test.go`

**Interfaces:**
- Produces:
  - `type HostKeyStatus int` con `HostKeyKnown`, `HostKeyUnknown`, `HostKeyChanged`.
  - `func OpenKnownHosts(path string) (*KnownHosts, error)` — formato OpenSSH (reutiliza `knownhosts`); crea el archivo `0600` si no existe.
  - `func (k *KnownHosts) Check(hostport string, key ssh.PublicKey) HostKeyStatus`
  - `func (k *KnownHosts) Add(hostport string, key ssh.PublicKey) error` — reemplaza la línea si existía.
  - `func Fingerprint(key ssh.PublicKey) string` = `ssh.FingerprintSHA256(key)`.
  - `type HostKeyPolicy struct { Accepted map[string]bool /* huellas aceptadas en el Login Test */; AcceptChanged bool }`
  - `func (k *KnownHosts) Callback(p HostKeyPolicy, onEvent func(audit.Entry)) ssh.HostKeyCallback` — Known → ok; Unknown o Changed cuya huella está en `Accepted` → `Add` y ok; Changed con `AcceptChanged` → `Add`, `onEvent(Action:"hostkey.accepted_changed", Detail: "<vieja> -> <nueva>")` y ok; resto → `*HostKeyError{Status, Fingerprint}`.

- [ ] **Step 1: Tests** con llaves ed25519 generadas en la prueba:
  - `TestUnknownReturnsFingerprint`: archivo vacío → `Callback` devuelve `*HostKeyError` con `Status == HostKeyUnknown` y la huella.
  - `TestAcceptedFingerprintAdds`: con la huella en `Accepted` → ok; segunda `Check` → `HostKeyKnown`; el archivo persiste tras reabrir.
  - `TestChangedRejectedByDefault`: tras `Add(k1)`, presentar `k2` → `HostKeyChanged`.
  - `TestChangedAcceptedWhenAllowed`: `AcceptChanged: true` → ok; `onEvent` recibe ambas huellas.
  - `TestKnownHostsPerms`: archivo `0600`.
- [ ] **Step 2:** FAIL. **Step 3:** Implementar. **Step 4:** PASS con `-race`.
- [ ] **Step 5:** Commit `feat(transport): known_hosts con confianza en el primer uso`.

### Task 3: Simulador SSH

**Files:**
- Create: `test/simulator/simulator.go`, `test/simulator/simulator_test.go`
- Create: `test/transcripts/ios-xe/show_version.txt`, `show_ip_interface_brief.txt`, `show_running-config.txt`, `test/transcripts/ios/show_version.txt`
- Modify: `test/transcripts/README.md` (formato y regla de anonimizado)

**Interfaces:**
- Produces:
  - `type Config struct { Hostname, Username, Password, Enable string; Transcripts string /* carpeta */; StartPrivileged bool; IgnoreTerminalLength bool; HangAfterLogin bool; DropDuringCommand string }`
  - `func Start(t testing.TB, c Config) (addr string, hostKey ssh.PublicKey)` — escucha en `127.0.0.1:0`, cierra con `t.Cleanup`.
  - Transcripción: archivo cuya primera línea es `# command: <comando exacto>` y el resto es la salida tal cual. Comando desconocido → `% Invalid input detected at '^' marker.`
  - Comportamiento: prompt `Hostname>` o `Hostname#`; `enable` pide `Password: ` y valida; `terminal length 0` desactiva la paginación; sin ella, la salida se pagina cada 24 líneas con ` --More-- ` esperando un espacio; `exit` cierra.
  - Contenido de transcripciones: escritas a mano siguiendo el formato público de Cisco, sin datos reales, hasta que existan grabaciones del laboratorio (ver Task 5). `show_running-config.txt` incluye a propósito `enable secret 9 $9$...`, `snmp-server community MARKER-SNMP RO`, `tacacs-server key 7 ...` para las pruebas de enmascarado de la Fase 1c.

- [ ] **Step 1: Test** `TestSimulatorBasics` usando un cliente `x/crypto/ssh` directo: login, `>` visible, `enable` + contraseña → `#`, `show version` devuelve el contenido del archivo.
- [ ] **Step 2:** FAIL. **Step 3:** Implementar. **Step 4:** PASS.
- [ ] **Step 5:** Commit `test: simulador SSH Cisco con transcripciones`.

### Task 4: Sesión SSH y driver IOS/IOS-XE

**Files:**
- Create: `internal/transport/ssh.go`, `internal/transport/ssh_test.go`
- Create: `internal/platform/platform.go`, `internal/platform/iosxe/iosxe.go`, `internal/platform/iosxe/iosxe_test.go`

**Interfaces:**
- Consumes: `Guard.Dial`, `KnownHosts.Callback`, `vault.Credential`, `test/simulator.Start`.
- Produces (transport):
  - `type SSHOptions struct { AllowLegacy bool; Keepalive time.Duration /* 15s */; HandshakeTimeout time.Duration /* 15s */ }`
  - `func OpenSSH(ctx context.Context, g *Guard, jobID string, host string, port uint16, cred vault.Credential, hk ssh.HostKeyCallback, o SSHOptions) (*Session, error)` — auth por contraseña y keyboard-interactive (y llave si `cred.SSHKey` no está vacía); destruye `cred.Password` y `cred.SSHKey` al volver; `cred.Enable` queda para el driver.
  - `func (s *Session) Shell() (io.Reader, io.Writer, error)` — PTY `vt100`, 200×24.
  - `func (s *Session) Close() error`
  - `var ErrAuth = errors.New("transport: autenticación rechazada")`
- Produces (platform):
  - `type Output struct { Command string; Text string; Invalid bool; Started, Ended time.Time }`
  - `type Driver interface { Open(ctx context.Context, r io.Reader, w io.Writer, enable *secret.Secret) error; Run(ctx context.Context, cmd string, timeout time.Duration) (Output, error); Detect(ctx context.Context) (string, error) }`
  - `iosxe.New() platform.Driver`; `Detect` devuelve `"ios-xe"` si `show version` contiene `Cisco IOS XE Software`, `"ios"` si contiene `Cisco IOS Software`, si no `ErrUnknownPlatform`.
  - Prompt: `(?m)^[\w.\-@/:]{1,63}[>#] ?$`. `Open`: esperar prompt (timeout 15 s → `ErrPromptTimeout`); si `>`, `enable` + secreto (rechazo → `ErrEnableFailed`, sin reintento); luego `terminal length 0` y `terminal width 0`. `Run`: escribe el comando, lee hasta el prompt, quita eco y prompt; responde ` --More-- ` con espacio; `% Invalid input` → `Invalid = true`. Conexión cerrada a mitad → error envuelto con `Output.Text` parcial.

- [ ] **Step 1: Tests transport** contra el simulador: `TestOpenSSHAuthOK`, `TestOpenSSHWrongPassword` (→ `ErrAuth`, un solo intento), `TestOpenSSHDeniedByGuard` (sin `Allow` → `ErrEgressDenied` antes de tocar la red), `TestCredentialDestroyed` (`cred.Password.Bytes() == nil` al volver).
- [ ] **Step 2: Tests driver**: `TestOpenEnableAndRun` (`show version` == archivo), `TestDetectIOSXE`, `TestDetectIOS`, `TestInvalidCommand`, `TestPagingFallback` (`IgnoreTerminalLength`), `TestPromptTimeout` (`HangAfterLogin`, timeout 200 ms), `TestEnableFailed`, `TestDropDuringCommand` (salida parcial no vacía).
- [ ] **Step 3:** FAIL. **Step 4:** Implementar. **Step 5:** `go test -race ./internal/transport/... ./internal/platform/... ./test/...` → PASS; noegress → 0.
- [ ] **Step 6:** Commit `feat: sesión SSH y driver IOS/IOS-XE`.

### Task 5: Grabación de transcripciones del laboratorio (requiere al dueño)

El dueño tiene dos APs, un equipo IOS-XE y un switch IOS. Cuando exista `mctl` (Fase 1d), se graban los comandos de `playbooks/cisco/ios-xe` y se reemplazan las transcripciones escritas a mano. Anonimizado: hostnames, IPs, números de serie y cualquier secreto reemplazados antes del commit. Este paso queda registrado aquí y se ejecuta al final de la 1d.
