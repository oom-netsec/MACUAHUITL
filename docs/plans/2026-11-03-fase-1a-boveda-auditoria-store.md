# Fase 1a — Secretos, bóveda, auditoría y almacenamiento: Plan de implementación

**Goal:** Implementar los cuatro paquetes base sin red: `internal/secret`, `internal/store`, `internal/audit` e `internal/vault`, con las pruebas de alteración y no-filtración que exige la spec.

**Architecture:** Paquetes de librería puros, sin gRPC ni red. `vault` depende de `secret`; `audit` depende de `store`. Nada aquí conoce a Patrol: las ventanas de bóveda se expresan como (ID de trabajo, fin, IDs de credenciales).

**Tech Stack:** Go 1.27, `github.com/awnumar/memguard`, `golang.org/x/crypto/argon2`, `modernc.org/sqlite`, `crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/sha256`, `log/slog`.

**Spec:** `docs/architecture/2026-11-02-macuahuitl-architecture-design.md` (§10, §11, §14) y `docs/security/CRYPTO.md`.

**Planes hermanos de la Fase 1** (se escriben al terminar este): 1b transporte + plataforma IOS-XE + simulador; 1c motor + Patrol + enmascarado + outputs; 1d IPC + núcleo + mctl + systemd; 1e UI Wails.

## Global Constraints

- Argon2id base: 256 MiB (`262144` KiB), 3 iteraciones, 4 hilos (spec §10.2).
- AES-256-GCM, nonce aleatorio de 96 bits por escritura (spec §10.2).
- Ventana de bóveda máxima: 96 h (spec §10.4).
- Archivos de bóveda y base de datos con permisos `0600` (spec §10.2).
- Ningún secreto como `string` fuera de `internal/secret` (CONTRIBUTING).
- Ningún import de red (lo verifica `noegress`).
- Formato de `vault.mcv` exactamente como `docs/security/CRYPTO.md`, salvo la codificación del texto en claro de la entrada (ver Task 3).

## Review Focus

1. **Contraseña maestra vacía** en `Create`, `Unlock` o `ChangeMasterPassword` debe rechazarse con `ErrEmptyPassword`, no crear una bóveda abierta para cualquiera. Test en Task 3.
2. **Archivo de bóveda truncado o basura** debe devolver `ErrCorrupt`, nunca panic. Test en Task 3.
3. **Credencial borrada mientras una ventana armada la referencia** debe dar `ErrNotFound`, y la ventana sigue válida para las demás. Test en Task 4.
4. **Fin de ventana exacto:** en el instante `until` la ventana ya no autoriza. Test en Task 4.
5. **Escrituras concurrentes al log de auditoría** deben producir una cadena íntegra con secuencias contiguas. Test en Task 2.

---

### Task 1: `internal/secret`

**Files:**
- Create: `internal/secret/secret.go`, `internal/secret/secret_test.go`
- Modify: `go.mod` (agrega `github.com/awnumar/memguard`), `internal/secret/doc.go` (se fusiona en `secret.go`)

**Interfaces:**
- Produces:
  - `type Secret struct` (campo no exportado `*memguard.LockedBuffer`).
  - `func New(b []byte) *Secret` — copia `b` a memoria bloqueada y pone `b` en ceros.
  - `func (s *Secret) Bytes() []byte` — vista válida hasta `Destroy`. Devuelve `nil` si `s` es nil o fue destruido.
  - `func (s *Secret) Destroy()` — borra y libera; idempotente; seguro con `s == nil`.
  - `func (s *Secret) Empty() bool`.
  - `String`, `GoString`, `Format(fmt.State, rune)`, `MarshalJSON`, `MarshalText`, `LogValue() slog.Value` → siempre `[REDACTED]`.
  - `const Redacted = "[REDACTED]"`.

- [ ] **Step 1: Tests**
  - `TestNewWipesSource`: `src := []byte("hunter2")`; `New(src)`; `bytes.Equal(src, make([]byte, 7))`.
  - `TestBytesRoundTrip`: `New([]byte("abc")).Bytes()` == `"abc"`.
  - `TestDestroyIdempotent`: `Destroy()` dos veces sin panic; `Bytes()` → `nil`; `(*Secret)(nil).Destroy()` sin panic.
  - `TestRedactionEverywhere`: con `s := New([]byte("MARKER-9f3a"))`, ninguna de estas salidas contiene `MARKER-9f3a` y todas contienen `[REDACTED]`: `fmt.Sprint(s)`, `fmt.Sprintf("%v %s %+v %#v %q %x", s, s, s, s, s, s)`, `fmt.Sprintf("%+v", struct{P *Secret}{s})`, `json.Marshal(struct{P *Secret}{s})`, salida de `slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "p", s)` y de `slog.NewJSONHandler`.
- [ ] **Step 2:** `go test ./internal/secret/` → FAIL (`undefined: New`).
- [ ] **Step 3:** Implementar. `Format` ignora el verbo y escribe `Redacted`, incluido `%x`.
- [ ] **Step 4:** `go test -race ./internal/secret/` → PASS; `go run ./tools/noegress/cmd/noegress ./...` → código 0.
- [ ] **Step 5:** Commit `feat(secret): tipo Secret con memoria bloqueada y redacción`.

### Task 2: `internal/store` y `internal/audit`

**Files:**
- Create: `internal/store/store.go`, `internal/store/migrations/0001_init.sql`, `internal/store/store_test.go`
- Create: `internal/audit/audit.go`, `internal/audit/audit_test.go`
- Modify: `go.mod` (agrega `modernc.org/sqlite`)

**Interfaces:**
- Produces (store):
  - `func Open(path string) (*sql.DB, error)` — crea el archivo con `0600` si no existe, driver `sqlite` de modernc, pragmas `journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`, y aplica migraciones.
  - Migraciones embebidas con `embed.FS`, aplicadas en orden de nombre, registradas en `schema_migrations(version TEXT PRIMARY KEY, applied_at TEXT)`. Idempotente.
  - `0001_init.sql` crea: `devices`, `device_profiles`, `jobs`, `job_runs`, `run_devices`, `credentials_ref(id TEXT PRIMARY KEY)` (solo el ID opaco), `playbooks_index`, `settings(key TEXT PRIMARY KEY, value TEXT)`, y `audit_log(seq INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, detail TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL)` con triggers `BEFORE UPDATE` y `BEFORE DELETE` que hacen `RAISE(ABORT, 'audit_log es solo inserción')`. Las columnas del resto de tablas las fija el builder según spec §12.1; los planes 1c/1d las amplían con migraciones nuevas.
- Produces (audit):
  - `type Entry struct { Actor, Action, Target, Detail string }`
  - `type Record struct { Seq uint64; At time.Time; Entry; Prev, Hash string }`
  - `func New(db *sql.DB, now func() time.Time) *Log`
  - `func (l *Log) Append(ctx context.Context, e Entry) (Record, error)` — serializado con mutex + transacción.
  - `func (l *Log) Verify(ctx context.Context) (VerifyResult, error)` con `type VerifyResult struct { Intact bool; FirstBroken uint64; Head string }`.
  - `func (l *Log) Head(ctx context.Context) (string, error)` — hash del último registro, o el génesis si está vacío.
  - `func (l *Log) Export(ctx context.Context, w io.Writer, from, to time.Time) error` — JSON Lines con los campos de `Record`.
  - `const Genesis = "000…0"` (64 ceros).
  - Hash: `hex(sha256(prev + "\n" + json.Marshal(struct{Seq; At string /*RFC3339Nano UTC*/; Actor; Action; Target; Detail})))`.

- [ ] **Step 1: Tests store**
  - `TestOpenCreates0600`: `Open(tmp/"m.db")`; `os.Stat` → `Mode().Perm() == 0600`.
  - `TestMigrateIdempotent`: `Open` dos veces sobre el mismo archivo sin error; `SELECT count(*) FROM schema_migrations` == 1.
  - `TestAuditLogAppendOnly`: insertar una fila en `audit_log`; `UPDATE` y `DELETE` → error que contiene `solo inserción`.
- [ ] **Step 2: Tests audit**
  - `TestChainIntact`: 3 `Append`; `Verify` → `Intact`, `Head` == hash del 3.º; `Record.Prev` del 1.º == `Genesis`.
  - `TestDetectsEditedRow`: 5 registros; `DROP TRIGGER` del update, `UPDATE audit_log SET detail='x' WHERE seq=3`; `Verify` → `!Intact`, `FirstBroken == 3`.
  - `TestDetectsDeletedRow`: 5 registros; quitar trigger de delete, borrar `seq=2`; `Verify` → `FirstBroken == 3` (el 3 ya no encadena con el 1).
  - `TestConcurrentAppend`: 100 gorrutinas × 1 `Append`; `Verify` → `Intact`; seqs 1..100 contiguos.
  - `TestSecretInDetailIsRedacted`: `Append(Entry{Detail: fmt.Sprint(secret.New([]byte("MARKER")))})`; `Export` no contiene `MARKER`.
  - `TestExportJSONLines`: 2 registros → 2 líneas, cada una `json.Valid`.
- [ ] **Step 3:** `go test ./internal/store/ ./internal/audit/` → FAIL.
- [ ] **Step 4:** Implementar ambos paquetes.
- [ ] **Step 5:** `go test -race ./internal/store/ ./internal/audit/` → PASS; noegress → 0.
- [ ] **Step 6:** Commit `feat(store,audit): SQLite con migraciones y log encadenado`.

### Task 3: `internal/vault` — formato, KDF y credenciales

**Files:**
- Create: `internal/vault/format.go`, `internal/vault/kdf.go`, `internal/vault/vault.go`, `internal/vault/entry.go`
- Create: `internal/vault/format_test.go`, `internal/vault/vault_test.go`
- Modify: `docs/security/CRYPTO.md` (codificación del texto en claro de la entrada)

**Interfaces:**
- Consumes: `secret.New`, `(*Secret).Bytes`, `(*Secret).Destroy`.
- Produces:
  - `type Params struct { MemoryKiB, Iterations uint32; Threads uint8 }`; `var DefaultParams = Params{262144, 3, 4}`; `var MinMemoryKiB uint32 = 262144` (las pruebas lo bajan a `8192`).
  - `func Calibrate(target time.Duration) Params` — parte de `DefaultParams` y sube `Iterations` hasta que una derivación tarde ≥ `target`, tope 10.
  - `type Credential struct { ID, Label, Username string; Password, Enable, SSHKey *secret.Secret }`
  - `type Info struct { ID, Label, Username string; HasEnable, HasSSHKey bool }`
  - `func Create(path string, master []byte, p Params) (*Vault, error)` — falla si el archivo existe (`ErrExists`). Queda desbloqueada.
  - `func Open(path string) (*Vault, error)` — lee y valida el encabezado; queda bloqueada.
  - `func (v *Vault) Unlock(master []byte) error`
  - `func (v *Vault) Put(c Credential) (string, error)` — ID vacío crea; con ID reemplaza. Persiste de inmediato.
  - `func (v *Vault) Get(id string) (Credential, error)` — el llamador hace `Destroy` de los secretos.
  - `func (v *Vault) List() ([]Info, error)`
  - `func (v *Vault) Delete(id string) error`
  - `func (v *Vault) ChangeMasterPassword(old, new []byte) error`
  - Errores: `ErrEmptyPassword`, `ErrWrongPassword`, `ErrLocked`, `ErrNotFound`, `ErrCorrupt`, `ErrExists`, `ErrWeakParams`.
  - Todos los `[]byte` de contraseña maestra recibidos se ponen en ceros antes de volver.
  - Texto en claro de la entrada: secuencia de 6 campos `uint32 longitud ‖ bytes` en orden etiqueta, usuario, contraseña, enable, llave SSH, reservado (vacío). **Cambio respecto a CRYPTO.md** (que decía Protocol Buffers): evita depender de código generado en un paquete criptográfico y permite borrar cada campo. Actualizar CRYPTO.md en esta tarea.
  - Escritura atómica según CRYPTO.md, con `vault.mcv.bak`.
  - `parseHeader` rechaza con `ErrCorrupt` antes de derivar: `MemoryKiB` fuera de `[MinMemoryKiB, 4194304]`, `Iterations` fuera de `[1, 10]`, `Threads` fuera de `[1, 16]`.

- [ ] **Step 1: Tests de formato** (`format_test.go`)
  - `TestHeaderRoundTrip`: `marshalHeader` → `parseHeader` conserva todos los campos; longitud 111 bytes antes de las entradas.
  - `TestParseRejectsHostileParams`: encabezado válido con `MemoryKiB` = 4194305, `Iterations` = 0 u 11, `Threads` = 0 o 17 → `ErrCorrupt` sin derivar la llave (un encabezado alterado no debe poder pedir terabytes de memoria).
  - `TestParseGarbage`: `Open` sobre archivos de 0 bytes, 10 bytes, 111 bytes aleatorios, y mágico correcto con N = 2^31 → `ErrCorrupt` (o `ErrBadMagic` envuelto en `ErrCorrupt`); ninguno hace panic.
- [ ] **Step 2: Tests de bóveda** (`vault_test.go`, `MinMemoryKiB = 8192` y `Params{8192,1,1}` en `TestMain`)
  - `TestCreateUnlockRoundTrip`: `Create`, `Put` con contraseña `MARKER-PW` y enable `MARKER-EN`, `Open` de nuevo, `Unlock`, `Get` devuelve los mismos bytes.
  - `TestWrongPassword`: `Unlock([]byte("otra"))` → `ErrWrongPassword`.
  - `TestEmptyPassword`: `Create(..., []byte{}, ...)`, `Unlock([]byte{})`, `ChangeMasterPassword(ok, []byte{})` → `ErrEmptyPassword`.
  - `TestWeakParamsRejected`: `Create` con `MemoryKiB` < `MinMemoryKiB` → `ErrWeakParams`.
  - `TestTamperEveryHeaderByte`: para cada desplazamiento 0..110, cambiar un bit → `Open` o `Unlock` fallan (nunca `nil`).
  - `TestTamperEntry`: cambiar un byte del texto cifrado de la entrada → `Get` → `ErrCorrupt`.
  - `TestSwapEntryIDs`: intercambiar los IDs de dos entradas en el archivo → `Get` de ambas → `ErrCorrupt`.
  - `TestChangeMasterPassword`: tras cambiar, la vieja → `ErrWrongPassword`, la nueva abre, `Get` intacto.
  - `TestNoPlaintextOnDisk`: tras `Put` con `MARKER-PW`, ni el archivo ni `.bak` contienen `MARKER-PW` en bruto, base64 estándar ni hex.
  - `TestFilePerms`: `vault.mcv` y `vault.mcv.bak` → `0600`.
  - `TestLockedOperations`: tras `Open` sin `Unlock`, `Get`, `Put`, `List`, `Delete` → `ErrLocked`.
  - `TestMasterPasswordWiped`: el slice pasado a `Unlock` queda en ceros.
  - `TestCreateRefusesExisting`: `Create` sobre ruta existente → `ErrExists`.
  - `TestConcurrentPutGet`: 20 gorrutinas mezclando `Put` y `Get` con `-race` sin errores.
- [ ] **Step 3:** `go test ./internal/vault/` → FAIL.
- [ ] **Step 4:** Implementar. Datos asociados de la DEK = bytes 0–46 del encabezado; de cada entrada = ID de bóveda ‖ ID de entrada ‖ versión (2 bytes). DEK en `*secret.Secret`. KEK destruida tras usarla.
- [ ] **Step 5:** `go test -race ./internal/vault/` → PASS; noegress → 0.
- [ ] **Step 6:** Commit `feat(vault): bóveda Argon2id + AES-256-GCM`.

### Task 4: `internal/vault` — bloqueo y ventanas armadas

**Files:**
- Create: `internal/vault/window.go`, `internal/vault/window_test.go`
- Modify: `internal/vault/vault.go`

**Interfaces:**
- Consumes: todo lo de Task 3.
- Produces:
  - `const MaxWindow = 96 * time.Hour`
  - `func (v *Vault) SetClock(now func() time.Time)` — solo pruebas y núcleo.
  - `func (v *Vault) Arm(jobID string, until time.Time, credentialIDs []string) error` — requiere bóveda desbloqueada (`ErrLocked`); `until - now > MaxWindow` → `ErrWindowTooLong`; `until <= now` → `ErrWindowTooLong`; IDs inexistentes → `ErrNotFound`. Rearmar el mismo `jobID` reemplaza.
  - `func (v *Vault) Disarm(jobID string)`
  - `func (v *Vault) Lock()` — cierre interactivo (inactividad, pantalla bloqueada, botón). Si hay ventanas vigentes, conserva la DEK pero `Get` solo autoriza IDs cubiertos por una ventana vigente (`ErrLocked` para el resto); `Put`, `List`, `Delete`, `Arm` → `ErrLocked`.
  - `func (v *Vault) LockAll()` — cierre de sesión, apagado, suspensión: desarma todo y destruye la DEK.
  - `func (v *Vault) Windows() []Window` con `type Window struct { JobID string; Until time.Time; CredentialIDs []string }`.
  - Ventana vigente ⇔ `now < until`. Al expirar la última ventana con la bóveda en estado `Lock`, la DEK se destruye en la siguiente llamada que consulte el estado.

- [ ] **Step 1: Tests** (reloj falso)
  - `TestArmMax96h`: `Arm(..., now+96h, ...)` → ok; `now+96h+1s` → `ErrWindowTooLong`; `now` → `ErrWindowTooLong`.
  - `TestLockKeepsArmedOnly`: credenciales A y B; `Arm("j1", now+1h, [A])`; `Lock()`; `Get(A)` ok; `Get(B)` → `ErrLocked`; `List()` → `ErrLocked`.
  - `TestWindowExpiresAtUntil`: tras `Lock`, avanzar reloj a exactamente `until` → `Get(A)` → `ErrLocked`; `Windows()` vacío.
  - `TestDEKDestroyedAfterLastWindow`: tras la expiración anterior, `Unlock` con la contraseña correcta vuelve a funcionar y `Get(B)` ok (prueba que el estado es "bloqueada", no corrupto).
  - `TestLockAllDropsWindows`: `Arm`, `LockAll()` → `Get(A)` → `ErrLocked`; `Windows()` vacío.
  - `TestDeletedCredentialInWindow`: `Arm("j1", now+1h, [A, B])`; `Delete(B)`; `Lock()`; `Get(B)` → `ErrNotFound`; `Get(A)` ok.
  - `TestArmRequiresUnlocked`: tras `Lock()` sin ventanas, `Arm` → `ErrLocked`.
- [ ] **Step 2:** `go test ./internal/vault/ -run 'Arm|Lock|Window|Deleted'` → FAIL.
- [ ] **Step 3:** Implementar.
- [ ] **Step 4:** `go test -race ./...` → PASS; noegress → 0; staticcheck → limpio.
- [ ] **Step 5:** Commit `feat(vault): bloqueo interactivo y ventanas armadas`.
