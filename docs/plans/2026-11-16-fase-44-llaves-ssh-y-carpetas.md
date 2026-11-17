# Fase 44: llaves SSH, hosts que no son Cisco y carpetas de hosts

Fecha: 2026-11-16 · Decisiones: ADR 0013 · Estado: propuesto · Contrato de proto: fijado en esta rama (`fase-44-plan`)

## Objetivo

El caso real del dueño es guardar dos equipos de su LAN y entrar con un toque desde el terminal SSH de la app, siempre con llave y nunca con contraseña:

| Host | Plataforma | Dirección | Usuario | Orden de inicio |
|---|---|---|---|---|
| pi-panel | linux | 192.168.3.61:22 | (el de la Pi) | — |
| zylant-box | windows | 192.168.3.69:22 | zylant-ai | `wsl -d Ubuntu-26.04 --cd ~` |

Para eso hacen falta tres cosas:

- **A.** Llaves ed25519 que nacen en el núcleo y nunca salen.
- **A.** Hosts `linux`/`windows` solo para el terminal, con orden de inicio por host.
- **B.** Carpetas de hosts como entidad propia: existen vacías, se renombran, se borran sin borrar hosts, y los hosts se mueven en lote.

Reparto: Backend lleva el núcleo, el proto y mctl (44a–44f). Front lleva la UI: menú, arrastrar y teclado para mover hosts, el botón de un toque, la vista de la pública y la orden antes de conectar. Release lleva la validación en una VM de Windows.

## Lo que hay hoy (leído en el código, sobre a25fe7c)

- **Bóveda.** `vault.Credential` tiene `SSHKey *secret.Secret`, cifrado en la entrada como 5.º campo (`entry.go`; el 6.º está reservado y vacío). `PutCredentialRequest.ssh_private_key` **acepta una llave privada por gRPC** (`core/services.go`, `PutCredential`). Ni `mctl cred add` ni la UI lo usan, pero el socket lo permite. El respaldo `.mcvault` (`vault/backup.go`, `WriteBackupWarn`) **copia la llave** con el resto de la credencial, y su import (`core/respaldo.go`) la trae de vuelta.
- **Autenticación.** `transport.OpenSSH` agrega `ssh.PublicKeys` si hay llave, y password + keyboard-interactive **solo si hay contraseña**. Una credencial sin contraseña ya ofrece solo publickey: el requisito A.2 ya se cumple y solo falta probarlo.
- **Hosts.** `devices.HostPlatforms` es una lista cerrada de Cisco. `Folder` es un texto del host (`^[A-Za-z0-9 _.-]{1,48}$`, sin espacios en los extremos) que se filtra sin distinguir mayúsculas (`NameKey`). Una carpeta vacía no existe. El CSV de hosts tiene encabezado fijo y el JSON usa `DisallowUnknownFields`.
- **Patrol** no conoce la plataforma de la libreta: `Target` trae solo dirección y puerto, y la plataforma sale de `drv.Detect` (show version). Un Linux hoy falla en la detección con `platform.err.unknown`. `playbook.knownPlatforms` es una lista cerrada de Cisco, así que un playbook ya no puede nombrar `linux` ni `windows`.
- **Errores de campo.** `devices.FieldError` no llega con `metadata.field`: `ErrFrom` toma el error del catálogo de adentro (regla 9b).
- **Terminal.** `service/terminal` recibe dirección, puerto y credencial del cliente. Abre `ShellSize` con PTY `vt100` y TOFU por `KnownHosts.Callback`: una llave nueva vuelve como `HostKeyError` con la huella `SHA256:…` y la UI reabre con `accepted_host_key_fingerprints`. Sale por `Guard.Allow` y lo audita (`terminal.open`/`close`/`failed`). No hay terminal en mctl.
- **Simulador** (`test/simulator`): solo password y keyboard-interactive, y solo `pty-req` + `shell`. No acepta publickey ni `exec`.

## Decisiones

### Llaves (detalle en ADR 0013)

1. **Generación dentro de `internal/vault`.**
   - `vault.GenerateKey(label, user) (id string, pub ssh.PublicKey, err error)`: `ed25519.GenerateKey(crypto/rand)` y `Put` en la misma llamada.
   - El servicio nunca toca los bytes de la privada. Los intermedios (`ed25519.PrivateKey`, el PEM) se ponen en ceros al terminar.
   - `vault.PublicKey(id) (ssh.PublicKey, error)` deriva la pública de la privada guardada. Funciona también con una llave importada antes de la fase 44.
2. **Almacenamiento.**
   - Formato OpenSSH sin frase (`ssh.MarshalPrivateKey` + PEM) dentro del campo llave ya cifrado con la DEK. Es el que `transport` ya lee con `ssh.ParsePrivateKey`.
   - El archivo de la bóveda no cambia de formato ni de versión, y no hay migración. El 6.º campo reservado sigue vacío.
   - Se descartó guardar la semilla de 32 bytes: obliga a un segundo formato en `transport` a cambio de menos copias en memoria, que de todos modos `ParsePrivateKey` vuelve a hacer.
3. **Tipo.**
   - `kind = "key"` si hay llave, sin contraseña ni enable. `"password"` en cualquier otro caso, también una credencial vieja con contraseña y llave.
   - Se calcula en `List` (`Info.HasPassword` nuevo); no se guarda.
   - Una credencial `key` no lleva enable en esta fase.
4. **Pública.**
   - Formato authorized_keys: `ssh-ed25519 AAAA… macuahuitl@<hostname>`.
   - `<hostname>` es `os.Hostname()` al momento de pedirla, filtrado a `[A-Za-z0-9._-]`; si queda vacío, `macuahuitl@localhost`. No se guarda: si cambia el hostname, cambia el comentario y la llave sigue siendo la misma.
5. **Nada saca la privada.** Revisado camino por camino:

   | Camino | Hoy | Fase 44 |
   |---|---|---|
   | `ListCredentials` | solo `has_ssh_key` | igual, más `kind` |
   | `GetCredentialPublicKey` (nuevo) | — | solo la pública |
   | Respaldo `.mcvault` (`WriteBackupWarn`) | **copia la llave** | la de solo llave no viaja; la de contraseña + llave viaja sin la llave; `ssh_keys_omitted` lo cuenta |
   | Import de respaldo (`core/respaldo.go`) | **trae la llave** | toda llave se descarta: solo llave → estado `llave_privada` (omitida); contraseña + llave → entra sin la llave (`ssh_key_dropped`) |
   | Export de hosts | solo la etiqueta | igual |
   | Auditoría, registros, grabación del terminal | nada | nada; la auditoría lleva solo la huella de la pública |
   | `assist/rotate.go` (copia `SSHKey` dentro de la bóveda) | interno | interno; además rechaza `--update-cred` sobre una credencial `key` (44b) |

6. **Nada mete una privada.**
   - `PutCredential` con `ssh_private_key` no vacío → InvalidArgument `vault.err.no_key_import`.
   - `PutCredential` con el id de una credencial `key` → FailedPrecondition `vault.err.key_credential`: para cambiarla se borra y se genera otra.
   - El campo no se marca `deprecated = true` en el proto: protoc-gen-go marcaría el campo como obsoleto y staticcheck (SA1019) fallaría en el núcleo, que lo sigue leyendo para rechazarlo. Va obsoleto en el comentario.
7. **Credenciales viejas con llave importada.** Solo pueden existir si alguien llamó al gRPC a mano; mctl y la UI nunca lo ofrecieron. Siguen autenticando y `cred pubkey` funciona con ellas. Ya no viajan en respaldos, y no se borran ni se migran.

### Hosts genéricos

8. **Plataformas.**
   - `HostPlatforms` suma `linux` y `windows`, al final de la lista.
   - El rechazo en Patrol va en `patrolSvc.validate`: cubre patrol, adhoc, backup y change. El cambio asistido lo rechaza al empezar.
   - Ambos usan un ayudante compartido nuevo, `service.GenericHostAt(db, address, port) (name, platform string, ok bool, err error)`. Es una consulta de solo lectura a `hosts`, como `JobOutputRoots`. La dirección se normaliza igual que la libreta: minúsculas, y en IP `netip` con `Unmap`.
   - Mensaje: `patrol.svc.generic_host` («{name} es un host {platform}: solo se abre en el terminal SSH»).
   - Las demás herramientas que conectan (ports, snippet, restore, metrics, visibility) siguen fallando en la detección como hoy. La transferencia SCP/SFTP no se toca: copiar a un Linux es legítimo.
9. **Orden de inicio (`startup_command`; en la UI, `startCommand`).** El núcleo es la barrera real; la UI solo repite la regla.
   - Una línea de 1 a 256 puntos de código (`utf8.RuneCountInString`), sin espacios en los extremos.
   - Se rechaza `\p{Cc}` (`unicode.IsControl`: tab, `\n`, `\r`, NUL, DEL y C1) y `\p{Cf}` (`unicode.Is(unicode.Cf, r)`: bidi U+202A–202E y U+2066–2069, U+200B–200F, U+FEFF). Con un U+202E la orden se vería distinta de la que corre («Trojan Source»).
   - El error llega con `metadata.field = "startup_command"` (ver regla 9b).
   - Solo en hosts `linux` o `windows` (`hostfield.startup_platform`): en un Cisco sería un comando de un clic contra un equipo de red fuera del modo asistido (ADR 0007).
   - Cambiar la plataforma de un host con orden a una de Cisco falla hasta que se vacía la orden.
   - **Viaja en el export/import de hosts** (pedido de Front).
     - Va como columna `startup_command` al **final** del CSV y como clave opcional del JSON. Sale de la misma tabla `HostFields`, así que la plantilla y la descripción de campos la traen solas.
     - El lector del CSV acepta el encabezado viejo, sin esa columna, y el nuevo: los archivos viejos siguen entrando. Un archivo nuevo no entra en una versión vieja, por el encabezado fijo y `DisallowUnknownFields`; se acepta.
     - La vista previa marca cada host que trae orden (`ImportHostItem.has_startup_command`) y la orden va en `host.startup_command`, para que el usuario la vea antes de aceptar.
     - «Igual» (`hosts_import.go`) compara también la orden. Reemplazar un host guardado reemplaza su orden.
     - El riesgo de un archivo ajeno con una orden de un clic queda cubierto dos veces: la vista previa la muestra y el terminal no conecta si la orden guardada no es la que la UI mostró al conectar (regla 12).
9b. **`metadata.field` en los errores de campo del inventario.**
    - Hoy **no llega**: `devices.FieldError` envuelve un error del catálogo, y `service.ErrFrom` toma por `errors.As` el `i18n.Coded` de adentro, sin `Field`.
    - Se arregla con `Reason`, `Metadata` y `Localize` en `devices.FieldError`, como `patrol.FieldError`, que suma `field`. Lo aprovechan todos los campos del host, no solo la orden.
    - El valor es el nombre del campo en el archivo y en el proto (`name`, `address`, `startup_command`…), el mismo que ya trae `ImportHostError.field`.
    - Front pedía `"startCommand"`. Se usa `startup_command` para no tener dos nombres del mismo campo en el cable: la UI ya mapea `ImportHostError.field`.

10. **Cómo se manda.**
    - Exec con PTY: `NewSession` → `RequestPty` → `Start(orden)`. Es `ssh -t host orden`, igual que `RemoteCommand` + `RequestTTY`. No se teclea en el shell. Confirma la propuesta de Front.
    - El servidor la pasa al shell de la cuenta: en Linux, `$SHELL -c`; en Windows, el `DefaultShell` de OpenSSH, `cmd.exe /c` por omisión.
    - El núcleo no arma ningún shell local.
    - Cuando la orden termina, la sesión se cierra con «el equipo cerró la sesión».
    - `transport.Session` gana `CommandSize(term string, rows, cols int, cmd string)`, junto a `ShellSize`.
11. **PTY.**
    - En hosts `linux` y `windows`, `xterm-256color`; la UI es xterm.js. Los Cisco siguen con `vt100`.
    - `ShellSize` gana el parámetro `term` y `Shell()` sigue pasando `vt100`.
12. **Terminal con `host_id`.**
    - El núcleo lee el host (`service.SavedHost(db, id)`) y usa su dirección, puerto, credencial y orden de inicio.
    - **`host_id` es exclusivo.** Si el pedido trae `address`, `port` o `credential_id` junto con `host_id` → InvalidArgument `terminal.err.host_and_address` (mensaje del catálogo es/en), antes de leer la bóveda y de `Guard.Allow`. Darle prioridad a `host_id` no basta: un cliente alterado no debe poder combinar un host guardado con otra credencial u otra dirección. Lo pidió Front.
    - Si `expected_startup_command` ≠ la orden guardada → FailedPrecondition `terminal.err.startup_changed`, **antes** de `Guard.Allow`, así que no hay conexión. Es la garantía de «lo que corre es lo que se vio» si el host se editó entre la lista y el clic.
    - Si el host no tiene credencial → FailedPrecondition `terminal.err.host_no_credential`.
    - `host_id` sirve para cualquier host guardado, también los Cisco: el toque abre el shell de siempre.
13. **Huella (TOFU).**
    - Sin cambios de flujo: la primera vez vuelve `HostKeyError` (FailedPrecondition) y la UI muestra la huella, el usuario confirma y la UI reabre con `accepted_host_key_fingerprints`.
    - `HostKeyError.Metadata()` gana `key_type` (p. ej. `ssh-ed25519`). La UI muestra `host:puerto`, el tipo y `SHA256:…`, el mismo formato que `ssh-keygen -lf`, con la orden para compararla:
      - en la Pi: `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`;
      - en Windows: `ssh-keygen -lf C:\ProgramData\ssh\ssh_host_ed25519_key.pub`.
    - Una llave cambiada se trata como hoy.
14. **CheckDenied** no aplica: es el terminal manual. La UI lo dice junto a la orden (texto de Front).

### Carpetas

15. **Por nombre, no por id.** Coincide con la preferencia de Front.
    - `Device.folder` ya es el nombre, el export/import lleva el nombre y un filtro por carpeta ya es por nombre.
    - Un id solo daría referencias estables al renombrar, y aquí renombrar ya mueve los hosts en la misma transacción.
16. **Tabla nueva** `host_folders(name TEXT PRIMARY KEY COLLATE NOCASE, created_at TEXT)`.
    - `hosts.folder` sigue siendo texto, sin llave foránea: agregarla exige reconstruir `hosts` en SQLite.
    - El servicio mantiene el invariante en cada transacción: todo `hosts.folder` no vacío existe en `host_folders` con el mismo texto.
17. **Reglas de nombre.**
    - Las de hoy: `^[A-Za-z0-9 _.-]{1,48}$` y sin espacios en los extremos.
    - Únicas sin distinguir mayúsculas. NOCASE de SQLite basta porque son solo ASCII.
    - Un solo nivel. «Sin carpeta» es `folder` vacío y no se lista.
    - Tope de 1000 carpetas (`hosts.err.folders_full`).
18. **Comportamiento.**
    - `RenameHostFolder` mueve sus hosts. Si el nombre nuevo es otra carpeta → AlreadyExists: no se fusiona; para eso está `MoveHosts`. Cambiar solo mayúsculas está permitido.
    - `DeleteHostFolder` deja los hosts sin carpeta y nunca borra un host. Con hosts y sin `confirm` → FailedPrecondition con la cuenta. Front lo pedía sin `confirm`; se agrega por el mismo motivo que `ExportBackupRequest.confirm`: el núcleo no confía en que el cliente preguntó.
    - `MoveHosts` admite de 1 a 5000 ids y es todo o nada. Un id que no existe → NotFound. Si el destino no existe se crea; vacío = sin carpeta.
    - `PutDevice`, `MoveHosts` y el import **crean la carpeta que falte**. Si ya existe con otras mayúsculas, el host toma el nombre guardado. Así `hosts edit --folder X` y la UI de hoy siguen funcionando igual.
    - El export no lleva carpetas vacías, porque exporta hosts.

### Migraciones de SQLite

19. Dos archivos nuevos en `internal/store/migrations`, con número fijo para que 44c y 44d no choquen:
    - `0009_host_startup.sql`: `ALTER TABLE hosts ADD COLUMN startup_command TEXT NOT NULL DEFAULT '';`
    - `0010_host_folders.sql`:
      - crea `host_folders`;
      - siembra con `INSERT OR IGNORE … SELECT folder, MIN(created_at) FROM hosts WHERE folder <> '' GROUP BY folder ORDER BY folder`. Si hoy hay «Lab» y «lab», queda la primera en orden binario, «Lab»; hoy el filtro ya las trata como una;
      - normaliza `UPDATE hosts SET folder = (SELECT name FROM host_folders f WHERE f.name = hosts.folder) WHERE folder <> ''`.

### Auditoría (sin secretos)

| Acción | Objetivo | Detalle |
|---|---|---|
| `credential.keygen` | id | `type=ssh-ed25519 fingerprint=SHA256:…` (la huella de la **pública**) |
| `credential.pubkey` | id | `fingerprint=SHA256:…` |
| `vault.backup_export` (la que ya existe) | ruta | suma `ssh_keys_omitted=N` |
| `hosts.crear` / `hosts.editar` (las de hoy) | id | lo de hoy, más `platform=P` y `startup=%q` si hay orden |
| `hosts.importar` (la de hoy) | ruta | suma `with_startup=N` |
| `terminal.open` (la de hoy) | nombre | suma `host=<id>` y `startup=%q` (o `startup=none`) |
| `terminal.failed` (la de hoy) | nombre | motivo `startup changed` o `host and address` |
| `hostfolder.create` | nombre | `origin=user\|put\|move\|import` |
| `hostfolder.rename` | nombre viejo | `to=%q hosts=N` |
| `hostfolder.delete` | nombre | `unfiled=N` |
| `hosts.move` | carpeta destino (vacía = `-`) | `n=N ids=<hasta 50>…` |

- La orden de inicio va en texto porque no es un secreto (regla 9). La UI avisa que no lleve secretos: queda en la auditoría y en la grabación.
- La grabación del terminal marca `orden de inicio: …` al abrir, porque no pasa por `rec.Input`.
- Las acciones nuevas van en inglés (idioma canónico); las de hosts de la fase 29b conservan su nombre.

## Bloques

Cada PR deja `main` en verde, con TDD y al menos una mutación a mano por lógica nueva. El proto de toda la fase ya está en esta rama, así que los bloques no tocan `api/proto` salvo para corregir algo.

| PR | Contenido | Pruebas que lo cierran | Riesgos |
|---|---|---|---|
| **44a** proto, bóveda y keygen | <br>• Esta rama: plan, ADR 0013 y proto + `gen/`. <br>• `internal/vault/keygen.go`: `GenerateKey` y `PublicKey`; `Info.HasPassword`. <br>• `vault/backup.go`: omite llaves y devuelve la cuenta. <br>• `core/respaldo.go`: estado `llave_privada` y `ssh_key_dropped`. <br>• `core/services.go`: `GenerateKeyCredential` (etiqueta reservada → como `PutCredential`), `GetCredentialPublicKey`, `kind` en la lista, rechazo de `ssh_private_key` y del reemplazo de una `key`. <br>• i18n es/en de los mensajes nuevos. <br>• `docs/security/CRYPTO.md` (formato) y `THREAT_MODEL.md` (la privada en memoria de Go al generar y firmar). | <br>• La pública firma y verifica contra la privada guardada. <br>• Tras `GenerateKey`, un `grep` de la privada (PEM y semilla) en el archivo de la bóveda, la auditoría y el `.mcvault` no encuentra nada. <br>• El respaldo de una bóveda con una `key` y una contraseña + llave escribe 1 sin llave y cuenta 2. <br>• Un `.mcvault` armado a mano con llave entra sin ella. <br>• `PutCredential` con llave → InvalidArgument y nada guardado. <br>• Mutación: quitar el filtro del respaldo hace fallar la prueba del grep. | Copias de la privada en el heap de Go (ver ADR). Una credencial vieja con contraseña + llave pierde la llave en el respaldo: se avisa con la cuenta. |
| **44b** solo publickey + simulador | <br>• `test/simulator`: `Config.AuthorizedKeys []ssh.PublicKey` (`PublicKeyCallback`), `Config.NoPassword` (sin `PasswordCallback`), `Config.AuthLog *[]string` (`AuthLogCallback`, método por intento). <br>• `exec` con o sin PTY: `Config.Exec func(cmd string) string`, que anota en `Recorder` `!exec pty=<bool> <cmd>`, responde, manda `exit-status` 0 y cierra. <br>• `assist/rotate.go`: `--update-cred` sobre una `key` → FailedPrecondition. | <br>• Con una credencial `key` contra el simulador, `AuthLog` tiene solo `none`/`publickey` y `Attempts == 0`. <br>• Contra un simulador que solo acepta password, una `key` falla con `ErrAuth` sin mandar contraseña. <br>• Mutación: agregar `PasswordCallback` aunque no haya contraseña hace fallar la primera. | El simulador es IOS: `exec` es solo para estas pruebas, sin emular un shell. |
| **44c1** hosts genéricos | <br>• `devices/hosts.go`: `linux`/`windows`, `StartupCommand` y su validación en `Clean`. <br>• `devices.FieldError` como `i18n.Coded` con `field` en la metadata (9b). <br>• `HostFields`: columna `startup_command` al final; el CSV acepta el encabezado viejo; «igual» compara la orden; `has_startup_command` en la vista previa. <br>• Migración `0009_host_startup.sql`. <br>• `service/inventory`: columna, `hostFromPB` y la vuelta, auditoría. <br>• `service/hosts.go` (compartido): `GenericHostAt` y `SavedHost`. <br>• Rechazo en `patrolSvc.validate` y en el arranque del cambio asistido. | <br>• Tabla de órdenes: válidas, 256 y 257 puntos de código (con letras de varios bytes), `\t`, `\n`, `\r`, NUL, DEL, U+0085, U+202A, U+202E, U+2066, U+2069, U+200B, U+200F, U+FEFF, espacio al borde, en un host `ios-xe`. <br>• `PutDevice` con una orden inválida → InvalidArgument con `metadata.field = "startup_command"`; lo mismo para `name`. <br>• Ida y vuelta export/import con orden; un CSV viejo de 8 columnas sigue entrando; la vista previa marca `has_startup_command` y una fila con orden inválida sale en `errors` con `field = startup_command`. <br>• Un trabajo de cada tipo contra un host `linux` → InvalidArgument con su nombre. <br>• Un playbook con `platforms: [linux]` sigue rechazado. | La dirección del trabajo puede venir en otra forma que la de la libreta (mayúsculas, IPv4 mapeada): se normaliza igual que `canonAddr`. |
| **44c2** terminal | <br>• `transport`: `CommandSize`, parámetro `term` en `ShellSize` y `key_type` en `HostKeyError`. <br>• `service/terminal`: `host_id`, `expected_startup_command`, sus errores, `xterm-256color` en genéricos, auditoría y marca en la grabación. | Contra el simulador de 44b: <br>• con orden, se ve `!exec pty=true <orden>` y la salida llega al stream; <br>• sin orden, shell como hoy; <br>• `expected` distinto → FailedPrecondition y **cero** conexiones al simulador; <br>• `host_id` con `address`, con `port` o con `credential_id` (tres casos) → InvalidArgument `terminal.err.host_and_address`, sin auditoría de apertura ni conexión al simulador; <br>• primera vez → huella con `key_type`, y con la huella aceptada conecta; <br>• la auditoría tiene `startup=` y ningún secreto. | El fin de la orden cierra la sesión: la UI debe mostrar «sesión terminada» y no un error. |
| **44d** carpetas | <br>• Migración `0010_host_folders.sql`. <br>• `service/inventory/folders.go`: las cinco RPC. <br>• Crear la carpeta que falte en `PutDevice` y en el import (`folders_created`). <br>• Auditoría. | <br>• Migración con «Lab»/«lab» y una vacía. <br>• Renombrar mueve hosts; renombrar a otra existente → AlreadyExists; cambiar solo mayúsculas funciona. <br>• Borrar sin `confirm` con hosts → FailedPrecondition y nada cambia; con `confirm` los hosts siguen y quedan sin carpeta. <br>• `MoveHosts` con un id falso no mueve nada. <br>• El import con carpeta nueva la crea una vez. <br>• Invariante comprobado tras cada operación (prueba de propiedad con secuencias al azar). | Choque con 44c1 en `service/inventory`: 44d va después de 44c1. |
| **44e** mctl | <br>• `cmd/mctl/vault`: `cred keygen --label L --user U` (imprime id y pública) y `cred pubkey ID` (solo la línea, para `>> authorized_keys`); `cred list` muestra el tipo. <br>• `cmd/mctl/devices`: `--platform linux\|windows`, `--startup-command` en `hosts add/edit` (vacío lo borra); `hosts folder list\|add NAME\|rename OLD NEW\|rm NAME [--yes]` (sin `--yes` y con hosts, dice cuántos y sale con 1); `hosts mv --folder F ID...` (`--folder ""` = sin carpeta). <br>• Ayuda es/en y sus golden. | <br>• Golden de la ayuda. <br>• `cred pubkey` de punta a punta contra el núcleo de prueba. <br>• `hosts folder rm` sin `--yes` no borra. <br>• noegress (sin `net` en `cmd/mctl`). | `cred pubkey` debe imprimir solo la línea, sin adornos, para poder redirigirla. |
| **44f** punta a punta y Windows | <br>• Prueba de punta a punta en `internal/core`: `GenerateKeyCredential` → pública al simulador → `PutDevice` `windows` con `cmd /c echo macuahuitl-ok` → `OpenTerminal{host_id, expected}` → llega `macuahuitl-ok`, `AuthLog` solo publickey y la auditoría completa. <br>• Validación en VM (Release), abajo. | La prueba en CI y el informe de la VM. | La VM no tiene WSL: la orden real del dueño se valida en su equipo. |

**Orden.** 44a va primero; 44b puede ir en paralelo con 44a. 44c1 va antes de 44c2 y de 44d. 44e va al final, o en paralelo una vez que esté cada RPC. 44f cierra. Como máximo tres agentes a la vez.

## Validación en Windows (Release)

VM local con la ISO de evaluación de Windows 11 (como en la fase 43). Al terminar se borran la ISO y la VM.

1. Instalar OpenSSH Server (`Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`) y arrancar `sshd`.
2. Usuario estándar `prueba`: la pública de `mctl cred pubkey` en `C:\Users\prueba\.ssh\authorized_keys`.
3. Usuario administrador: la pública en `C:\ProgramData\ssh\administrators_authorized_keys`, con `icacls … /inheritance:r /grant Administrators:F /grant SYSTEM:F`. Sin eso, sshd la ignora.
4. Huella confirmada contra `ssh-keygen -lf C:\ProgramData\ssh\ssh_host_ed25519_key.pub`.
5. Host `windows` con orden `cmd /c echo macuahuitl-ok`: aparece la salida y la sesión termina sola. Otra con `cmd` sola deja un shell interactivo con PTY (ConPTY).
6. `PasswordAuthentication no` en `sshd_config`: sigue entrando. En el registro `OpenSSH/Operational` solo aparece publickey.
7. Una orden distinta en la UI y en la libreta (editada entre medio) no conecta.

La Pi y `wsl -d Ubuntu-26.04 --cd ~` en zylant-box los valida el dueño en su red.

## Contrato para Front (proto → UI)

| Proto | UI (propuesta de Front) | Notas |
|---|---|---|
| `CredentialInfo.kind` (`"password"`/`"key"`) | `Credential.kind` | igual |
| `VaultService.GenerateKeyCredential{label, username}` → `{id, public_key}` | `createKeyCredential(label, username)` → `{id, publicKey}` | igual |
| `VaultService.GetCredentialPublicKey{id}` → `{public_key}` | `credentialPublicKey(id)` → string | igual |
| `PutCredentialRequest.ssh_private_key` | — | obsoleto: el núcleo lo rechaza |
| `ExportBackupResponse.ssh_keys_omitted`, `VaultBackupItem.ssh_key_dropped`, estado `llave_privada` | aviso en el respaldo de la bóveda | nuevo |
| `Device.platform` suma `linux`, `windows` | `HostPlatform` | igual |
| `Device.startup_command` | `Host.startCommand` | el cable usa el nombre del dueño; `metadata.field = "startup_command"` (9b) |
| `ImportHostItem.has_startup_command` (+ `host.startup_command`) | vista previa del import | nuevo |
| `ApplyImportHostsResponse.folders_created` | resumen del import | nuevo |
| `ListHostFolders` → `folders[{name, host_count}]` | `listFolders()` → `{name, count}[]` | `count` = `host_count`; incluye vacías, sin «Sin carpeta» |
| `CreateHostFolder{name}` → `{folder}` | `createFolder(name)` | igual |
| `RenameHostFolder{name, new_name}` → `{folder}` | `renameFolder(old, new)` | igual |
| `DeleteHostFolder{name, confirm}` → `{hosts_unfiled}` | `deleteFolder(name)` | **suma `confirm`**, obligatorio si tiene hosts (regla 18) |
| `MoveHosts{ids, folder}` → `{moved, folder_created}` | `moveHosts(ids, folder)` | igual; `folder` vacío = sin carpeta |
| `TerminalOpen.host_id` | `TerminalOpenRequest.hostId` | exclusivo con dirección, puerto y credencial (regla 12) |
| `TerminalOpen.expected_startup_command` | — | **nuevo**: la orden que la UI mostró; si no coincide, no conecta |
| `HostKeyError` metadata `key_type` | diálogo de huella | nuevo (regla 13) |

## Fuera de esta fase

- Enable en credenciales `key`.
- Llaves RSA o ECDSA.
- Llave con frase.
- Rotar una llave conservando el id.
- Agente SSH.
- Reenvío de puertos o de X11.
- Carpetas anidadas.
- Exportar carpetas vacías.
- Abrir `linux`/`windows` a otras herramientas que no sean el terminal.
- Terminal en mctl.
- macOS.
