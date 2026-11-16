# ADR 0012: Multiplataforma (primero Windows)

Fecha: 2026-11-16 · Estado: propuesto

## Contexto

Hasta la v1.0.0, MACUAHUITL es solo para Linux. Tras el anuncio de la v1.0.0, el dueño dio el visto bueno para empezar con Windows. Será en el mismo repo, con build tags por sistema. macOS viene después y no entra en este ADR, salvo para no cerrarle el camino.

Medición de hoy (`GOOS=windows CGO_ENABLED=0 go build ./cmd/... ./internal/...` sobre 73dec0b): compilan todos los paquetes menos cinco.

| Paquete | Qué usa de Linux |
|---|---|
| `internal/sys` | `O_NOFOLLOW`, `mlockall`, `RLIMIT_MEMLOCK`, `prctl(PR_SET_DUMPABLE)`, `renameat2(RENAME_NOREPLACE)`, `Stat_t` (dueño y `Nlink`), `/proc/swaps`, `/sys/power/resume` |
| `internal/ipc` | `flock`, `umask`, `SO_PEERCRED` |
| `internal/diag` | `Setpgid` y `kill(-pgid)` para cortar el árbol de procesos; `PATH` fijo de Unix |
| `internal/diag/serialcon` | termios sobre `/dev/ttyUSB*` y `/dev/ttyACM*` |
| `internal/core/power` | compila (godbus es Go puro), pero en Windows no hay logind: hoy caería en `Noop` sin avisar |

`internal/transport/guard_control.go` compila tal cual: `syscall.RawConn` existe en Windows, y el guard decide por la dirección, no por el socket. No hay que tocarlo.

Además, hay supuestos que compilan pero fallan en ejecución. Son los más peligrosos, porque ninguna prueba de compilación los detecta:

- `os.Getuid()` devuelve -1 en Windows. Lo usan `ipc.Listen` y `service.ProcUID`. La negativa a correr como root (`os.Geteuid() == 0` en `cmd/macuahuitld`) nunca se dispararía.
- `fi.Mode().Perm()` en Windows solo refleja el atributo de solo lectura (0666 o 0444). La regla de la carpeta de salidas (`service/outputs.go`: dueño, modo 0700, ancestros sin escritura de otros) rechazaría todo o aceptaría cualquier cosa.
- Rutas XDG (`core/paths.go`) y `XDG_RUNTIME_DIR` para el socket.
- Las herramientas externas tienen otros nombres y banderas, y su salida sale en el idioma del sistema (`LANG=C` no aplica).

## Decisión

### Forma del código

- Lo que cambia por sistema vive en archivos `_linux.go` y `_windows.go`, dentro de los mismos paquetes de hoy: `internal/sys`, `internal/ipc`, `internal/diag`, `internal/diag/serialcon` y `internal/core/power`. La API de cada paquete no cambia; los llamadores no llevan build tags.
- `golang.org/x/sys/windows` (BSD, el módulo ya es dependencia) solo se importa en esos paquetes. Un caso nuevo en archcheck lo hace cumplir, igual que noegress con `net`.
- Dependencia nueva: `github.com/Microsoft/go-winio` (MIT, la usa Docker), solo para el named pipe; antes de agregarla se lee su LICENSE. El resto de las llamadas sale de `x/sys/windows`.
- Rutas en Windows: `%LOCALAPPDATA%\MACUAHUITL\{config,data,state}`. Nunca `%APPDATA%`: esa carpeta es *roaming*, y en un dominio subiría la bóveda a un servidor.

### (a) Canal local: named pipe con ACL y verificación del cliente

Hoy el ADR 0003 exige tres cosas: que solo el usuario pueda conectarse, que el núcleo verifique la identidad del cliente (`SO_PEERCRED`) y que no haya ningún puerto TCP.

**Decisión: named pipe `\\.\pipe\macuahuitl-<SID del usuario>`.**

- **DACL protegida.** Solo el SID del usuario tiene acceso (`D:P(A;;GA;;;<SID>)`). Ni Everyone, ni Usuarios, ni herencia.
- **Clientes remotos rechazados** con `PIPE_REJECT_REMOTE_CLIENTS`. Un named pipe es alcanzable por SMB si no se rechaza.
- **Contra la suplantación del pipe.** La primera instancia se crea con `FILE_FLAG_FIRST_PIPE_INSTANCE`. Si el nombre ya existe, otro proceso lo tomó: el núcleo no arranca y lo dice. Esto también reemplaza al `flock` de instancia única.
- **El núcleo verifica al cliente.** Por cada conexión llama a `GetNamedPipeClientProcessId` y luego a `OpenProcess` y `OpenProcessToken`. Si el SID del token no es el del núcleo, la conexión se cierra antes de hablar gRPC. Es el equivalente directo de `SO_PEERCRED` con comparación de UID.
- **Los clientes verifican al servidor** (mctl y la app). El espacio de nombres de los pipes es global a la máquina, así que los clientes también hacen la verificación inversa con `GetNamedPipeServerProcessId` y el SID del token, para no hablarle a un pipe que otro usuario creó primero. En Linux esto lo cubre la carpeta `$XDG_RUNTIME_DIR` (0700); en Windows no hay carpeta, por eso la verificación es explícita.
- **Detalles por confirmar en 43a.** Que go-winio ponga `FILE_FLAG_FIRST_PIPE_INSTANCE` y `PIPE_REJECT_REMOTE_CLIENTS` por omisión se comprueba con una prueba, no se da por hecho. Si alguno falta, se crea el pipe con `x/sys/windows` en vez de go-winio.

**AF_UNIX de Windows 10+ no se elige.** Go lo soporta (`net.Listen("unix", …)`), pero Windows no tiene `SO_PEERCRED`. Lo único parecido es el ioctl `SIO_AF_UNIX_GETPEERPID`: está poco documentado y Go no lo expone. Además, que la ACL del archivo del socket se aplique en `connect` no está documentado con la claridad que exige un canal que da acceso a la bóveda. El named pipe es el mecanismo de IPC de Windows con ACL y API de identidad documentadas.

### (b) Endurecimiento de memoria: lo que hay y lo que no

| Linux hoy | Windows | Equivalencia |
|---|---|---|
| `mlockall(MCL_CURRENT\|MCL_FUTURE)` | No existe «bloquear todo». `VirtualLock` bloquea rangos, con tope en el *working set* mínimo, que se sube con `SetProcessWorkingSetSizeEx` sin privilegios. | Parcial. Se suben los mínimos y se bloquean los rangos del material de llaves de la bóveda, no todo el heap. Si falla, aviso como hoy `harden.mlockall`. |
| `PR_SET_DUMPABLE=0` y `RLIMIT_CORE=0` | `WerAddExcludedApplication(…, FALSE)` (HKCU, sin admin) excluye al núcleo de los reportes de error de Windows. `SetErrorMode(SEM_NOGPFAULTERRORBOX)` evita el diálogo. | Parcial: sin volcados de WER. |
| Otro proceso del mismo usuario no puede leer la memoria (Yama, no dumpable) | **No hay equivalente sin admin ni firma especial.** Cualquier proceso del mismo usuario puede hacer `OpenProcess` + `ReadProcessMemory`. | **Ninguna.** Se dice tal cual en el modelo de amenazas: en Windows, un malware con la sesión del usuario lee la bóveda abierta. |
| Avisos de swap e hibernación | Avisos de *pagefile* sin cifrar (`EncryptPagingFile`, BitLocker) y de `hiberfil.sys`, leídos sin admin donde se pueda; si no se puede leer, se avisa que no se pudo comprobar. | Equivalente en avisos. |

### (c) Permisos: ACL en lugar de 0700/0600

- **Archivos y carpetas propios.** Se crean con un descriptor de seguridad explícito: dueño el usuario y DACL protegida con el usuario, SYSTEM y Administradores. Esos dos ya tienen acceso a todo el perfil y pueden tomar posesión de todos modos; quitarlos no protege y rompe los respaldos de Windows. Es el equivalente de 0700/0600 con `umask`.
- **Regla de la carpeta de salidas** (`service/outputs.go`). En Windows no mira `Mode().Perm()`, sino la ACL: dueño igual al SID del usuario, y ninguna ACE que dé acceso a otro SID fuera de usuario, SYSTEM y Administradores. Los ancestros se aceptan si ningún SID ajeno tiene escritura en ellos. Los mensajes `prefs.outputs.permisos*` necesitan su variante de Windows, con la orden `icacls` en vez de `chmod`.
- **`openregular` y los enlaces.** Abre con `CreateFile(…, FILE_FLAG_OPEN_REPARSE_POINT)`, para no seguir el último componente si es enlace simbólico o *junction*. Con `GetFileInformationByHandle` rechaza `FILE_ATTRIBUTE_REPARSE_POINT` y lo que no sea archivo regular. `HardLinked` usa `NumberOfLinks` y `Owner` usa el SID del dueño en lugar del uid; la firma cambia a un tipo opaco por sistema.
- **`RenameNoReplaceIn`** pasa a `MoveFileEx` sin `MOVEFILE_REPLACE_EXISTING`, que en Windows ya falla si el destino existe. Es más simple que `renameat2`.
- **Identidad del proceso.** `ProcUID` y la negativa a correr como root se reemplazan por el SID del token. El núcleo **se niega a correr elevado** (token con `TokenElevation`), igual que hoy se niega a correr como root.

### (d) Inhibir la suspensión y enterarse de suspensión y bloqueo

- **Inhibir**: `PowerCreateRequest` + `PowerSetRequest(PowerRequestSystemRequired)`. Va mientras corre un trabajo de Patrol o una transferencia, igual que el bloqueo de logind. Se prefiere a `SetThreadExecutionState` porque se ata a un handle y no al hilo; en Go un goroutine cambia de hilo.
- **Enterarse**: hoy `power.Watch` llama `onSleep` y `onLock` (el bloqueo de pantalla cierra la bóveda). En Windows, una ventana *message-only* (`HWND_MESSAGE`, invisible) en un hilo fijo recibe `WM_POWERBROADCAST`/`PBT_APMSUSPEND` y, tras `WTSRegisterSessionNotification`, `WM_WTSSESSION_CHANGE`/`WTS_SESSION_LOCK`. No necesita admin.
- Si algo de esto no se puede tomar, se avisa como faltante, igual que `Noop`. No se queda callado.

### (e) Consola serie COMx

- **Abrir**: `CreateFile(\\.\COMn)` + `SetCommState` (DCB 9600 8N1 sin control de flujo) + `SetCommTimeouts`, con `x/sys/windows`. Es código propio y sin dependencia nueva, como el termios de hoy.
- **Listar**: se lee `HKLM\HARDWARE\DEVICEMAP\SERIALCOMM`, legible sin admin. Las consolas USB de los Catalyst e ISR y los adaptadores FTDI/Prolific/CP210x aparecen ahí cuando su driver está instalado. El driver lo instala el usuario y la app no lo empaqueta.

### (f) Herramientas externas

- **Rutas.** Se resuelven a rutas absolutas conocidas, nunca por el `PATH` del usuario (secuestro de `PATH`). Primero `%SystemRoot%\System32` para `ping.exe` y `tracert.exe`; luego `%ProgramFiles%\Nmap`, `%ProgramFiles%\Wireshark` y `%ProgramFiles%\iperf3`. El entorno del hijo lleva solo `SystemRoot`, `TEMP` y un `PATH` mínimo.
- **Banderas.** Las arma `diag.Build` por sistema:
  - `ping`: `-n` en lugar de `-c`, `-w` en milisegundos;
  - `tracert`: `-d -h N -w ms` en lugar de `traceroute -n -m`; en Windows no hay `tracepath`.
- **Salida localizada.** La salida de `ping` y `tracert` sale en el idioma de Windows. Se muestra tal cual; ningún parser del núcleo depende de ella. Si alguno llega a depender, ese parser se vuelve multidioma con fixtures o se marca solo Linux.
- **Cortar el árbol de procesos**: un *Job Object* con `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, que reemplaza `Setpgid` y `kill(-pgid)`. Windows no tiene un SIGTERM para procesos sin consola, así que cancelar es terminar el job. Por eso la captura siempre lleva condición de parada propia (`dumpcap -a duration:N`): termina sola y cierra bien el pcapng. Cancelar a mano puede dejar el último bloque truncado, y el visor debe tolerarlo.
- **Licencias, nada empaquetado.**
  - nmap (NPSL) se trae Npcap, cuya licencia **no es permisiva** y prohíbe redistribuirlo sin licencia OEM.
  - Wireshark/dumpcap también se apoya en Npcap.
  - iperf3 no tiene versión oficial para Windows.

  Las tres son dependencias **opcionales que instala el usuario**. El instalador nunca las incluye. Sin ellas, cada herramienta falla con el `diag.err.install` de hoy, con el enlace de descarga.

### (g) Arranque del núcleo sin servicio ni admin

- **Arranque**: una entrada en `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` lanza el núcleo al iniciar sesión. Además, la app y mctl lo lanzan bajo demanda si no encuentran el pipe.
- **Por qué no una tarea programada.** Release propuso una tarea al iniciar sesión, pero crear una tarea con disparador *ONLOGON* puede pedir elevación según la política del equipo. La clave `Run` de HKCU nunca la pide y es el equivalente de `systemctl --user enable`.
- Nada de servicio de Windows: correría como SYSTEM o con otra cuenta, y eso choca con el ADR 0004.
- El núcleo corre sin consola: es un binario `-H windowsgui`, o lo lanza la app con `CREATE_NO_WINDOW`.

### (h) Puertos 21 y 69

- **Puertos bajos sin privilegios.** Windows **no** tiene puertos privilegiados: un usuario normal puede escuchar en 21 y 69. El impedimento real es el Firewall de Windows. La primera escucha dispara su diálogo, y permitir la entrada pide admin.
- **Decisión.** En Windows el servidor escucha en el puerto que el usuario elija, 69 o 21 incluidos, con la misma IP explícita, duración acotada y auditoría de siempre. La regla de entrada del firewall es un paso del usuario, documentado con su orden exacta: `netsh advfirewall firewall add rule … program="…\macuahuitld.exe" dir=in action=allow localip=<IP>`. Se hace una vez, como admin, o aceptando el diálogo.
- **No se usa `netsh interface portproxy`.** Solo redirige TCP, así que no sirve para TFTP (UDP 69), pide admin y deja una regla persistente que sobrevive a la app.

### (i) Qué puede faltar en la primera versión de Windows

La primera versión de Windows se llama **beta**. No promete paridad. Puede salir sin:

- captura de paquetes, hasta que el usuario instale Wireshark con Npcap; nmap e iperf3, igual;
- el bloqueo de toda la memoria del proceso: solo se bloquean los rangos del material de llaves (ver b);
- protección contra procesos del mismo usuario, que no existe en Windows sin admin (ver b);
- la consola serie, si su validación en hardware real no está lista: se marca «sin validar» y no se bloquea la beta;
- ARM64: solo amd64 al principio.

Todo lo demás debe funcionar igual que en Linux. Eso incluye la bóveda, Patrol, el cambio asistido, los paquetes `.mpack`, el enmascarado, la auditoría y el terminal SSH. Esa es la vara del CI.

### (j) CI

- **Job nuevo `windows`** en `ci.yml`, con `windows-latest`. Compila `./cmd/... ./internal/... ./ui/bridge/...`, corre `go test` sobre todos los paquetes, y además noegress, archcheck y gofmt. Son herramientas Go y corren igual.
- **Sin -race.** En Windows, -race exige cgo y gcc. La cobertura con -race sigue en los jobs de Linux, que ya la tienen completa.
- **Pruebas exclusivas de Linux.** Las que dependen de Linux (termios, `SO_PEERCRED`, `/proc`) llevan `//go:build linux`. Cada una tiene su par `_windows_test.go` con el equivalente; nada se salta en silencio.
- **Mientras dure 43a**, el job arranca con `continue-on-error` y una lista de paquetes que crece PR a PR. Al cerrar 43a pasa a ser obligatorio en la protección de `main`, junto a go, ui y proto.
- **En el job `go-checks` de Linux**, un paso barato `GOOS=windows go vet ./...` detecta antes de llegar a Windows que algo dejó de compilar.

### Instalador y firma

**Sección de Front (app Wails, WebView2, instalador y su CI): pendiente de integrar.**

Opciones de firma, a decidir por el dueño. Los costos son aproximados y se confirman antes de comprar.

| Opción | Costo | SmartScreen | Notas |
|---|---|---|---|
| Azure Artifact Signing (antes Trusted Signing) | ~9.99 USD/mes, plan Basic | Reputación que se acumula | **Solo personas físicas de EE. UU. y Canadá**, u organizaciones de EE. UU., Canadá, UE o Reino Unido. Una persona física en México hoy no califica; habría que confirmarlo. |
| Certificado OV | ~150–300 USD/año | Reputación que se acumula por firma | La llave va en token o HSM (exigencia del CA/B Forum desde 2023). |
| Certificado EV | ~400+ USD/año | **Igual que OV** desde agosto de 2024: ya no da reputación inmediata | No vale el sobreprecio para evitar SmartScreen. |
| SignPath Foundation | Gratis para proyectos de código abierto que califiquen | Igual que OV | El proyecto es Apache-2.0; hay que solicitarlo y cumplir sus reglas de build. |
| Primera beta sin firmar | 0 | Aviso «Windows protegió su PC» | Se mitiga con las sumas SHA-256 y la atestación SLSA que ya publica `release.yml`, y un aviso claro en la página de descarga. |

## Consecuencias

- Hay dos implementaciones de cada pieza sensible: canal, permisos, memoria y apertura de archivos. Cada una con sus pruebas en su sistema, y el CI de Windows las corre.
- El modelo de amenazas (`docs/security/THREAT_MODEL.md`) gana una sección de Windows. Lo que **no** se protege allí (lectura de memoria por procesos del mismo usuario) queda escrito, no implícito.
- Se agrega una dependencia nueva (go-winio, MIT).
- macOS reutiliza las partes POSIX de Linux: `flock`, `umask`, `LOCAL_PEERCRED` en vez de `SO_PEERCRED`, termios. Tendrá su propio ADR o una enmienda a este.
