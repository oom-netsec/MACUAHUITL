# ADR 0012: Multiplataforma (primero Windows)

Fecha: 2026-11-16 · Estado: aceptado

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
- `golang.org/x/sys/windows` (BSD, el módulo ya es dependencia) solo se importa en esos paquetes y en `ui` (el aviso de WebView2 faltante). Un caso nuevo en archcheck lo hace cumplir, igual que noegress con `net`; mientras dure 43a, `tools/ci/winsys.sh` lo revisa también en los archivos `_windows.go`, que archcheck no carga en Linux.
- Dependencia nueva: `github.com/Microsoft/go-winio` (MIT, la usa Docker), solo para el named pipe; antes de agregarla se lee su LICENSE. El resto de las llamadas sale de `x/sys/windows`.
- Rutas en Windows (el spec §14 hoy es XDG):

  | Ruta | Carpeta |
  |---|---|
  | Config | `%LOCALAPPDATA%\MACUAHUITL\config` |
  | Data (bóveda) | `%LOCALAPPDATA%\MACUAHUITL\data` |
  | State (auditoría, registros, caché de WebView2) | `%LOCALAPPDATA%\MACUAHUITL\state` |
  | Outputs | `%USERPROFILE%\MACUAHUITL\outputs`, como `~/MACUAHUITL/outputs` en Linux |

  - **Nada va en `%APPDATA%`**, que es *roaming*: en un dominio subiría la bóveda a un servidor. Config tampoco va ahí, aunque Front lo propuso por ser chica: guarda los paquetes `.mpack` y los playbooks del usuario, que son contenido que se ejecuta, y un perfil roaming dejaría que otro equipo del dominio los cambie.
  - **No hay carpeta runtime**: el named pipe no la necesita, y `FILE_FLAG_FIRST_PIPE_INSTANCE` hace de candado de instancia única.

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
| `mlockall(MCL_CURRENT\|MCL_FUTURE)` | No existe «bloquear todo». `VirtualLock` bloquea rangos, con tope en el *working set* mínimo, que se sube con `SetProcessWorkingSetSizeEx` sin privilegios. | Parcial. Se sube el mínimo del working set. Las llaves de la bóveda ya viven en buffers de memguard (`internal/secret`), que en Windows se bloquean con `VirtualLock` igual que con `mlock` en Linux. El resto del heap no queda bloqueado. Si no se puede subir el mínimo del working set, el fallo es fatal: memguard hace `panic` cuando `VirtualLock` falla, así que `Harden` devuelve error y el núcleo no arranca (`internal/secret` lo sube en `init()`, para que lo tengan también la UI y las pruebas). |
| `PR_SET_DUMPABLE=0` y `RLIMIT_CORE=0` | `WerAddExcludedApplication(…, FALSE)` (HKCU, sin admin) excluye al núcleo de los reportes de error de Windows. `SetErrorMode(SEM_NOGPFAULTERRORBOX)` evita el diálogo. | Parcial: sin volcados de WER. |
| Otro proceso del mismo usuario no puede leer la memoria (Yama, no dumpable) | **No hay equivalente sin admin ni firma especial.** Cualquier proceso del mismo usuario puede hacer `OpenProcess` + `ReadProcessMemory`. | **Ninguna.** Se dice tal cual en el modelo de amenazas: en Windows, un malware con la sesión del usuario lee la bóveda abierta. |
| Avisos de swap e hibernación | Avisos de *pagefile* sin cifrar (`EncryptPagingFile`, BitLocker) y de `hiberfil.sys`, leídos sin admin donde se pueda; si no se puede leer, se avisa que no se pudo comprobar. | Equivalente en avisos. |

### (c) Permisos: ACL en lugar de 0700/0600

- **Archivos y carpetas propios.** Se crean con un descriptor de seguridad explícito: dueño el usuario y DACL protegida con el usuario, SYSTEM y Administradores. Esos dos ya tienen acceso a todo el perfil y pueden tomar posesión de todos modos; quitarlos no protege y rompe los respaldos de Windows. Es el equivalente de 0700/0600 con `umask`. Lo hacen funciones de `internal/sys` con la misma firma en los dos sistemas:
  - `MkdirPrivate(path)` (la ruta debe ser absoluta, en los dos sistemas). Linux: `MkdirAll` 0700, como siempre. Windows: crea la carpeta y los padres que falten y les aplica la DACL protegida con herencia (`OI|CI`), para que lo que se cree dentro la herede. Las carpetas raíz del núcleo (Config, Data, State y la carpeta de salidas de fábrica, esta última solo si no está vacía) se crean así. La UI (WebView2) puede crear `MACUAHUITL\`, `config\`, `data\` o `state\` antes que el núcleo, con la ACL heredada. Si la carpeta ya existe:
    - Un enlace simbólico o una *junction* se rechaza (la ACL que se leería sería la del destino).
    - Si su dueño es el usuario o Administradores (el dueño por omisión de lo que crea un token elevado) se le **reaplica** la DACL, que además deja al usuario como dueño. `SetNamedSecurityInfo` la propaga a lo que ya hay dentro. Si ya es privada y heredable no se reaplica, para no recorrer el árbol en cada arranque.
    - Si el dueño es otro SID falla con `sys.err.not_owner` y el núcleo no arranca. Una carpeta propia nunca se rechaza solo por traer la ACL heredada.
  - `OpenNewPrivate(path)`, `OpenNewPrivateIn(root, name)` y `CreateTempPrivate(dir, patrón)` crean un archivo **que nace privado**. Linux: `OpenNew`, `OpenNewIn` y `os.CreateTemp`, es decir `O_EXCL|O_NOFOLLOW` y 0600. Windows: `CreateFile` con `CREATE_NEW` y `FILE_FLAG_OPEN_REPARSE_POINT` (no sigue enlaces ni pisa nada, y rechaza rutas UNC y de dispositivo) y un `SECURITY_ATTRIBUTES` con el descriptor completo (dueño el usuario, DACL protegida sin herencia, usuario, SYSTEM y Administradores). Proteger después de crear dejaría un hueco con la ACL heredada en el que otro usuario con acceso a la carpeta podría abrir el archivo y quedarse con el handle (Go abre con `FILE_SHARE_READ|WRITE`). Los usan todos los archivos con contenido sensible que se escriben fuera de las carpetas propias: exportaciones del usuario (`mctl backup export -o`, llaves de la CA, `mpack-keygen`, `WriteExport`, guardar desde la UI), archivos que se reciben o descargan a una carpeta elegida y los temporales de la bóveda que luego se renombran (el `rename` conserva la DACL). Un sistema de archivos sin ACL (FAT, exFAT) ignora el descriptor; los respaldos de la bóveda lo detectan con `ProtectNewStrict` y lo anotan como «sin permisos», como un vfat en Linux. `OpenNewPrivateIn` arma la ruta con el nombre de la carpeta abierta (`shortcut:` anotado en el código).
  - `ProtectFile(path)` (Linux: `Chmod` 0600; Windows: DACL protegida sin herencia) y `ProtectNew(path)` (Linux: nada, porque el archivo ya nació 0600; Windows: DACL protegida, tolerando FAT) son para un archivo que ya existe. Solo `mctl` las usa para los SVG, que no son secretos; ninguna ruta con secretos las necesita.
  - Para pruebas, no para producción: `IsPrivate` (Linux: sin bits de grupo ni otros; Windows: dueño el usuario, DACL protegida y solo los tres SID), `OnlyOwnAccess` (lo mismo sin exigir DACL protegida, para lo que hereda de una carpeta privada) y `ReadOnlyDir`, con el paquete `internal/sys/systest` que las usa.
  - Lo que se crea dentro de una carpeta hecha con `MkdirPrivate` (bóveda, base de datos, `known_hosts`, evidencias, respaldos por equipo) hereda la DACL y no llama a nada.
- **Regla de la carpeta de salidas** (`service/outputs.go`, `sys.PrivateDir`). En Windows no mira `Mode().Perm()`, sino la ACL: la carpeta no es un enlace simbólico ni una *junction*, dueño igual al SID del usuario, y ninguna ACE que dé acceso a otro SID fuera de usuario, SYSTEM y Administradores (cuentan también las ACE que solo se heredan, porque lo que se cree dentro las hereda, y las de «permitir» condicionales; cualquier tipo de ACE que no sea de negar y no se pueda interpretar cuenta como un SID ajeno). Los ancestros se aceptan si ningún SID ajeno tiene en ellos derechos de escritura que dejen reemplazar un hijo (crear archivos, borrar hijos, borrar la carpeta, cambiar la DACL o el dueño); se ignoran las ACE que no aplican a la carpeta misma, CREATOR OWNER y TrustedInstaller. Agregar solo subcarpetas (lo que Autenticados tiene en la raíz de `C:\`) no cuenta. La regla mira las ACE tal como las lee el sistema, sin evaluar la pertenencia a grupos del SID ajeno (`AccessCheck`). En Linux la regla no cambió: sigue en `service/outputs.go` con sus ganchos de prueba, y `sys.PrivateDir` aplica la misma en Linux sin que el servicio la use. Los mensajes `prefs.outputs.permisos*` y `ancestro_inseguro` tienen su variante `….windows` (la orden `icacls` en vez de `chmod`, el SID en vez del modo y el uid), elegida por `runtime.GOOS` donde se arma el error. `Owner` (uid) falla cerrado en Windows y solo queda para el gancho `FileOwner`, que Windows no usa.
- **`openregular` y los enlaces.** `OpenRegular` y `OpenRegularIn` **sí siguen enlaces**, en los dos sistemas, igual que en Linux: se usan con rutas que el usuario eligió (importar, adjuntar) y un enlace que él puso es una decisión suya. Rechazan las rutas UNC y de dispositivo antes de abrir, y lo que no sea un archivo regular. Lo que nunca sigue enlaces es **`OpenNew` y `OpenNewIn`**: abren con `O_EXCL` (en Linux, además, `O_NOFOLLOW`; en Windows, Go abre con `CREATE_NEW` y `FILE_FLAG_OPEN_REPARSE_POINT`), así que fallan si la ruta existe, aunque sea un enlace simbólico o una *junction*, y no pisan nada. `HardLinkedFile` usa `NumberOfLinks` del handle ya abierto, y `HardLinked(os.FileInfo)` es solo un filtro de listado que en Windows siempre dice que no.
- **`RenameNoReplaceIn`** pasa a `MoveFileEx` sin `MOVEFILE_REPLACE_EXISTING`, que en Windows ya falla si el destino existe. Es más simple que `renameat2`.
- **Identidad del proceso.** `ProcUID` y la negativa a correr como root se reemplazan por el SID del token. El núcleo **se niega a correr elevado** (token con `TokenElevation`), igual que hoy se niega a correr como root.
  - **Limitación conocida.** Una cuenta con UAC desactivado, o el Administrador integrado, tiene el token siempre elevado y no puede usar la app.
  - El núcleo lo dice con un mensaje claro: usar una cuenta estándar, o una de administrador con UAC activo, que arranca con token sin elevar. Así no queda un cierre sin explicación.

### (d) Inhibir la suspensión y enterarse de suspensión y bloqueo

- **Inhibir**: `PowerCreateRequest` + `PowerSetRequest(PowerRequestSystemRequired)`. Va mientras corre un trabajo de Patrol o una transferencia, igual que el bloqueo de logind. Se prefiere a `SetThreadExecutionState` porque se ata a un handle y no al hilo; en Go un goroutine cambia de hilo.
- **Enterarse**: hoy `power.Watch` llama `onSleep` y `onLock` (el bloqueo de pantalla cierra la bóveda). En Windows, una ventana *message-only* (`HWND_MESSAGE`, invisible) en un hilo fijo recibe, tras `RegisterSuspendResumeNotification`, `WM_POWERBROADCAST`/`PBT_APMSUSPEND` y, tras `WTSRegisterSessionNotification`, `WM_WTSSESSION_CHANGE`/`WTS_SESSION_LOCK`. No necesita admin.
- Una ventana message-only no recibe la difusión `WM_POWERBROADCAST`: se le llama `RegisterSuspendResumeNotification(hwnd, DEVICE_NOTIFY_WINDOW_HANDLE)` (Windows 8+), que además funciona con Modern Standby. Con Modern Standby, `PBT_APMSUSPEND` llega al entrar al estado de bajo consumo, que puede ser minutos después de apagarse la pantalla. Antes suele llegar `WTS_SESSION_LOCK`, que ya cierra la bóveda. Al cerrar, en `WM_CLOSE` y antes de `DestroyWindow`, se desregistran esa y la de WTS.
- Límites en Windows: no se puede bloquear la tapa ni la suspensión que pide el usuario (por eso el inhibidor devuelve `missing` vacío si `PowerSetRequest` funciona; al suspenderse por la tapa, `onSleep` ya pausa el trabajo). Una ventana message-only tampoco recibe `WM_QUERYENDSESSION`/`WM_ENDSESSION`, así que el apagado no llama a `onSleep`; se acepta, sin otra ventana.
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
  - El núcleo lanzado bajo demanda corre **separado** de quien lo lanzó (`DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW`, fuera de cualquier Job Object de la app). Si no, moriría al cerrar la UI y cortaría un trabajo de Patrol a medias.
  - El instalador da de alta la entrada de `Run` y la desinstalación la quita.
  - La app y la entrada de `Run` usan la ruta absoluta de `macuahuitld.exe`, en la misma carpeta que `macuahuitl.exe`; nunca lo buscan por el `PATH` (secuestro de `PATH`, como en f).
- **Por qué no una tarea programada.** Release y Front propusieron una tarea «al iniciar sesión». Crear una tarea propia no pide admin, pero el disparador *ONLOGON* sí puede pedir elevación, según la versión y la política del equipo. La clave `Run` de HKCU nunca la pide y es el equivalente de `systemctl --user enable`.
- Nada de servicio de Windows: correría como SYSTEM o con otra cuenta, y eso choca con el ADR 0004.
- **Sin consola.** El núcleo es un binario `-H windowsgui`, así que no tiene stdout ni stderr. Su registro va a `%LOCALAPPDATA%\MACUAHUITL\state\macuahuitld.log`, con la misma rotación que en Linux. La app lo enlaza para soporte.

### (h) Puertos 21 y 69

- **Puertos bajos sin privilegios.** Windows **no** tiene puertos privilegiados: un usuario normal puede escuchar en 21 y 69. El impedimento real es el Firewall de Windows. La primera escucha dispara su diálogo, y permitir la entrada pide admin.
- **Decisión.** En Windows el servidor escucha en el puerto que el usuario elija, 69, 21 y 162 incluidos, con la misma IP explícita, duración acotada y auditoría de siempre.
  - La regla de entrada del firewall es un paso del usuario, igual que hoy la regla de nftables: la app la muestra y nunca la aplica.
  - La orden exacta es `New-NetFirewallRule -DisplayName MACUAHUITL-TFTP -Direction Inbound -Program "…\macuahuitld.exe" -LocalAddress <IP> -Protocol UDP -LocalPort 69 -Action Allow`. Se corre una vez, como admin, o se acepta el diálogo del firewall.
  - Los textos de puertos privilegiados, `setcap` y nftables, de la UI y del núcleo, tienen su variante para Windows.
- **No se usa `netsh interface portproxy`.** Solo redirige TCP, así que no sirve para TFTP (UDP 69), pide admin y deja una regla persistente que sobrevive a la app.

### (i) Qué puede faltar en la primera versión de Windows

La primera versión de Windows se llama **beta**. No promete paridad. Puede salir sin:

- captura de paquetes, hasta que el usuario instale Wireshark con Npcap; nmap e iperf3, igual;
- el bloqueo de toda la memoria del proceso: solo se bloquean los rangos del material de llaves (ver b);
- protección contra procesos del mismo usuario, que no existe en Windows sin admin (ver b);
- la consola serie, si su validación en hardware real no está lista: se marca «sin validar» y no se bloquea la beta;
- ARM64: solo amd64 al principio;
- el escaneo SYN de nmap. En Windows necesita Npcap, que no es parte del producto, y su comportamiento sin admin depende de cómo se instaló. La beta esconde la opción SYN y deja el escaneo por conexión.

Limitaciones de una beta sin firma. Van en las notas del release y en el README, dichas tal cual:

- **Smart App Control** de Windows 11, si está activo, bloquea por completo un ejecutable sin firma, sin opción de ejecutarlo. Desactivarlo no tiene vuelta atrás sin reinstalar Windows, así que esa decisión es del usuario. No la tomamos ni la recomendamos por él.
- **SmartScreen** muestra «Windows protegió su PC». Se sigue con «Más información → Ejecutar de todas formas», y en cada versión nueva vuelve a aparecer.
- **Defender** puede marcar como falso positivo un binario Go sin firma. Se reporta a Microsoft como falso positivo y se avisa en el release.

Todo lo demás debe funcionar igual que en Linux. Eso incluye la bóveda, Patrol, el cambio asistido, los paquetes `.mpack`, el enmascarado, la auditoría y el terminal SSH. Esa es la vara del CI.

### (j) CI

- **Job nuevo `windows`** en `ci.yml`, con `windows-latest`. Compila `./cmd/... ./internal/... ./ui/bridge/...`, corre `go test` sobre todos los paquetes, y además noegress, archcheck y gofmt. Son herramientas Go y corren igual.
- **Sin -race.** En Windows, -race exige cgo y gcc. La cobertura con -race sigue en los jobs de Linux, que ya la tienen completa.
- **Pruebas exclusivas de Linux.** Las que dependen de Linux (termios, `SO_PEERCRED`, `/proc`) llevan `//go:build linux`. Cada una tiene su par `_windows_test.go` con el equivalente; nada se salta en silencio.
- **Mientras dure 43a**, el job arranca con `continue-on-error` y una lista de paquetes que crece PR a PR. Al cerrar 43a pasa a ser obligatorio en la protección de `main`, junto a go, ui y proto.
- **En el job `go-checks` de Linux**, un paso barato `GOOS=windows go vet ./...` detecta antes de llegar a Windows que algo dejó de compilar.

### La app (Wails v3) en Windows

Propuesta de Front, verificada sobre el código de wails/v3 v3.1.0 (la versión del `go.mod`) y una compilación de prueba del 2026-11-16.

- **Compilación.** `GOOS=windows CGO_ENABLED=0 go build -tags wails ./ui` compila sin cgo: en Windows, Wails carga WebView2 con go-webview2, en Go puro. Se compila en cruzado desde Linux. Hoy solo fallan `internal/ipc` e `internal/sys`, que son del núcleo.
- **Runtime de WebView2: Evergreen, nunca Fixed Version.**
  - Fixed Version pesa más de 250 MB.
  - No se actualiza sola, así que los parches de Chromium dependerían de nuestros releases.
  - En Windows 10 pide un `icacls` a mano.
- **Instalación del runtime: no se redistribuye nada de Microsoft.** Ni el bootstrapper ni el Standalone Installer van dentro del instalador, y tampoco se descargan durante la instalación.
  - Motivo: la licencia del runtime («Microsoft Software License Terms – Microsoft Edge WebView2 Runtime», sección 2) exige a quien lo distribuye dos cosas: que los usuarios acepten términos que protejan a Microsoft (2(b)(ii)) e indemnizar y defender a Microsoft ante reclamos sobre la app (2(b)(iv)).
  - En su lugar, el instalador revisa la clave `pv` (HKLM y HKCU). Si falta, avisa al final con el enlace oficial de descarga. Es la vía que documenta Microsoft («Redirect your end users to the Microsoft site»).
  - La app avisa lo mismo al abrirse (`ui/webview2_windows.go`).
  - Windows 11 ya trae el runtime, y según Microsoft la gran mayoría de los Windows 10 también.
  - Decisión del dueño (2026-11-16), vía Release.
- **Sin WebView2, hoy la app se cerraría muda.** Wails llama a `os.Exit(1)` y escribe en stderr, y una app GUI no tiene consola. En `ui/main.go`, solo en Windows, antes de `application.New` se consulta `GetAvailableCoreWebView2BrowserVersionString`. Si falla, sale un MessageBox nativo en es/en con el enlace de descarga, y la app termina. Lleva prueba.
- **Puente.** Solo usa `ipc.Dial` e `ipc.ClientConn`. El `ipc_windows.go` del canal (a) da el mismo `Dial`, así que ni `bridge.go` ni sus módulos cambian. `sys.NoDump`, `sys.RenameNoReplaceIn` y `NoAtomicRename` conservan su firma en Windows (ver b y c).
- **Ventana.**
  - Los controles propios ya están en el orden de Windows.
  - Snap Layouts:
    - Arrastrar la ventana a un borde y Win+Z deberían funcionar con las zonas de arrastre de hoy: `--wails-draggable` arrastra con `HTCAPTION`, y la ventana sin marco conserva `WS_MAXIMIZEBOX` y `WS_THICKFRAME`. Se confirma en la validación.
    - El menú de Snap Layouts al pasar el mouse por maximizar necesita marcar el botón con `--wails-non-client-region: maximize`. En Wails 3.1 eso solo funciona con `WebView2CompositionHosting`, otro modo de alojar WebView2, así que se evalúa en la validación en Windows real antes de encenderlo.
    - `NonClientRegionSupport` no hace falta: solo activa el `app-region` de CSS, que la UI no usa.
  - `WebviewUserDataPath` va dentro de State, no en `%APPDATA%\macuahuitl.exe`, que es lo que pone Wails por omisión.
- **Rutas con «/» en la UI.** Se corrigen con un helper `baseName`/`dirName` que acepta los dos separadores, y con pruebas. Los casos:
  - `modules/transfer/client.ts` (origen local de «put»);
  - `components/Files.tsx` (nombre del archivo rechazado).
- **Textos por sistema.**
  - El puente expone `runtime.GOOS` y la UI elige entre la clave `…` y `….windows`. Las dos van en `es.ts` y `en.ts`, y las cubre `i18nCoverage`.
  - El catálogo de `internal/i18n` sigue el mismo patrón.
  - Claves de la UI que cambian: `systemctl --user` en `shell.coreDown` y `App.tsx`; `/dev/ttyUSB*` y `dialout` en la consola; CAP_NET_RAW y SYN; puertos menores a 1024 y nftables; 0600 y 0700, `chmod`, `/tmp` y `~/.ssh` en Almacenamiento y respaldos.
  - Claves del núcleo que cambian: `setcap`, `nft_remove`, `listen.privileged`, `serial.err.permission_hint`, `/dev/ttyUSB0` → `COM3`, `harden.*` y `harden.err.runtime_dir`.
- **Fuentes OFL.** Inter y JetBrains Mono viajan embebidas en `macuahuitl.exe` (Vite → `dist` → `go:embed`). El instalador solo lleva sus licencias en `THIRD_PARTY_LICENSES` y `NOTICE`.

### Instalador

- **NSIS por usuario, no MSIX.**
  - MSIX redirige `%APPDATA%` y `%LOCALAPPDATA%` a una carpeta del paquete. Al desinstalar, Windows la borra sin preguntar, y con ella la bóveda.
  - MSIX además exige firma (Microsoft Learn, «Understanding how packaged desktop apps run on Windows»).
  - La plantilla de Wails ya trae `WAILS_INSTALL_SCOPE "user"`, que pone `RequestExecutionLevel user`. Instala en `$LOCALAPPDATA\Programs\MACUAHUITL`, la desinstalación queda en HKCU, sin UAC, y los accesos directos van en el menú Inicio del usuario. El del escritorio es opcional, con la casilla apagada.
- **Desinstalación.**
  - Se borran solo `$INSTDIR`, los accesos directos, la clave de desinstalación y la entrada de `Run`.
  - Los datos (bóveda, auditoría, configuración) se borran solo si el usuario dice que sí en una pregunta aparte, con **«No» por omisión**. Con `/S` **nunca** se borran.
  - Antes de borrar, se cierran la app y el núcleo. Si siguen abiertos, la desinstalación falla con un mensaje.
  - Se quita de la plantilla de Wails el `RMDir /r "$AppData\<exe>"`.
- **Firma, lista pero apagada.** El armado del instalador tiene un paso de firma opcional que se salta si no hay secret. Firmar más adelante no obliga a rehacer nada.
- **Contenido del instalador:**
  - `macuahuitl.exe`, `macuahuitld.exe` y `mctl.exe`;
  - `LICENSE`, `NOTICE`, `THIRD_PARTY_LICENSES` y `TRADEMARK.md`;
  - el `.ico`, generado de los PNG del ícono.
  - Nada de Microsoft (ver «Instalación del runtime») ni de nmap, Npcap, Wireshark o iperf3 (ver f).
- **CI de la app.** Un job `ui-windows` en `windows-latest` corre:
  - `npm ci`, `npm test` y `npm run build`;
  - `go test ./ui/bridge/...`;
  - `CGO_ENABLED=0 go vet -tags wails ./ui/`;
  - `makensis`, para comprobar que el instalador se arma.

  Corre en paralelo con el resto, así que se estima que agrega de 0 a 2 minutos al reloj del CI. Pasa a obligatorio cuando esté estable.

### Firma: decidido, la beta sale sin firmar

**Decisión del dueño (2026-11-16): «sin firmar, vamos como open source».** La beta de Windows sale **sin firma de código**. La verificación se apoya en lo abierto:
- `SHA256SUMS` y la atestación SLSA (`gh attestation verify`), que ya publica `release.yml`;
- el código Apache-2.0;
- binarios reproducibles.

Las limitaciones que esto trae están en (i).

Referencia futura, sin decisión pendiente. Costos aproximados, a confirmar si algún día se retoma:

| Opción | Costo | Notas |
|---|---|---|
| SignPath Foundation | 0 | **Posible más adelante, sin costo, si el dueño lo solicita.** El editor que aparece es «SignPath Foundation», no el autor. Pide licencia OSI, MFA y crédito en la política de firma. |
| Certum Open Source Code Signing | desde ~69 EUR, con lector | **Posible más adelante, si el dueño lo solicita.** Se emite a la persona, con el prefijo «Open Source Developer». |
| Azure Artifact Signing (antes Trusted Signing) | ~9.99 USD/mes | Hoy solo personas físicas de EE. UU. y Canadá, u organizaciones de EE. UU., Canadá, UE o Reino Unido. Una persona física en México no califica. |
| Certificado OV (Sectigo, SSL.com, Certum) | ~170–400 USD/año | Llave en HSM, token o nube. Desde el 2026-02-27 un certificado dura como máximo ~460 días. |
| Certificado EV | ~300–600 USD/año | Desde agosto de 2024 da la misma reputación de SmartScreen que OV; no vale el sobreprecio. |
| Microsoft Store | — | Evita SmartScreen, pero exige MSIX, que borra la bóveda al desinstalar. Descartada. |

Ninguna firma evita el aviso de SmartScreen en las primeras descargas. Con firma, la reputación se acumula por certificado y pasa a las versiones siguientes. Sin firma, empieza de cero en cada versión.

## Consecuencias

- Hay dos implementaciones de cada pieza sensible: canal, permisos, memoria y apertura de archivos. Cada una con sus pruebas en su sistema, y el CI de Windows las corre.
- El modelo de amenazas (`docs/security/THREAT_MODEL.md`) gana una sección de Windows. Lo que **no** se protege allí (lectura de memoria por procesos del mismo usuario) queda escrito, no implícito.
- Se agrega una dependencia nueva (go-winio, MIT).
- macOS reutiliza las partes POSIX de Linux: `flock`, `umask`, `LOCAL_PEERCRED` en vez de `SO_PEERCRED`, termios. Tendrá su propio ADR o una enmienda a este.
