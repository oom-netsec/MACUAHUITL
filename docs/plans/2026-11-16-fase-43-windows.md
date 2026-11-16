# Fase 43: Windows

Fecha: 2026-11-16 · Decisiones: ADR 0012 · Estado: propuesto

## Objetivo

Que el núcleo, mctl y la app corran en Windows 10/11 amd64 con las mismas garantías que en Linux. Donde Windows no ofrece una garantía, el ADR 0012 lo dice. Se trabaja en el mismo repo, con build tags. La fase 42 sigue en paralelo y no comparte archivos con esta, salvo `ci.yml`.

Reparto:
- Backend lleva el núcleo y mctl (43a).
- Front lleva la app Wails, WebView2, el instalador y su CI (43b).
- Release lleva los artefactos de release y la firma (43c), según lo que decida el dueño.

## Reglas de la fase

- PRs chicos: cada uno deja `main` compilando en Linux y suma paquetes a la lista del job `windows`.
- La API de cada paquete no cambia. Lo que es por sistema va en `_linux.go`/`_windows.go`, y los llamadores no llevan build tags.
- `x/sys/windows` solo en `internal/{sys,ipc,diag,diag/serialcon,core/power}`, con archcheck. La única dependencia nueva es go-winio (MIT), y antes se lee su LICENSE.
- TDD. Cada equivalente de Windows trae su prueba en `_windows_test.go`, que corre en el job `windows`. Las pruebas exclusivas de Linux llevan `//go:build linux` y su par en Windows.
- Nada de Linux cambia de comportamiento. El job `go` de Linux sigue igual y es la red de seguridad.

## 43a: el núcleo compila y pasa sus pruebas en Windows

| PR | Contenido | Prueba que lo cierra |
|---|---|---|
| 43a1 | **CI y reglas.** <br>• Job `windows` en `ci.yml` (`windows-latest`, `continue-on-error`): compila `./cmd/... ./internal/...`, corre noegress, archcheck y gofmt, y `go test` sobre la lista de paquetes portables. <br>• `GOOS=windows go vet ./...` en `go-checks`. <br>• Regla de archcheck para `x/sys/windows`. | El job corre y lista lo que falta. |
| 43a2 | **`internal/sys` y rutas.** <br>• `harden_windows.go`: working set, `VirtualLock` del material de llaves, WER fuera, avisos de pagefile e hibernación. <br>• `openregular_windows.go`: `FILE_FLAG_OPEN_REPARSE_POINT`, `NumberOfLinks`, dueño por SID; `RenameNoReplaceIn` con `MoveFileEx`. <br>• `core/paths.go`: `%LOCALAPPDATA%\MACUAHUITL`. <br>• El núcleo se niega a correr elevado. | Un junction y un symlink se rechazan; un archivo con dos nombres se rechaza; renombrar sobre un existente falla con `fs.ErrExist`; un token elevado se rechaza (doble). |
| 43a3 | **Permisos por ACL.** <br>• Helpers para crear archivos y carpetas con DACL protegida (usuario, SYSTEM, Administradores). <br>• La regla de `service/outputs.go` en Windows, con sus mensajes `icacls`. | Una carpeta con ACE para Usuarios se rechaza; una con DACL propia se acepta; un ancestro con escritura de Everyone se rechaza. |
| 43a4 | **`internal/ipc`.** <br>• Named pipe `\\.\pipe\macuahuitl-<SID>`: DACL del usuario, `PIPE_REJECT_REMOTE_CLIENTS`, `FILE_FLAG_FIRST_PIPE_INSTANCE`, verificación del cliente por SID del token. <br>• Lado cliente con verificación del servidor; lo usan mctl y el puente. | Un segundo núcleo no arranca; un cliente de otro SID se corta antes de gRPC (doble del verificador); go-winio sí pone las dos banderas o se crea con `x/sys/windows`. |
| 43a5 | **`internal/diag`.** <br>• `Build` por sistema: `ping -n -w`, `tracert -d -h -w`. <br>• Rutas absolutas conocidas en lugar del `PATH`. <br>• Job Object para cortar el árbol; `dumpcap -a duration:N` siempre. | Las banderas por herramienta (tabla); un hijo que lanza un nieto muere al cancelar; sin nmap, `diag.err.install` con el enlace de Windows. |
| 43a6 | **`internal/diag/serialcon`.** <br>• `\\.\COMn` con DCB 9600 8N1 y timeouts. <br>• Listado desde `HARDWARE\DEVICEMAP\SERIALCOMM`. | Listado contra un registro simulado; la apertura queda «sin validar» hasta tener hardware. |
| 43a7 | **`internal/core/power`.** <br>• `PowerSetRequest(SystemRequired)` mientras corre un trabajo. <br>• Ventana message-only para suspensión (`PBT_APMSUSPEND`) y bloqueo (`WTS_SESSION_LOCK`) que llama `onSleep`/`onLock`. | El despacho de mensajes llama a las funciones correctas (mensajes simulados); lo que no se pueda tomar sale en `missing`. |
| 43a8 | **Cierre de 43a.** <br>• Sección de Windows en `docs/security/THREAT_MODEL.md`. <br>• El job `windows` sin `continue-on-error` y con todos los paquetes; pasa a obligatorio en la protección de `main`. | El job en verde con la suite completa. |

**Orden.** 43a1 va primero. 43a2 va antes de 43a3 y 43a4, que usan sus helpers de SID y ACL. 43a5, 43a6 y 43a7 son independientes y pueden ir en paralelo (≤3 agentes).

## 43b: app e instalador (Front)

**Pendiente de la sección de Front.** Se integra en el ADR 0012 y aquí.

## 43c: release y firma (Release)

- **`release.yml`**: artefactos de Windows (zip del núcleo y mctl, e instalador), con sumas SHA-256 y atestación SLSA como hoy, y reproducibilidad comprobada igual que en Linux.
- **Firma**: según lo que decida el dueño entre las opciones del ADR 0012. Sin decisión, la beta sale sin firmar y con aviso.

## Validación

El CI de Windows prueba el código, pero no el uso real. Antes de llamarla beta hace falta una corrida en un Windows 10/11 real o en una VM. La corrida cubre:

- instalar;
- crear la bóveda;
- un trabajo de Patrol contra el 3560CX (solo show);
- el terminal SSH;
- una transferencia TFTP con la regla de firewall;
- bloquear la pantalla con la bóveda abierta, que debe cerrarla;
- suspender en medio de un trabajo.

Quién la hace y dónde se decide con Release. Si es una VM local, al terminar se borran la ISO y la VM.

## Fuera de esta fase

macOS, ARM64 y el empaquetado de nmap, Npcap, Wireshark o iperf3 (nunca, por licencia).
