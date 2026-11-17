# Fase 45b — Transferencias en vivo: Plan de implementación

**Goal:** ver en vivo los servidores de transferencia (TFTP, FTP, SCP, SFTP y HTTP): si se está transfiriendo algo, qué IPs usan cada servidor y el avance de cada transferencia. Núcleo → proto → mctl → puente; la vista es de Front.

**Pedido del dueño (textual):** ver en vivo los servidores de transferencia (TFTP, FTP, SCP, SFTP y HTTP): 1) si en este momento se está transfiriendo algo; 2) qué IPs están usando cada servidor; 3) el progreso de cada transferencia.

**Licencias:** nada nuevo; librería estándar de Go.

**Architecture:**
- `internal/diag/fileserve`: un contador por transferencia (`Live`, solo atómicos) que cada protocolo suma en su bucle de datos, y un gancho `Config.OnStart(*Live)`. La `Transfer` final lleva su `Live` (`json:"-"`) para enlazar inicio y fin. Sin `OnStart` (servidor de Campo) no cambia nada.
- `internal/service/transfer/sessions.go`: el registro de sesiones por servidor (activas y últimas terminadas), la tasa y la RPC `ListTransferSessions`.
- Proto: `TransferService.ListTransferSessions` y `TransferSession` (este PR; `gen/` regenerado).
- `cmd/mctl/transfer`: `transfer status [ID] [--json]` y el avance en `transfer serve`.
- `ui/bridge/transfer.go`: `TransferSessions(serverID)`; la UI la hace Front con encuesta de 1 s.

**Spec:** ADR 0004 (escuchas), fase 22a (servidores de transferencias), `docs/plans/contratos-front.md` §3 (convenciones del puente).

## Contrato (fijado en este PR)

```proto
rpc ListTransferSessions(ListTransferSessionsRequest) returns (ListTransferSessionsResponse);

message ListTransferSessionsRequest  { string server_id = 1; }            // vacío = todos (abiertos y cerrados hace < 10 min)
message ListTransferSessionsResponse { repeated TransferSession sessions = 1; }
message TransferSession {
  string id = 1; string server_id = 2; string client = 3; string name = 4;
  string direction = 5;      // "in" (el equipo sube) | "out" (el equipo descarga)
  string protocol = 6;       // tftp, ftp, scp, sftp, http
  int64 bytes = 7; int64 total = 8;   // total 0 = desconocido
  double bytes_per_sec = 9;
  int64 started = 10; int64 ended = 11;   // unix ms; ended 0 = activa
  string state = 12;         // active | done | failed
  string error = 13; string error_code = 14;
}
```

Es el contrato provisional de Front sin cambios de nombre ni de forma. Solo se fija lo que no decía: `server_id` vacío lista todo, un `server_id` desconocido (o cerrado hace más de 10 min) da `NOT_FOUND`, el orden de la lista, y que `error_code` es la clave del catálogo.

Puente (`ui/bridge/transfer.go`) y TS (`modules/transfer/api.ts`):

```ts
interface TransferSession {
  id: string; serverId: string; client: string; name: string;
  direction: "in" | "out"; protocol: "tftp" | "ftp" | "scp" | "sftp" | "http";
  bytes: number; total: number;          // total 0 = desconocido: barra indeterminada
  bytesPerSec: number;
  started: number; ended: number;        // unix ms; ended 0 = activa
  state: "active" | "done" | "failed";
  error: string; errorCode: string;
}
// core.transferSessions(serverId: string): Promise<TransferSession[]>  — Bridge.TransferSessions(serverID string) ([]TransferSessionDTO, error)
```

## Decisiones

1. **Encuesta, no stream** (lo acordado con Front). Una RPC unaria barata: toma dos candados cortos y lee atómicos. Ya existe un stream (`StartServer`) que da el resultado final de cada transferencia; agregarle eventos de avance obligaría a regular el ritmo por cliente y a duplicar la lógica en mctl. Con la encuesta, la UI, mctl y cualquier otro cliente leen lo mismo.
2. **Sesión = transferencia que empezó.** El punto de inicio de cada protocolo está en la tabla de abajo. Los rechazos previos (archivo no publicado, origen no permitido, método, saturación) **no** son sesiones: un escáner o un RRQ falsificado no deben sacar del registro las transferencias reales. Siguen como hoy en el stream de `StartServer` (`transfer_json` con `Rejected`) y en `ServerInfo.rejected`. Una falla después del inicio (sin respuesta, tope, disco) sí es sesión `failed`. Lo que falla antes de empezar sin ser rechazo (p. ej. FTP sin conexión de datos) se audita como hoy y sale en el stream, pero no se lista.
3. **TFTP empieza al verificar al par.** RRQ: con el primer ACK (del OACK o del bloque 1). WRQ: con el primer DATA. Antes de eso el origen UDP es falsificable: hoy esos intentos ya cuestan un cupo y unos segundos, y no deben además ensuciar la lista.
4. **Bytes confirmados, no enviados.** TFTP suma tras el ACK de cada bloque. Las subidas cuentan hasta donde se escribió en disco (`recvFile.WriteAt`, el mismo punto que aplica los topes). Las descargas TCP cuentan lo entregado al socket. Así la barra nunca pasa del 100 % ni retrocede.
5. **La tasa la calcula quien lee, no la transferencia.** Cada sesión guarda una muestra `(bytes, hora)`. En `List`, si pasó ≥ 1 s desde la muestra, `bytes_per_sec = Δbytes/Δt` y se renueva la muestra; si no, se repite el último valor. La primera lectura usa el promedio desde el inicio. Una sesión terminada da el promedio `bytes/(ended-started)`. Varios lectores a la vez (UI + mctl) no se estorban: la muestra nunca se renueva antes de 1 s. La hora sale de `Deps.Now()`, que es reemplazable en pruebas.
6. **Nombre:** `name` es el `Transfer.File` de hoy, el mismo que va a la auditoría y al stream. Ya pasó la validación de hoy: lectura por `plainName` y archivo publicado, escritura por `SafeName`. Como los rechazos no son sesiones, nunca llega a la lista un nombre crudo del equipo. Antes de responder pasa por `transfer.SanitizeName` (`internal/diag/transfer`), el mismo saneado de `Browse`: control, formato Unicode y UTF-8 inválido se cambian por «?», por si un archivo publicado desde `--from` trae U+202E. No se expone la ruta (`Path`), para no mostrar la carpeta del usuario; la ruta ya va a la auditoría.
7. **`error` en el idioma de la petición** con `fileserve.ReasonIn(loc, t)`, como el stream. **`error_code`** es `t.ReasonT.Key`, la clave del catálogo (`fileserve.reason.no_reply`, `fileserve.reason.stopped`…), o vacío cuando el motivo no tiene clave (error del sistema, «HTTP 416»). La sesión guarda `Error` y `ReasonT` y traduce al leer: dos clientes con idiomas distintos ven cada uno el suyo.
8. **`direction`**: `"in"` = escritura en el servidor (el equipo sube), `"out"` = lectura (el equipo descarga). Es el mismo criterio que la insignia actual de `ServerPanel` (`dirCode === "write"` → `transfer.dir.in`).
9. **`started`/`ended` en ms** con los nombres del contrato de Front (en proto otros campos usan `_ms`). Cambiarlos solo por estilo no es razón fuerte.
10. **Fuera de alcance:** el servidor de Campo (`FieldService.ServeFiles`) no tiene `server_id` ni aparece en `ListServers`; no pasa `OnStart` y no cambia. Los clientes `GetStream`/`PutStream` ya tienen su avance. `ServerInfo` no cambia; «hay algo activo» sale de `ListTransferSessions("")`.

## Avance por protocolo

| Protocolo | Inicio de la sesión | Dónde se cuenta | Total |
|---|---|---|---|
| TFTP RRQ (`sendFile`) | primer ACK (del OACK o del bloque 1) | `live.add(n)` junto a `t.Bytes += n`, tras el ACK | `st.Size()` del archivo publicado (el mismo que se responde en `tsize`) |
| TFTP WRQ (`recvFileTFTP`) | primer DATA (al crear `rf`) | `recvFile.WriteAt` (máximo escrito) | `tsize` anunciado; 0 si no vino |
| FTP RETR | conexión de datos aceptada | escritor que cuenta sobre `dc` (hoy `ctxConn` ya no usa sendfile: sin costo nuevo) | `fi.Size()` (lo mismo que responde `SIZE`) |
| FTP STOR | conexión de datos aceptada | `recvFile.WriteAt` | 0: STOR no anuncia tamaño (no hay ALLO) |
| SCP fuente (`scpSource`) | archivo abierto | escritor que cuenta sobre `ch` en `io.CopyN` | `fi.Size()` (la orden `C`) |
| SCP destino (`scpSink`) | `rcv.create` aceptado | `recvFile.WriteAt` | `size` de la orden `C` |
| SFTP lectura (`sftpReader`) | `Fileread` abierto | `ReadAt`: el máximo leído, el que ya calcula `r.max` | `fi.Size()` |
| SFTP escritura (`sftpWriter`) | `Filewrite` abierto | `recvFile.WriteAt` (máximo escrito; SFTP escribe fuera de orden) | 0: SFTP no anuncia tamaño |
| HTTP GET/HEAD | archivo abierto, antes de `ServeContent` | `countingWriter.Write` | `Content-Length` que fija `ServeContent` al llamar a `WriteHeader` (con `Range`, el tamaño del tramo; sin él, el del archivo) |

`Live` (en `fileserve`):

```go
type Live struct {
	Proto, Client, File, Dir string // fijos antes de OnStart
	bytes, total atomic.Int64
}
func (l *Live) add(n int64)     // nil-safe
func (l *Live) atLeast(n int64) // CAS al máximo, nil-safe (subidas y SFTP)
func (l *Live) setTotal(n int64)
func (l *Live) Bytes() int64
func (l *Live) Total() int64
```

`Config.OnStart func(*Live)` (opcional) y `func (c Config) start(t Transfer, total int64) *Live`, que lo arma y llama a `OnStart`. `recvFile` gana `live *Live`, que pone `rcv.create` o el protocolo. `Transfer` gana `Live *Live json:"-"`. El protocolo que llama a `start` **siempre** termina con `OnTransfer` de esa `Transfer` (ver Riesgos).

## Registro de sesiones (servicio)

- En `server`: `mu sync.Mutex`, `active map[*fileserve.Live]*session` y `recent []*session`, un anillo de **100** terminadas por servidor (la más vieja sale). En `svc`: `closed`, los servidores cerrados con su `recent`, conservados **10 min** tras el cierre y como mucho **8** (sale el más viejo). Se purga al leer y al cerrar un servidor; no hay goroutine de limpieza.
- `session`: `id` (`service.NewID()`), `live`, `started`, `ended`, `state`, `bytes`, `total` (copiados del `Live` al terminar), `err string`, `reason i18n.Text`, `name` ya saneado, y la muestra de la tasa.
- **Tope de memoria:** una sesión ocupa < 1 KiB (nombre ≤ 255 B). Las activas ya están acotadas por los cupos de cada protocolo (`maxTransfers` = 16 en TFTP y HTTP, conexiones SSH/FTP limitadas). Peor caso: (4 abiertos + 8 cerrados) × 100 × 1 KiB ≈ 1,2 MiB.
- **Cierre de seguridad:** cuando `fileserve.Serve` vuelve, toda sesión que siga en `active` pasa a `failed` con `fileserve.reason.stopped`, y se audita como cualquier otra. Ningún camino olvidado deja una sesión «activa» para siempre.

## Concurrencia

- El camino caliente (bucle de datos) solo hace `atomic.Int64.Add`/CAS: ni candados ni canales ni asignaciones.
- `OnStart` y `OnTransfer` ocurren una vez por transferencia: toman `server.mu` un instante (insertar o mover la sesión). La auditoría y el envío al stream quedan fuera del candado (la auditoría sigue donde está hoy).
- `ListTransferSessions` toma `svc.mu` para copiar los punteros de servidor y luego cada `server.mu` por separado (nunca los dos a la vez: sin inversión de orden). Lee los atómicos y arma la respuesta fuera de los candados con una copia de los campos.
- La tasa (muestra por sesión) se actualiza bajo `server.mu` dentro de `List`.
- Pruebas con `-race`: lecturas concurrentes de `List` mientras corren transferencias.

## Auditoría

Ya existe y alcanza: `transfer.serve.transfer` por cada transferencia no rechazada, con `server`, `proto`, `direction`, `file` (`%q`), `path`, `bytes`, `sha256`, `duration`, `result` y `error` en inglés; el objetivo es `t.Client` (IP:puerto). Cambios:
- se agrega `session=<id>` (y `total=<n>`) para cruzar la auditoría con la lista;
- las sesiones cerradas por el cierre de seguridad también se auditan, con `result=error error="stopped"`;
- los rechazos siguen sin auditarse uno por uno: van contados en `transfer.serve.close` (`rejected=`). Así un escáner no llena la bitácora.

## mctl

- `mctl transfer status [ID] [--json]`: una lectura de `ListTransferSessions` con una línea por sesión: `ESTADO  SERVIDOR  PROTO  CLIENTE  in|out  NOMBRE  bytes/total (pct)  tasa  [motivo]`. Con total 0 no hay porcentaje. `--json` es `protojson` de la respuesta. No trae `--watch`: `watch -n1 mctl transfer status` ya lo hace.
- `mctl transfer serve`: además del stream, cada **5 s** consulta `ListTransferSessions(server_id)` e imprime una línea `progreso` por sesión activa. Las líneas de fin siguen siendo las del stream. Las sesiones ya vienen saneadas del núcleo; lo que imprime del stream pasa por un `strings.Map` local con la misma regla que `SanitizeName` (control y formato Unicode → «?»). Es local porque `cmd/mctl` no debe importar `internal/diag/...`, que trae `net`.
- **De paso, una falla de hoy:** `serve` imprime con `%s` el `File` de los rechazos TFTP, que es el nombre crudo del paquete UDP; un nombre con secuencias ANSI le escribe a la terminal. Se sanea en este mismo bloque (prueba con `\x1b[2J` en el nombre).
- Textos nuevos en `internal/i18n/catalog_mctl_a.go` (es y en). `cmd/mctl` no importa `net` ni `grpc` directamente (noegress).

## Bloques (PRs chicos)

### 45b-1 — Plan y proto (este PR)
`docs/plans/2026-11-16-fase-45b-transferencias-en-vivo.md`, `api/proto/macuahuitl/v1/transfer.proto`, `gen/`. Cierra con `buf lint`, `buf breaking --against .git#branch=main`, `buf generate` y `go build ./...` (el servicio responde `Unimplemented` hasta 45b-3).

### 45b-2 — Contador en `fileserve`
Archivos: `internal/diag/fileserve/{fileserve.go,live.go,tftp.go,ftp.go,sshsrv.go,http.go,recv.go}`, `live_test.go`.
Pruebas:
- `Live`: `add`, `atLeast` concurrente (CAS) y métodos nil-safe.
- Cada protocolo: `OnStart` se llama una vez, antes de `OnTransfer`, con el mismo puntero en `t.Live`, `Bytes() == t.Bytes` al final y `Total` según la tabla (TFTP con y sin `tsize`, SCP con orden `C`, FTP STOR y SFTP escritura en 0, HTTP con y sin `Range`).
- Avance a medias, determinista: TFTP RRQ con un cliente de prueba que no manda el ACK del bloque 2 (`Bytes() == blksize`); HTTP con un archivo disperso de 64 MiB (`Truncate`) y un cliente que lee 1 MiB y se detiene (`0 < Bytes < Total`).
- TFTP: un RRQ cuyo par nunca responde no llama a `OnStart`.
- Rechazos: sin `OnStart`.
- Mutación a mano: quitar el `add` de un protocolo hace fallar su prueba.

### 45b-3 — Registro y RPC en el servicio
Archivos: `internal/service/transfer/{sessions.go,transfer.go}`, `sessions_test.go`, `internal/i18n/catalog_transfer.go` (`transfer.svc.no_server`).
Pruebas:
- Unitarias del registro, sin red y con reloj falso: anillo de 100, 10 min tras el cierre, tope de 8 cerrados, orden de la lista y tasa (primera lectura = promedio; luego Δ por ventana ≥ 1 s; terminada = promedio).
- Integración con TFTP en loopback: activa con `client`, `name`, `total`; luego `done`. Falla → `failed` con `error_code`. Un rechazo no aparece y sube `rejected`. Un `server_id` desconocido da `NOT_FOUND`. `""` lista todos.
- Nombre publicado con U+202E → «?».
- Cierre de seguridad: `Live` sin `OnTransfer` → `failed` y auditada.
- Auditoría con `session=`.
- `-race` con `List` en paralelo.
- Mutación a mano en la tasa y en el anillo.

### 45b-4 — mctl
Archivos: `cmd/mctl/transfer/{transfer.go,status.go}`, `status_test.go`, `internal/i18n/catalog_mctl_a.go`.
Pruebas:
- Formato puro de la línea (con y sin total, `failed` con motivo) y `--json`.
- Saneado del nombre (ANSI y U+202E), también en el `serve` de hoy.
- La ayuda lista `transfer status`.
- `noegress` limpio.

### 45b-5 — Puente
Archivos: `ui/bridge/transfer.go` (`TransferSessionDTO`, `TransferSessions`) y su prueba de mapeo. Después Front agrega `api.ts`, `fake.ts`, la vista y las claves `transfer.session.*` en `es.ts` y `en.ts`; no es parte de este plan.

## Review Focus

1. **Ninguna sesión queda activa para siempre:** cada camino que llama a `start` termina en `OnTransfer`; si no, actúa el cierre de seguridad. Prueba en 45b-2 por protocolo y en 45b-3.
2. **El bucle de datos no toma candados ni espera a la UI.** Revisión de 45b-2 más `-race` en 45b-3.
3. **Un escáner o un RRQ falsificado no desplaza la historia real:** los rechazos y los pares TFTP sin verificar no crean sesión. Pruebas en 45b-2 y 45b-3.
4. **Ningún nombre crudo llega a la UI ni a la terminal.** Pruebas en 45b-3 y 45b-4.
5. **`--allow`, `--write`, los topes y la validación de nombres no cambian:** las pruebas existentes de `fileserve` y `transfer` pasan sin tocarse.

## Riesgos

- **Fuga de sesiones activas** si un camino nuevo de un protocolo olvida `OnTransfer`. Mitigan el cierre de seguridad y una prueba por protocolo; la revisión debe recorrer los `return` posteriores a `start`.
- **HTTP con `Range`:** IOS puede pedir por tramos. Cada petición es una sesión con su total del tramo, y la lista puede mostrar varias sesiones por archivo. Si Front quiere agruparlas, puede hacerlo por `client` + `name`.
- **HEAD de HTTP** crea una sesión `done` de 0 bytes. Es inofensiva y real: el equipo sí preguntó.
- **Tasa con encuestas espaciadas:** si nadie lee en un rato, la primera lectura promedia toda esa ventana. Es aceptable para una barra.
- **Reloj:** `started`/`ended` usan `Deps.Now()`. El servicio estampa la hora al recibir `OnStart` y `OnTransfer`, no en `fileserve`, así que una pausa del planificador puede correrla algunos ms.
- **Memoria:** acotada (§ Registro). Si se suben los topes de servidores, revisar el cálculo.
- **Pruebas de tiempo bajo carga** (la suite completa va de a una): las de avance a medias usan pasos deterministas (ACK retenido, lector detenido), no plazos cortos.
