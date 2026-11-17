# Fase 46: historial de trabajos de Patrol

Fecha: 2026-11-17 · Estado: propuesto · Contrato de proto: fijado en esta rama (`fase-46-plan`)

## Objetivo

El historial de trabajos crece sin fin y hace ruido. Los terminados de días anteriores pasan a una sección aparte («Past jobs»), a los 7 días se quitan del historial, y el ingeniero puede quitar a mano. La evidencia en disco no se toca nunca.

Reparto: Backend lleva el núcleo, el proto y mctl (46a–46d). Front lleva la UI (46e).

## Decisiones del dueño (no se discuten)

- (a) Los trabajos ACTIVOS (armed, arming, running) siempre se ven y nunca se quitan.
- (b) Los terminados (completed, cancelled, failed) del día actual siguen en la lista principal.
- (c) Cada día, al cambiar de día en hora local, los terminados de días anteriores pasan a «Past jobs», una sección aparte que se puede revisar.
- (d) A los 7 días de terminados se QUITAN del historial por completo.
- (e) A mano: «Quitar del historial» por trabajo y «Limpiar terminados» en bloque. Nunca un trabajo activo.
- (f) LA EVIDENCIA EN DISCO NO SE TOCA NUNCA. Carpetas, zips y manifest se quedan en outputs/. Solo se quita la fila del historial en la DB.
- (g) La auditoría no se toca. Cada quitado se audita: `job.removed` el manual y `job.pruned` el automático, con id, nombre, carpeta y motivo.

Pedidos de Release: `past` en ListJobs, RPC `RemoveJobs(ids | all_finished)`, poda al arrancar y una vez al día con `d.Now()`, `mctl job rm ID...` y `mctl job clear --finished`, que sobreviva a reinicios, y que quitar no rompa las referencias por job id.

## Lo que hay hoy (sobre 230b5244)

- **Tablas.** `jobs(id, name, spec_json, state, created_at, history_json)` (`migrations/0001_init.sql:32`, `0003_job_history.sql`), `job_runs(job_id→jobs, round)` y `run_devices(job_id, round→job_runs)` (`0001_init.sql:40-57`). La conexión abre con `foreign_keys(1)` (`store/store.go:34`): borrar un job exige borrar antes `run_devices` y `job_runs`. Última migración: 0011, la siguiente libre es **0012**.
- **No hay `finished_at`.** El fin solo existe como `At` de la fase COMPLETED/CANCELLED/FAILED dentro de `history_json` (`core.go:79-100`, `jobHistory.Phases`, tope 200; la fase final siempre es la última, así que sobrevive al tope). `created_at` se escribe una vez (`persistJob`, `core.go:604`; el upsert no lo actualiza).
- **Núcleo.** `Core.jobs map[string]*job` en memoria, cargado por `loadJobs` (`core.go:615`); un job armed/arming de un núcleo caído pasa a `failed` con `addPhase` (`core.go:645`). `persistJob` (`core.go:590`) hace upsert con `persistMu` por job. Estados: created, arming, armed, completed, cancelled, failed; `closed` marca que ya no hay finish pendiente.
- **ListJobs** (`services.go:660`) devuelve todos los jobs sin filtro; `summary` (`core.go:~700`) arma `JobSummary`. UI: `ListJobs` en `ui/bridge/bridge.go:421`, `JobDTO` en `bridge.go:385`. mctl: `cmd/mctl/patrol/patrol.go:153` lista; no hay `job rm`.
- **Auditoría.** `c.audit(action, target, detail)` (`core.go:399`) no falla la operación; en el servicio, `d.Audit`. Formato de detalle: `clave=valor` con `%q` para texto libre (p. ej. `backup.start`, `adhoc.start`). Con una sola conexión SQLite nunca se audita con `rows` ni tx abiertas (`loadJobs` anota fallos y audita tras `rows.Close`).
- **Reloj.** `Options.Now`, por omisión `time.Now` (`core.go:46,170`). El núcleo no fija zona: usa `time.Local`, que sale de `TZ`/`/etc/localtime` del proceso (en Windows, la del sistema). Un servicio con `TZ=UTC` contaría el día en UTC.
- **Evidencia fuera de outputs/.** `service.JobOutputRoots` (`service/helpers.go:114`) lee `spec_json` de la tabla `jobs` para saber de carpetas de corrida fuera de `Outputs()`; lo usan `fleet.go:27` e `inventory.go:48`. Quitar la fila haría desaparecer de esas vistas la evidencia que sí sigue en disco (ver 46b).

## Decisiones técnicas

### Fin del trabajo y `past`

1. **Migración `0012_job_finished_at.sql`:** `ALTER TABLE jobs ADD COLUMN finished_at TEXT NOT NULL DEFAULT ''` (RFC3339 UTC, como `created_at`). Relleno solo de los terminales (`completed`, `cancelled`, `failed`): el `at` de la última fase terminal de `history_json` (`json_each`/`json_extract`) y, si no hay, `created_at`. Los activos quedan en `''`.
   - Un job armed/arming de un núcleo caído se pasa a failed al cargar: su `finished_at` es el instante de ese arranque (la fase nueva), no el de la caída.
2. **Escritura.** `addPhase` es el único lugar donde entran las fases COMPLETED/CANCELLED/FAILED: ahí, si `j.FinishedAt` está vacío, se fija con `c.o.Now()`. Se guarda en `jobHistory.FinishedAt` (verdad en memoria) y `persistJob` lo escribe también en la columna. Idempotente: no se reescribe. `loadJobs` lee la columna (y `SELECT` pasa a incluirla).
3. **`past`.** Función pura `isPast(finished, now time.Time) bool`: fecha civil local de `finished` anterior a la fecha civil local de `now` (`y,m,d := t.In(time.Local).Date()`, se compara la terna, nunca `now.Sub`). `now` sale de `c.o.Now()`. Un job sin `finished_at` (activo) nunca es past. Se calcula al leer, no se guarda: el cambio de día no necesita temporizador.
4. **Cambio de horario.** Al comparar fechas civiles, un día de 23 o 25 horas no altera nada. Si el reloj retrocede y `finished_at` queda en el futuro, no es past.
5. **ListJobs.** Sin `include_past`: activos + terminados de hoy (como hoy, pero sin los de días anteriores). Con `include_past`: todos los que aún no se podaron. `JobSummary.finished_at` y `JobSummary.past` siempre vienen. Orden: sin cambio (hoy es el del mapa; se ordena por `armed_at/created` descendente solo si Front lo pide, fuera de alcance).

### Poda automática

- Constante `jobRetention = 7 * 24 * time.Hour` en `core`. **Fija por decisión del dueño; si el dueño lo pide, va a Ajustes.**
- Un job se poda si es terminal, `closed`, `!closing`, y `now.Sub(finished_at) >= jobRetention`. Los activos jamás son candidatos.
- Cuándo corre: una vez en `New` tras `loadJobs`, y luego un chequeo cada hora desde `idleLoop` o una goroutine hermana con `c.stop`; corre si la fecha civil local de `now` difiere de la de la última poda hecha (`lastPrune`, en memoria). No se usa un `Ticker` de 24 h: no sobrevive a la suspensión ni al cambio de hora.
- Sobrevive a reinicios por construcción: la poda se deriva de `finished_at` guardado, no de un contador. Si el núcleo estuvo apagado N días, la primera pasada al arrancar quita de una vez todo lo vencido (con un `job.pruned` por trabajo). Idempotente: una segunda pasada no encuentra nada.
- Primer arranque tras actualizar: los terminados viejos cuyo `finished_at` salió del relleno ya tienen más de 7 días y se podan todos en esa pasada. Es lo que pide (d); se pregunta al dueño si quiere un aviso (ver preguntas).

### Quitar (compartido por la poda y `RemoveJobs`)

`removeJobs(ids []string, reason string) []*job` en `core`, con este orden (respeta la regla de una sola conexión y el orden de locks `persistMu` → `c.mu`):

1. Para cada job candidato: tomar `j.persistMu`, luego `c.mu`; revalidar que sigue terminal y `closed` y que está en `c.jobs`; marcar `j.removed = true` y sacarlo de `c.jobs`; soltar `c.mu`.
2. `DELETE FROM run_devices WHERE job_id=?`, `DELETE FROM job_runs …`, `DELETE FROM jobs …` en una tx corta, que se cierra (commit/rollback) **antes** de auditar. Sin `rows` abiertas.
3. Soltar `persistMu`. `persistJob` revisa `j.removed` bajo `persistMu` y no hace nada: un guardado tardío no resucita la fila.
4. Auditar con `c.audit` ya sin locks ni tx.
5. Si el DELETE falla, se vuelve a meter el job en `c.jobs` (`removed=false`) y se devuelve `Internal`; no se audita como quitado (se audita `job.remove_failed` con el error, igual que `job.persist_failed`).

Convivencia con trabajos que terminan durante la poda: un job que acaba de terminar tiene `finished_at = ahora` y nunca cumple 7 días; el manual lo ve terminal solo tras `closed`; mientras `closing` el job cuenta como activo y se rechaza. Un job terminal no vuelve a armarse (comprobar en 46a que ArmJob/CancelJob no reabren un terminal; si lo hicieran, `RemoveJobs` lo revalida en el paso 1).

No se toca disco: no hay `os.Remove` ni en el núcleo ni en el servicio. Una prueba lo comprueba (carpeta, zip y manifest intactos con sus hashes).

### `RemoveJobs`

- Request: `job_ids` (repetido) o `all_finished`; no ambas ni ninguna → `InvalidArgument` `patrol.err.remove_args`.
- Con `job_ids`: duplicados se ignoran; ids inexistentes se ignoran (idempotente, no cuentan). Si **alguno** está activo (created, arming, armed, o terminal pero `closing`): falla entera con `FailedPrecondition`, reason `patrol.job_active`, metadata `job_ids` = ids activos separados por comas, ordenados; no se quita ninguno. `created` cuenta como activo (aún no tiene resultado: decisión a confirmar, ver preguntas).
- Con `all_finished`: quita todos los terminales (de hoy y pasados); nunca toca activos ni falla por ellos.
- Respuesta: `removed` (int32) y `removed_ids` (orden estable).
- Auditoría manual: `job.removed`, target = id, detalle `name=%q dir=%q state=%s finished=%s reason=manual` (con `all_finished`: `reason=clear_finished`). Una entrada por trabajo.
- Poda: `job.pruned`, mismo detalle con `reason=age_7d`.
- `dir` es el `OutputDir` del historial o, si falta, el del spec (la misma lógica que `summary`).
- Catálogo i18n: `patrol.job_active` y `patrol.err.remove_args` en es y en; acción `job.removed`/`job.pruned` en el glosario de `auditen.go` si aplica.
- Permisos: ya existe la política de RPC por servicio; `RemoveJobs` es escritura (misma clase que `CancelJob`).

### Referencias por job id

Revisado en el código. «Carpeta» = acepta ruta absoluta hoy.

| Quién | Cómo usa el id | Acepta carpeta | Si el id ya no está | Cambio |
|---|---|---|---|---|
| `analysis` (AnalyzeJob, DiffRounds, Timeline) `analysis.go:40` | `job` = id o ruta absoluta | Sí | Con id: NotFound `patrol.err.job_missing`. Con carpeta: funciona | Ninguno en el servicio. UI y mctl deben pasar la carpeta de la fila en lugar del id cuando se abra evidencia de un job pasado (la UI la tiene en `outputDir`) |
| `drift` `drift.go:33` | `job` = id o ruta | Sí | Igual que analysis | Ninguno |
| `forensic` `source.go:41` | `job` = id o ruta | Sí | Igual | Ninguno |
| `change` `change.go:172` | `rec.jobs` por fase (en memoria), exige `completed` y `Dir`; `GetChangeReport` acepta `pre_dir`/`post_dir` | Sí, por `pre_dir`/`post_dir` | `outputDir` falla; la lista muestra estado vacío (`jobState` ignora el error) | Ninguno de proto. Mensaje: al fallar un id quitado, el error ya incluye el id; Front ofrece pedir el reporte por carpetas. Un cambio asistido en curso tiene jobs activos y no se pueden quitar; los jobs `completed` de un cambio sí. Prueba: reporte por carpetas tras quitar |
| `backup` `CollectBackups` `backup.go:286` y `:501` | `job_id`; estado en memoria `s.jobs/s.final` | **No** hoy | NotFound | **Proto nuevo `CollectBackupsRequest.dir`** (en esta rama): con `dir`, el estado se toma como terminado y los guardados salen de la carpeta; mctl/UI lo usan si el id falló. Los respaldos ya guardados (`ListBackups`, `GetBackup`) usan su propio almacén y no dependen del job |
| `metrics` (GetJobMetrics, GetPortStatus) `metrics.go:32` | `job_id` o `dir` | Sí, `dir` | NotFound con id | Ninguno |
| `visibility` BuildTopology `visibility.go:37` | `job_id` o `dir` | Sí, `dir` | NotFound con id | Ninguno |
| `adhoc` AdhocResult `adhoc.go:79` | `job_id`; comandos en memoria `s.cmds` | No | NotFound | Sin cambio: el resultado se pide al terminar y el job no se quita en el momento. Aceptado; si el dueño quiere verlo luego, es una fase aparte |
| `fleet` `fleet.go:27,29` | Solo carpetas; las raíces extra salen de `JobOutputRoots` | Sí | — | **Cambio:** `JobOutputRoots` lee `jobs`; al quitar la fila se perdería la raíz de una corrida con carpeta personalizada. Migración 0013 `job_roots(dir PRIMARY KEY, removed_at)`: `removeJobs` inserta el `output_dir` absoluto (si cae fuera de `Outputs()`) en la misma tx; `JobOutputRoots` hace `UNION`. Alimenta también `inventory.go:48` |
| `patrol` GetRun / ArmJob / CancelJob / LoginTest / Subscribe | id | No | NotFound `patrol.err.job_missing` (ya existe) | Ninguno: son operaciones de un job vivo o recién terminado |
| `events` Subscribe(job_ids) | filtro | — | Ids inexistentes no emiten | Ninguno |
| `vault` `armed_job_ids` `vault.proto:41` | lista de activos | — | — | Ninguno: solo activos |
| UI `ui/bridge` (`adhoc.go`, `backup.go`, `change.go`, `ListJobs`) | pasa ids a los servicios | Depende del servicio | Ver arriba | Front: tras un NotFound por id quitado, reintentar con carpeta donde exista; refrescar la lista al volver |
| mctl `patrol`, `backup`, `metrics`, `visibility` | id o `--dir` | Las que ya tienen `--dir` | Error de NotFound | `mctl backup collect` gana `--dir`; el resto sin cambio |

### mctl

- `mctl job rm ID...`: `RemoveJobs{job_ids}`; imprime `removed N` y los ids. Con activos imprime el error y los ids activos, sale con código distinto de cero.
- `mctl job clear --finished`: `RemoveJobs{all_finished}`. `--finished` es obligatorio (sin él, error de uso) para que `clear` solo no borre por accidente.
- `mctl job list` (hoy `cmd/mctl/patrol/patrol.go:153`): muestra `finished_at` y marca los pasados; `--all` pide `include_past`.
- Estas son nuevas cadenas del catálogo mctl (es y en). `noegress`: mctl no importa `net` ni `grpc` directo; se usa `cli`/`ipc` como los demás.

### Contrato para Front

- `JobSummary.finished_at` (Timestamp, como el resto de fechas de `JobSummary`): vacío mientras el job está activo.
- `JobSummary.past` (bool): lo calcula el núcleo con su hora local; la UI no hace la cuenta.
- `ListJobsRequest.include_past` (bool): sin él, activos + terminados de hoy (la lista principal). Con él, también los de días anteriores no podados («Past jobs»). Una llamada con `include_past` trae todo; Front separa por `past`.
- `RemoveJobs`: `job_ids` o `all_finished`, nunca ambos. Respuesta `removed` (int32) y `removed_ids`.
  - Con algún activo falla entera: `FailedPrecondition`, reason `patrol.job_active`, metadata `job_ids` (activos separados por comas). No se quita ninguno.
  - Ids inexistentes se ignoran y no cuentan en `removed` (idempotente).
  - `all_finished` nunca toca activos.
- El puente: `JobDTO` gana `finishedAt` (RFC3339) y `past` (bool); `ListJobs(includePast bool)`; `RemoveJobs(ids []string)` y `ClearFinishedJobs()`; el error `patrol.job_active` llega con `metadata.job_ids`.
- Cuando el núcleo poda en segundo plano, la fila desaparece al siguiente `ListJobs`: la UI refresca al abrir la vista y al cambiar de día local; no hay evento de poda (no se añade a `events.proto`; si Front lo necesita, 46e lo pide).
- Para abrir evidencia de un trabajo pasado, usar la carpeta de la fila (`outputDir`), no el id.
- La retención es fija en 7 días; si el dueño lo pide, va a Ajustes.

## Bloques (PRs chicos, TDD)

### 46a. Fin del trabajo, `past` y ListJobs
- Migración 0012 con relleno; `FinishedAt` en `jobHistory`; `addPhase` lo fija; `loadJobs` lo lee; `isPast`; `summary` y `ListJobs(include_past)`.
- Pruebas primero: relleno de la migración (terminal con fase, terminal sin fase → `created_at`, activo vacío); `finished_at` se fija una vez; `isPast` en el límite de la medianoche local, en un cambio de horario (zona `America/Mexico_City` con transición simulada, y `Europe/Madrid`), y con reloj hacia atrás; `ListJobs` sin y con `include_past`; un job armed de un núcleo caído que pasa a failed.
- Review Focus: que el relleno no toque activos; que `past` use fechas civiles; que `persistJob` no pise `finished_at`.
- Riesgos: el relleno por JSON en SQLite sobre historiales grandes (tope 200 fases, aceptable); zona del proceso distinta de la del usuario.

### 46b. Quitar, `RemoveJobs` y auditoría
- `removeJobs`, `j.removed` en `persistJob`, RPC, catálogo i18n, migración 0013 `job_roots` y `JobOutputRoots` con `UNION`.
- Pruebas primero: ids (uno, varios, duplicados, inexistentes) ; activo en la lista → falla entera con metadata y no quita ninguno; `all_finished` deja los activos; `InvalidArgument` con ambos o ninguno; auditoría con formato exacto, una por job, tras la tx (con una sola conexión, sin bloqueo); evidencia en disco intacta (hashes de carpeta, zip y manifest); un `persistJob` tardío no resucita la fila; carrera quitar vs. terminar; `fleet`/`inventory` siguen viendo la raíz personalizada tras quitar; DELETE que falla vuelve el job a memoria.
- Review Focus: orden de locks (`persistMu` → `c.mu`) y que no hay tx ni rows abiertas al auditar; que nada llama a `os.Remove`.
- Riesgos: carrera con `closing`; que `job_roots` crezca (una fila por carpeta distinta; aceptable).

### 46c. Poda automática
- `pruneJobs(now)`, llamada al arrancar y cada hora con chequeo de cambio de día; constante `jobRetention`.
- Pruebas primero con `Options.Now` inyectado: no poda a 6 d 23 h, poda a 7 d; no toca activos ni `closing`; núcleo apagado 30 días poda todo de una vez con un `job.pruned` por job; segunda pasada sin efecto; reinicio entre pasadas; el cambio de día dispara una sola pasada por día; `job.pruned` con `reason=age_7d`; el cierre del núcleo (`c.stop`) detiene la goroutine sin fugas.
- Review Focus: la goroutine no sostiene `c.mu` durante el DELETE; idempotencia.
- Riesgos: la primera pasada tras actualizar quita muchos jobs viejos (y emite muchas auditorías).

### 46d. mctl y referencias
- `job rm`, `job clear --finished`, `job list --all`; `CollectBackupsRequest.dir` en el servicio de backup; `mctl backup collect --dir`.
- Pruebas primero: salida y códigos de salida de mctl con activos; `CollectBackups` por `dir` tras quitar el job; `AnalyzeJob`/`Drift`/`Timeline`/`GetChangeReport` por carpeta tras quitar; con id quitado, el error es NotFound con el id.
- Review Focus: que `dir` en backup se valide absoluto y dentro de las raíces conocidas (`Outputs()` + `JobOutputRoots`), como el resto de rutas.
- Riesgos: aceptar una ruta arbitraria en `CollectBackups`.

### 46e. UI (Front)
- Sección «Past jobs», «Quitar del historial», «Limpiar terminados», con confirmación y el texto «la evidencia en disco no se borra». Puente según el contrato. Tras NotFound por id quitado, abrir por carpeta.
- Fuera de este plan: el detalle visual.

## Preguntas abiertas para el dueño

1. Primera actualización: los terminados con más de 7 días se podan todos al arrancar. ¿Se acepta sin aviso, o prefieres que la primera vez solo marque `past` y la poda empiece a los 7 días de instalar?
2. Un trabajo `created` (nunca armado) ¿cuenta como activo (no se quita ni se poda)? Propuesta: sí, mientras no termine; «Limpiar terminados» no lo toca. Un creado abandonado se cancela primero.
3. «Día actual en hora local» usa la zona del proceso del núcleo. En un servicio con `TZ=UTC` sería UTC. ¿Basta con la del sistema?
4. AdhocResult de un job quitado no se puede pedir luego (el resultado vive en memoria). ¿Aceptado?
