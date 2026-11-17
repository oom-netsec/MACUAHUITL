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

- **Tablas.** `jobs(id, name, spec_json, state, created_at, history_json)` (`migrations/0001_init.sql:32`, `0003_job_history.sql`), `job_runs(job_id→jobs, round)` y `run_devices(job_id, round→job_runs)` (`0001_init.sql:40-57`). La conexión abre con `foreign_keys(1)` (`store/store.go:34`): borrar un job exige borrar antes `run_devices` y `job_runs`. Última migración: 0011, la siguiente libre es **0012** (la usa `job_roots`; `finished_at` no lleva migración).
- **No hay `finished_at`.** El fin solo existe como `At` de la fase COMPLETED/CANCELLED/FAILED dentro de `history_json` (`core.go:79-100`, `jobHistory.Phases`, tope 200; la fase final siempre es la última, así que sobrevive al tope). `created_at` se escribe una vez (`persistJob`, `core.go:604`; el upsert no lo actualiza).
- **Estados y cierre.** No existe un estado «running»: los activos son `armed` y `arming`; `paused` es un indicador de un `armed` dormido (`core.go:71,505`), no un estado. `isFinal` (`services.go:773`) = completed, cancelled, failed. `closing` se pone en `finish` (`services.go:587`) y **nunca vuelve a false**; lo que marca que un job terminó de verdad es `closed` (`finish`, `services.go:627`; `closeCancelled`, `:731`). Una fase FAILED no siempre es el fin del job: `phase.round_zip_failed` (`:570`) y `phase.close_failed` (`:602`) se agregan con el job aún corriendo o cerrando.
- **Núcleo.** `Core.jobs map[string]*job` en memoria, cargado por `loadJobs` (`core.go:615`); un job armed/arming de un núcleo caído pasa a `failed` con `addPhase` (`core.go:645`). `persistJob` (`core.go:590`) hace upsert con `persistMu` por job. Estados: created, arming, armed, completed, cancelled, failed; `closed` marca que ya no hay finish pendiente.
- **ListJobs** (`services.go:660`) devuelve todos los jobs sin filtro; `summary` (`core.go:~700`) arma `JobSummary`. UI: `ListJobs` en `ui/bridge/bridge.go:421`, `JobDTO` en `bridge.go:385`. mctl: `cmd/mctl/patrol/patrol.go:153` lista; no hay `job rm`.
- **Auditoría.** `c.audit(action, target, detail)` (`core.go:399`) no falla la operación; en el servicio, `d.Audit`. Formato de detalle: `clave=valor` con `%q` para texto libre (p. ej. `backup.start`, `adhoc.start`). Con una sola conexión SQLite nunca se audita con `rows` ni tx abiertas (`loadJobs` anota fallos y audita tras `rows.Close`).
- **Reloj.** `Options.Now`, por omisión `time.Now` (`core.go:46,170`). El núcleo no fija zona: usa `time.Local`, que sale de `TZ`/`/etc/localtime` del proceso (en Windows, la del sistema). Un servicio con `TZ=UTC` contaría el día en UTC.
- **Evidencia fuera de outputs/.** `service.JobOutputRoots` (`service/helpers.go:114`) lee `spec_json` de la tabla `jobs` para saber de carpetas de corrida fuera de `Outputs()`; lo usan `fleet.go:27` e `inventory.go:48`. Quitar la fila haría desaparecer de esas vistas la evidencia que sí sigue en disco (ver 46b).

## Decisiones técnicas

### Activo, quitable y «en uso»

- **Activo** (nunca se quita): `armed`, `arming` (con `paused` o sin él) y cualquier job terminal que aún no cerró (`isFinal(state) && !closed`, es decir en `finish`). Criterio único: `state in (armed, arming) || (isFinal(state) && !closed)`. Se descarta `closing` como criterio (B1: nunca vuelve a false).
- **`created` NO es activo** (decisión de Release/dueño). Nunca se armó, o `ArmJob` falló y lo devolvió a `created` (`services.go:377`): se puede quitar a mano y se poda a los 7 días contados desde `created_at`. `all_finished` no lo toca (solo terminales); `job_ids` sí.
- **Quitable** = no activo y no «en uso».
- **En uso** (decisión del coordinador): un job que otro flujo todavía necesita aunque ya no corra. Gancho `c.addPinned(func() []string)`, como `addBusy` (`shutdown.go:28`), que devuelve ids. Lo alimentan:
  - backup: los jobs que vigila (`s.jobs`, `backup.go:152`);
  - change: los PRE sin POST (`rec.jobs`);
  - adhoc: los resultados sin leer (`s.cmds`, `adhoc.go:62`; se borra al entregarse en `adhoc.go:114`).
  Los jobs entran en el conjunto cuando están activos, así que ya están fijados antes de terminar. El conjunto se calcula **antes** de tomar `c.mu` (los servicios toman sus propios mutex), y se revalida bajo `c.mu` solo lo del núcleo. Un en uso no se quita a mano, ni con `all_finished`, ni en la poda.

### Fin del trabajo y `past`

1. **Sin migración y sin columna** (M1). `FinishedAt time.Time` va en `jobHistory` (`history_json`), una sola fuente de verdad. `loadJobs` agrega `created_at` al SELECT y, si `FinishedAt` está en cero y el estado es terminal, lo rellena con el `At` de la última fase terminal o, si no hay fases, con `created_at`; los activos y los `created` no lo llevan. El relleno se persiste una vez (el siguiente `persistJob`).
   - Un job armed/arming de un núcleo caído pasa a failed al cargar: su `finished_at` es el instante de ese arranque (la fase nueva).
2. **Escritura (B2).** En `addPhase`, bajo `c.mu`: `if isFinal(j.state) && j.FinishedAt.IsZero() { j.FinishedAt = p.At }`. Se decide por el estado del job, no por el tipo de fase: una FAILED de `round_zip_failed` o `close_failed` con el job aún en curso no lo fija. Prueba: un zip de ronda que falla no fija `finished_at`. Se fija una sola vez; `persistJob` lo guarda con el resto del historial.
   - Verificar en 46a el orden real: `state` cambia a final antes de la fase final (si no, el `finished_at` se fijaría en la fase siguiente o nunca); si no, `finish`/`closeCancelled` lo fijan al poner `closed`.
3. **`past`.** `isPast(finished, now time.Time) bool`: la fecha civil de `finished.In(now.Location())` es anterior a la de `now` (se comparan `y,m,d`, nunca `now.Sub`). `now` sale de `c.o.Now()`; la zona es la del sistema donde corre el núcleo (decisión del dueño), y las pruebas inyectan la zona por `Now`. Job sin `finished_at` (activo, `created`): nunca past. Se calcula al leer: el cambio de día no necesita temporizador.
4. **Cambio de horario y reloj.** Fechas civiles: un día de 23 o 25 h no altera nada; con el reloj hacia atrás, un `finished_at` futuro no es past. La prueba usa `America/Chicago` con una fecha anterior a 2022 (la regla de cambio vigente de México ya no la tiene).
5. **ListJobs.** Cambia el valor por omisión: sin `include_past`, activos + `created` + terminados de hoy; con él, también los pasados no podados. En el mismo 46a el puente (Front) pide `includePast: true` hasta que llegue 46f, para que la UI no pierda los de ayer; es una nota para Front. `finished_at` y `past` siempre vienen.

### Poda automática

- `jobRetention = 7 * 24 * time.Hour`, constante en `core`. **Fija por decisión del dueño; si el dueño lo pide, va a Ajustes.** Son 7×24 h exactas desde `finished_at` (en los `created`, desde `created_at`).
- Candidato: quitable (ver arriba) y `now.Sub(ref) >= jobRetention`.
- **Cuándo.** Una goroutine propia con tick **inmediato** al arrancar y luego cada hora (M5). Sin `lastPrune` (la poda es idempotente; si ya no hay nada, no hace nada). No corre en `New`.
- **Cierre (M4).** La goroutine entra a `c.watchers` (`core.go:155`) y sale con `c.stop`, para que `Close` la espere antes de `db.Close`. Prueba: `Close` con la goroutine en medio de una pasada no deja la base cerrada bajo ella.
- **Lote en una tx (M5).** Los candidatos se marcan y se sacan de `c.jobs` (ver «Quitar»); el borrado de todo el lote va en **una** tx; la tx se cierra y **después** se audita, una entrada `job.pruned` por trabajo, fuera de la tx.
- **Sobrevive a reinicios** por construcción (sale de las fechas guardadas). **Núcleo apagado varios días**, o primera actualización: la primera pasada quita de una vez todo lo vencido. Decisión del dueño: se acepta, y se acepta la ráfaga de `job.pruned`. **Nota de release:** «la primera vez se quitan del historial los trabajos terminados hace más de 7 días; su evidencia sigue en outputs/».

### Quitar (compartido por la poda y `RemoveJobs`)

`removeJobs(ids, reason)` en `core`:

1. Calcular el conjunto «en uso» (sin locks del núcleo).
2. Por cada candidato, en orden: `j.persistMu`, luego `c.mu`; revalidar que está en `c.jobs`, que no es activo y no está en uso; poner `j.removed = true` y sacarlo de `c.jobs`; soltar `c.mu`.
3. `DELETE` de `run_devices`, `job_runs` y `jobs` del lote, y el `INSERT OR IGNORE` de `job_roots`, en una tx corta; se cierra antes de auditar. Sin `rows` abiertas.
4. Soltar los `persistMu`. `persistJob` revisa `j.removed` bajo `persistMu` y no escribe: un guardado tardío no resucita la fila.
5. Auditar con `c.audit`, sin locks ni tx.
6. Si el DELETE falla: los jobs vuelven a `c.jobs` con `removed=false`, error `Internal` y `job.remove_failed` con el error.

**Carrera con `ArmJob`.** `ArmJob` hace `getJob` y luego toma `c.mu` (`services.go:349-355`): entre ambos pudo llegar una quita. `ArmJob` debe revisar `j.removed` **bajo `c.mu`**, junto con `state == "created"`, y responder `NotFound patrol.err.job_missing`. Como el quitar exige `created` bajo `c.mu` y `ArmJob` cambia a `arming` bajo `c.mu`, uno de los dos gana, sin tercer caso. Lo mismo para `CancelJob`, `LoginTest` y los demás que toman el job (prueba: quitar vs. `ArmJob` simultáneos, con `-race`).

**Terminar durante la poda.** Un job que acaba de terminar tiene `finished_at = ahora`: no vence. Mientras `finish` corre no está `closed` y cuenta como activo.

No se toca disco: sin `os.Remove` en el núcleo ni en el servicio. Una prueba lo comprueba (carpeta, zip y manifest con los mismos hashes).

### `RemoveJobs`

- Request: `job_ids` o `all_finished`; ambos o ninguno → `InvalidArgument` `patrol.err.remove_args`.
- `job_ids`: duplicados e inexistentes se ignoran (idempotente, no cuentan). Si alguno **no es quitable**, falla entera y no se quita ninguno:
  - activo → `FailedPrecondition`, reason `patrol.job_active`, metadata `job_ids` = ids activos, ordenados y separados por comas;
  - en uso, sin activos → `FailedPrecondition`, reason `patrol.job_in_use`, metadata `job_ids` = ids en uso;
  - ambos → `patrol.job_active`, con `job_ids` (activos) y `in_use_ids` (en uso).
- `all_finished`: quita los terminales cerrados que no están en uso (de hoy y pasados); salta activos, en uso y `created`, sin fallar. Los ids saltados por estar en uso vuelven en `skipped_ids` de la respuesta.
- Respuesta: `removed` (int32), `removed_ids` (orden estable), `skipped_ids`.
- Auditoría manual: `job.removed`, target = id, detalle `name=%q dir=%q state=%s finished=%s reason=manual` (con `all_finished`, `reason=clear_finished`; `finished=` va vacío en un `created`). La poda: `job.pruned`, mismo detalle con `reason=age_7d`. `dir` = `OutputDir` del historial o, si falta, el del spec (como `summary`).
- Catálogo i18n es/en: `patrol.job_active`, `patrol.job_in_use`, `patrol.err.remove_args`. Glosario de acciones de auditoría (`service/auditen.go`) para `job.removed`, `job.pruned`, `job.remove_failed`.
- Sin política propia de permisos: las RPC unarias pasan por los mismos interceptores; no entra en `liveUnary` ni en `liveIgnore` (`core.go`, lista de unarios largos).

### Referencias por job id

Revisado en el código. «Carpeta» = acepta ruta absoluta hoy.

| Quién | Con el id quitado | Acepta carpeta | Cambio |
|---|---|---|---|
| `analysis` (AnalyzeJob, DiffRounds, Timeline) `analysis.go:40` | NotFound por id; con carpeta funciona | Sí, ruta absoluta en `job` | Ninguno en el servicio; UI y mctl pasan `outputDir` de la fila |
| `drift` `drift.go:33` | Igual | Sí | Ninguno |
| `forensic` `source.go:41` | Igual | Sí | Ninguno |
| `change` `change.go:172` | `outputDir` falla; la lista ve estado vacío (`jobState` ignora el error) | Sí, `pre_dir`/`post_dir` | Ninguno de proto. Un PRE sin POST está «en uso» y no se quita. Prueba: reporte por carpetas tras quitar |
| `backup` `CollectBackups` `backup.go:286,501` | NotFound | **No** hoy | `CollectBackupsRequest.dir` (en el proto) con la validación de abajo. Los jobs que vigila están «en uso». Los respaldos guardados (`ListBackups`, `GetBackup`) usan su propio almacén |
| `metrics` `metrics.go:32` | NotFound por id | Sí, `dir` | Ninguno |
| `visibility` `visibility.go:37` | NotFound por id | Sí, `dir` | Ninguno |
| `adhoc` `adhoc.go:79` | NotFound | No | Aceptado por el dueño: el resultado de un job quitado deja de estar disponible. Mientras no se haya leído (`s.cmds`) está «en uso» y no se quita |
| `fleet` `fleet.go:27,29`; `inventory` `inventory.go:48` | No dependen del id | Sí | **`JobOutputRoots` (`helpers.go:114`) lee `spec_json` de `jobs`**: quitar la fila perdería las carpetas fuera de outputs/. Migración 0012 `job_roots(dir TEXT PRIMARY KEY)`; al quitar se inserta `spec.OutputDir` (la raíz, no la carpeta de la corrida) siempre, y se filtra contra `Outputs()` al leer; `JobOutputRoots` hace `UNION`. Sin `removed_at` |
| `patrol` GetRun / ArmJob / CancelJob / LoginTest | NotFound `patrol.err.job_missing` | No | `ArmJob` revisa `removed` bajo `c.mu` (arriba) |
| `events` Subscribe `services.go:784-795` | Con un id que ya no existe, `getJobIn` da NotFound. Si se quita entre esa validación y `closedJobs`, el id ausente cuenta como cerrado y el stream termina sin eventos | — | Ninguno: solo se quitan cerrados |
| `vault` `armed_job_ids` | solo activos | — | Ninguno |
| UI `ui/bridge` | pasa ids | según el servicio | Nota para Front: tras NotFound por un id quitado, reintentar con la carpeta |
| mctl `patrol`, `backup`, `metrics`, `visibility` | NotFound | las que tienen `--dir` | `mctl backup collect` gana `--dir` |

**Validación de `CollectBackupsRequest.dir` (M3).** `AbsPath` y `EvalSymlinks`; fuera de las carpetas reservadas (como `CheckOutputs`); dentro de `Outputs()` ∪ `JobOutputRoots`; debe existir `manifest.json` de la corrida, que prueba que terminó. Con `dir`, el estado se toma como terminado. `backup.Entry.Job` y el `job=` de la auditoría llevan el id del manifest.

### mctl

- `mctl job rm ID...`: `RemoveJobs{job_ids}`; imprime los quitados. Con activos o en uso imprime el error con los ids y sale con código distinto de cero.
- `mctl job clear --finished`: `RemoveJobs{all_finished}` (`--finished` obligatorio).
- `mctl job list` (`cmd/mctl/patrol/patrol.go:153`): muestra `finished_at`; `--all` pide `include_past`.
- Cadenas nuevas del catálogo de mctl; `noegress`: sin `net` ni `grpc` directos.

### Contrato para Front

- `JobSummary.finished_at` (Timestamp): vacío mientras el job no terminó (activos y `created`).
- `JobSummary.past` (bool): lo calcula el núcleo en la zona del sistema; la UI no hace la cuenta.
- `ListJobsRequest.include_past` (bool): sin él, activos, `created` y terminados de hoy. Con él, también los pasados no podados («Past jobs»). Hasta 46f el puente pide `includePast: true`.
- `RemoveJobs`: `job_ids` o `all_finished`, nunca ambos. Respuesta `removed` (int32), `removed_ids`, `skipped_ids`.
  - Con algún activo: `FailedPrecondition`, reason `patrol.job_active`, metadata `job_ids` (activos separados por comas; si además hay en uso, `in_use_ids`). No se quita ninguno.
  - Solo en uso: `FailedPrecondition`, reason `patrol.job_in_use`, metadata `job_ids`.
  - Ids inexistentes se ignoran y no cuentan.
  - `all_finished` nunca toca activos ni en uso, ni falla por ellos.
- Firma del puente (acordada con Front): `RemoveJobs({jobIds} | {allFinished})`. No hay `ClearFinishedJobs`. `JobDTO` gana `finishedAt` (RFC3339) y `past`; `ListJobs(includePast)`.
- La fila desaparece al siguiente `ListJobs` si el núcleo la podó: refrescar al abrir la vista y al cambiar de día local. No hay evento de poda.
- Para abrir la evidencia de un job pasado, usar la carpeta de la fila (`outputDir`).
- La retención es fija en 7 días; si el dueño lo pide, va a Ajustes.

## Bloques (PRs chicos, TDD)

Orden: 46a, 46b, 46c, 46d, 46e, 46f. Cada uno con sus pruebas escritas primero.

### 46a. Fin del trabajo, `past` y ListJobs
- `FinishedAt` en `jobHistory`, relleno en `loadJobs`, `addPhase`, `isPast`, `summary`, `ListJobs(include_past)`.
- Pruebas: relleno (terminal con fase, sin fase usa `created_at`, activo y `created` vacíos); se fija una sola vez; **un zip de ronda que falla no fija `finished_at`** y `close_failed` con el job aún cerrando tampoco (B2); `isPast` en la medianoche local, en `America/Chicago` con cambio de horario anterior a 2022, y con reloj hacia atrás; `ListJobs` con y sin `include_past`; armed→failed al cargar.
- Review Focus: **B2** (se decide por estado, no por tipo de fase); **M1** (una sola fuente, sin migración); que `past` use fechas civiles y `now.Location()`; que `persistJob` no pise `finished_at`.
- Riesgos: el valor por omisión de `ListJobs` cambia (la UI actual perdería los de ayer: nota de `includePast: true` para Front); el orden estado/fase en `finish`.

### 46b. `job_roots` y `JobOutputRoots`
- Migración 0012, `recordRoot(dir)` y `UNION` en `JobOutputRoots`.
- Pruebas: sin la fila de `jobs`, `fleet` e `inventory` siguen viendo una raíz personalizada; una raíz dentro de `Outputs()` se filtra al leer; inserción idempotente; la migración no rompe una base con datos.
- Review Focus: que la migración sea mínima y no pueda impedir el arranque; que la lectura filtre al leer.
- Riesgos: crece una fila por carpeta distinta (aceptable).

### 46c. Quitar, `RemoveJobs`, «en uso» y auditoría
- `removeJobs`, `j.removed` en `persistJob` y `ArmJob`, `addPinned` con backup, change y adhoc, RPC, i18n, glosario.
- Pruebas: ids (uno, varios, duplicados, inexistentes); activo → falla entera con `patrol.job_active` y `job_ids`; en uso → `patrol.job_in_use`; ambos con `in_use_ids`; `all_finished` salta activos, en uso y `created`; `created` se quita por id; `InvalidArgument`; auditoría exacta una por job y tras la tx (una sola conexión, sin bloqueo); evidencia en disco intacta; `persistJob` tardío no resucita la fila; **`ArmJob` vs. quita con `-race`**; DELETE que falla vuelve el job a memoria; un job en `finish` (`!closed`) es activo (B1); el adhoc sin leer se fija y se libera al leerlo.
- Review Focus: **B1** (`!closed`, no `closing`); orden de locks `persistMu` → `c.mu` y el conjunto «en uso» calculado antes; **M2**; sin tx ni rows abiertas al auditar; que nada llama a `os.Remove`.
- Riesgos: carrera con `ArmJob`; un servicio que olvide registrarse en `addPinned`.

### 46d. Poda automática
- `pruneJobs`, goroutine en `c.watchers` con tick inmediato y cada hora, constante `jobRetention`.
- Pruebas con `Options.Now` inyectado: no poda a 6 d 23 h, poda a 7×24 h; `created` desde `created_at`; no toca activos, `!closed` ni en uso; apagado 30 días poda todo en una pasada, con una tx y un `job.pruned` por job después; segunda pasada sin efecto; reinicio entre pasadas; **`Close` espera a la goroutine antes de `db.Close`** (M4); la primera pasada no corre en `New` (M5).
- Review Focus: **M4** y **M5**; que no sostiene `c.mu` durante el DELETE; idempotencia.
- Riesgos: la primera pasada tras actualizar quita muchos jobs (aceptado; va en las notas del release).

### 46e. mctl y respaldo por carpeta
- `job rm`, `job clear --finished`, `job list --all`; `CollectBackupsRequest.dir`; `mctl backup collect --dir`.
- Pruebas: salida y código de salida con activos y en uso; `CollectBackups` por `dir` tras quitar; `dir` fuera de las raíces, con symlink que escapa, reservada o sin `manifest.json` → rechazo; `Entry.Job` y la auditoría llevan el id del manifest; `AnalyzeJob`, `Drift`, `Timeline` y `GetChangeReport` por carpeta tras quitar.
- Review Focus: **la validación de `dir`** (aceptar una ruta arbitraria es el riesgo del bloque).
- Riesgos: el id del manifest ausente en corridas muy viejas.

### 46f. UI (Front)
- «Past jobs», «Quitar del historial», «Limpiar terminados» con confirmación y «la evidencia en disco no se borra»; puente según el contrato; el puente deja de pedir `includePast: true` fijo; tras NotFound por un id quitado, abrir por carpeta.

## Notas de release
- «La primera vez se quitan del historial los trabajos terminados hace más de 7 días; su evidencia sigue en outputs/».

## Preguntas abiertas para el dueño

Ninguna bloqueante. Respondidas por Release (valen como del dueño): poda inicial sin aviso y sin contar desde la instalación; `created` no es activo; hora local = zona del sistema; AdhocResult de un job quitado no disponible (salvo sin leer, que cuenta «en uso»).
