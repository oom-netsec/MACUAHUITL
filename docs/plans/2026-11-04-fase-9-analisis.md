# Fase 9 — Análisis de evidencia: Plan de implementación

**Goal:** Convertir lo que recolecta Patrol en diagnóstico: hallazgos por reglas declarativas, diferencias entre rondas y una línea de tiempo correlacionada, expuestos por gRPC, `mctl` y la pestaña Análisis de la UI.

**Licencias:** sin dependencias nuevas. Biblioteca estándar de Go (BSD-3) y `gopkg.in/yaml.v3` (MIT/Apache-2.0, ya usada por los playbooks).

**SIN VALIDAR EN LABORATORIO.** No hay transcripciones reales: los parsers, las reglas y los fixtures (`internal/analyze/testdata/lab_20261104-100000`) siguen la documentación pública de Cisco IOS-XE. Cada archivo de reglas lo dice en su cabecera. Antes de confiar en un umbral hay que correr el playbook `ios-xe/analisis` contra equipos reales y ajustar.

**Architecture:**
- `internal/analyze` (sin red): lee la carpeta de un trabajo de Patrol, aplica reglas, compara rondas y arma la línea de tiempo.
  - `bundle.go`: corta los archivos por las cabeceras de `patrol.Writer` (`===== [ronda N · ]HORA · comando[ · comando inválido] =====`). Entiende archivos por ronda (`r001_*.txt`), consolidados y, si se borraron los sueltos, los zips de Patrol. Límites: 8 MiB por salida (aviso si se recorta) y 256 MiB por archivo.
  - `rules/*.yaml` (incrustadas con `embed`): `id`, `title`, `severity` (critica, alta, media, baja, info), `commands`, `check` + `params`, `explanation`, `action`. `KnownFields` y validación al cargar: un check o parámetro desconocido, una regex inválida o un id repetido es error.
  - `rules.go`: checks en Go que las reglas parametrizan: `match` (regex con `exclude`, `min`, `group`), `cpu_high`, `cpu_trend`, `mem_low`, `mem_leak`, `iface_counter` (absoluto o `growing`), `uptime`, `uptime_reset`, `stp_changes`, `bgp_neighbors` (down/flap), `ospf_neighbors` (stuck/lost), `hsrp` (changed/bad).
  - `parse.go`: un parser por comando. Formato inesperado → `ok=false`; la regla avisa ("formato inesperado: sin datos para esta regla") y no produce hallazgo. Salida vacía, `% BGP not active` o `No spanning tree instance` son legítimas y no avisan.
  - `diff.go`: por equipo entre la ronda A y la B: contadores de interfaz, vecinos BGP/OSPF y grupos HSRP (aparece/desaparece/cambia), prefijos BGP por vecino, uptime (recarga) y diff textual por comando (LCS, sin contexto; tope de 4 M celdas y 400 líneas).
  - `timeline.go`: eventos de rondas, hallazgos, `show logging` fechado, archivos del receptor syslog, auditoría y un reporte de `pcapan`. Filtro por equipo (los eventos globales siempre quedan) y ventana ±N alrededor de un instante.
- `internal/pcapan`: `TCP.Events` con la hora de cada RST y retransmisión (hasta 1000).
- `api/proto/macuahuitl/v1/analysis.proto`: `AnalysisService` con `AnalyzeJob`, `DiffRounds`, `Timeline`; los reportes viajan como `ToolReport` (JSON + texto), igual que la Fase 7.
- `internal/core/services_analysis.go`: `job` es el ID de un trabajo de la sesión o la ruta absoluta de su carpeta. Auditoría: `analysis.run`, `analysis.diff`, `analysis.timeline`.
- `mctl analyze|diff|timeline`, `ui/bridge/analysis.go`, pestaña Análisis (`ui/frontend/src/modules/analysis`).
- Playbook `ios-xe/analisis` con todos los comandos que usan las reglas.

## Decisiones

- **Reglas = datos + checks.** El YAML declara qué mirar y qué decir; la lógica que entiende cada salida es Go probado. Un `match` cubre todo lo que es "buscar líneas" (log, causa de recarga, crashinfo) sin código nuevo.
- **Evidencia siempre de la ronda del hallazgo.** Las líneas son exactas de la salida de esa ronda; el detalle lleva la serie (`15 → 1515`, `45% → 72% → 91%`). Para "vecino OSPF perdido" la evidencia es la tabla actual (lo que falta es el hallazgo).
- **El búfer de log se arrastra entre rondas.** Un mensaje ya reportado no se repite; en la línea de tiempo, una línea idéntica del mismo equipo entra una sola vez.
- **`--round N`** usa las rondas anteriores para tendencias y crecimiento, y solo reporta la N.
- **Contadores que bajan** (clear o recarga) no cuentan como crecimiento; la recarga sale por `reload-entre-rondas`.
- **Horas del log del equipo**: sin año se toma el de la ronda (o el anterior si quedaría >1 día en el futuro). Se toman como UTC; si traen otra zona o el `*` de reloj sin sincronizar, el evento lo anota. Las marcas de uptime (`1d02h:`) no tienen hora absoluta: se omiten con aviso.
- **Ventana sin instante**: syslog y auditoría entran si caen hasta 15 min alrededor de las rondas del trabajo.
- **Trabajos de sesiones anteriores**: el núcleo no persiste el `Writer`; por eso `job` también acepta la carpeta.
- Comandos de una palabra en `mctl` (`analyze`, `diff`, `timeline`), como pide la fase; el resto de la CLI sigue con dos.

## Review Focus

1. **Formato inesperado** (basura, binario, recortes de las salidas reales a cualquier longitud) → sin hallazgo, con aviso, sin pánico. `TestUnexpectedFormatWarnsWithoutFinding`, `TestTruncatedOutputsNeverPanic`.
2. **Evidencia exacta**: cada línea de cada hallazgo existe tal cual en la salida de su ronda. `TestEvidenceIsExactLines`.
3. **Zip con y sin sueltos** no duplica secciones. `TestLooseAndZipAreNotDuplicated`.
4. **Integración real**: lo que escribe Patrol contra el simulador se analiza por ID. `TestAnalysisOfRealJobByID`.
5. **Sin red**: `internal/analyze` y `internal/core` no importan `net` (noegress).

## Pendiente

- Validar formatos y umbrales con transcripciones reales (sobre todo `show memory statistics`, `show platform resources` y `show spanning-tree detail` en MST).
- Abreviaturas de comandos (`sh proc cpu`) no se reconocen; los playbooks usan el comando completo.
- Plataformas distintas de IOS/IOS-XE (NX-OS, WLC, FTD) no tienen reglas todavía.
- `show platform resources` y `show ip route summary` no tienen parser.

### Límites vigentes (revisión)

- Tope de 512 MiB de texto descomprimido por trabajo (incluidos zips): al pasarlo se lee parcialmente con aviso; `--round N` carga solo hasta la ronda N.
- La línea de tiempo lee `outputs/syslog` acotado a la ventana (descarta al leer y omite archivos que empezaron después) y a 64 MiB en total, con aviso.
- La hora local del log se pasa a UTC con el desfase entre `show clock detail` y la hora de la ronda, redondeado a 15 min; sin `show clock detail`, aviso por equipo y se toma como UTC.

### Pendientes menores de la revisión

- `job` como ruta arbitraria sigue enlaces simbólicos: usar `Lstat` + `IsRegular` al leer el paquete.
- `show logging | include …` se acepta como log completo sin avisar que la salida está filtrada.
- `mctl timeline --window` menor a 1 s cae en silencio a 30 s.
- La deduplicación de mensajes entre rondas compara el texto exacto, sin normalizar timestamps.
- El diff no avisa cuando no logra interpretar contadores o vecinos de una ronda.
