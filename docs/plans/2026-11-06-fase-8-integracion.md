# Integración del frontend de la fase 8 con la rama de módulos

Fecha: 2026-11-06 · Rama `fase-8-integracion` (de `fase-8-frontend`, con `fase-16b-snippets` mezclada).

## Conflictos y cómo se resolvieron

| Archivo | Resolución |
|---|---|
| `cmd/mctl/main.go` | Se tomó la versión por áreas. `diag interfaces` pasó a `cmd/mctl/diag` (y su línea de ayuda); la fase `PhaseAdded` de `job watch`, a `cmd/mctl/patrol`. `testdata/help.golden` suma la línea de `interfaces`. |
| `internal/core/core.go`, `services.go` | Se tomó la versión de 16b (con `finishErr`, `closers`, `service.NewID`) y se reaplicó encima el ciclo de vida de la fase 8: `jobHistory`, fases, resumen, `loadJobs`, `addPhase`. Es del motor de Patrol, así que se queda en `core`. `finish` registra FAILED/PACKAGED y guarda `finishErr`. |
| `internal/service/diag/diag.go` | Se agregó `ListInterfaces`. La lectura con `net` pasó a `internal/diag/ifaces` (archcheck prohíbe `net` en la raíz de un dominio). |
| `internal/store` | Ver migraciones. |
| `ui/.../App.tsx`, `main.tsx` | Base: barra lateral de la fase 8. `App` recorre el manifiesto; `main.tsx` ya no lista vistas. |
| `DiagView`, `ToolsView` (+ pruebas) | Base de la fase 8 (páginas, `Console`, `Notice`). La salida pasa por `Terminal` (paletas de la 15b): `Console` de `Field.tsx` y la lista de Syslog (`Hl` por línea). Las pruebas de Syslog usan `termText`. |
| `core.ts`, `fake.ts` | Unión de ambos lados, luego partidos por área (ver más abajo). |
| `styles.css` | Unión. Se quitó el `.actions` duplicado de 16b (queda el de la fase 8); `--bad` pasó a `--danger` y se definió `--alert-bg` (= `--danger-soft`) para los estilos de 16b. |

## Migraciones

`0001_init`, `0002_preferences` (15b), `0003_job_history` (fase 8, antes `0002_job_history`). Las migraciones se registran por nombre de archivo, así que no chocaban; se renumeró para tener un orden único. `store.legacy` mapea `0003_job_history` a su nombre viejo: una base que ya aplicó `0002_job_history` registra la nueva sin repetir el `ALTER TABLE` (que fallaría con columna duplicada). `TestMigrateFromEitherBranch` siembra tres bases (solo preferencias, historial con el nombre viejo, nueva) y comprueba tablas y conteos; sin el mapa, la segunda falla con `duplicate column name`.

## Barra lateral

- Suelto: Patrol, Visibilidad, Seguridad, Syslog; abajo, Bóveda y Auditoría.
- Diagnóstico: Ping, Traceroute, nmap, iperf3, Captura.
- Análisis: PCAP, ACL, DNS, TLS, Corridas (el antiguo "Análisis" de salidas de Patrol), Deriva, Limpiador, Flota.
- Operación: Cambios, Lotes, Puertos, Snippets, Rotar credenciales, Respaldos, Terminal.
- Utilidades: Campo, Calculadoras.

El selector de paleta (`TermPrefsControl`) va en la barra de título, a la izquierda de los controles de la ventana; las paletas siguen guardadas en el núcleo.

## Manifiesto

`ui/frontend/src/modules/index.ts`: `groups` y `modules` (`id`, `label` = clave `nav.*`, `group`, `icon`, `bottom`, `view(core)`). Es `.ts`, así que las vistas se crean con `createElement`. La barra y `App` lo recorren; `app/modules.tsx` desapareció. Prueba en `App.test.tsx`: ids únicos y cada módulo se alcanza desde la barra.

Cada área trae `api.ts` (tipos, `XAPI`, `xWails(call)`) y `fake.ts` (`fakeX()`, con su estado y sus `emitX`). `lib/core.ts` y `lib/fake.ts` solo componen; `core.ts` reexporta los tipos (`export type *`) para no tocar los imports existentes. Quedan en `core.ts` solo `BaseAPI` (estado del núcleo, preferencias, diálogo de archivos, portapapeles).

Agregar un módulo hoy: sus archivos + una línea en `modules/index.ts` + las claves `nav.*` en `es.ts`/`en.ts`; si tiene API, además una línea en `core.ts` (import, `extends`, spread) y una en `fake.ts`.

## Correcciones de la segunda revisión

- Trabajo recargado: `coreDeps.Job` toma la carpeta del historial (`OutputDir`, solo si es absoluta) cuando no hay escritor, y `finishErr` pasó al historial (`FinishErr`) para sobrevivir al reinicio. `AdhocResult` termina con error si el trabajo recargado quedó `failed` o no tiene carpeta; nunca lee una carpeta vacía. Un lote recargado pierde sus columnas pedidas (viven en memoria del servicio) y las deduce de las salidas. Pruebas: `TestJobRecargado*`, `TestAdhocResultSinCarpeta*`, `TestAdhocLoteArmadoAlCaer*` (el harness tiene `restart`).
- `store.migrate` revisa el error de la consulta del nombre viejo (`migrationApplied`).
- `persistJob` se serializa por trabajo (`job.persistMu` cubre foto y escritura), así que la última foto es la última en llegar a la base. `TestPersistJobConcurrenteNoRetrocede` (con `-race`). Al recargar, un trabajo armado o armándose ya volvía como `failed`; se agregó el caso `arming` a la prueba.

## Pendiente

- Traducción: solo la barra, los grupos y el selector de terminal pasan por i18n. Los textos internos de Flota, Puertos, Lotes, Deriva, Limpiador, Snippets, Rotar credenciales, Respaldos, Terminal, Cambios, Seguridad, Visibilidad, Campo, Calculadoras y Corridas siguen en español, y sus pruebas buscan esos textos. Cuando se traduzcan hay que pasar las pruebas a las claves.
- Revisión visual: no hay Chrome en este entorno, así que los módulos nuevos no se vieron con los dos temas; solo se cuidó que usen los tokens (`--line`, `--accent`, `--danger`...). Falta pasarles la vista a mano (en especial `.verdict`, `.cols`, `.box`, tablas anchas).
- Los módulos de 16b siguen usando clases propias (`.warn`, `.banner`, `.box`) en vez de `Notice`/`Page`; migrarlos a los componentes compartidos.
- Reducir a una sola lista: `core.ts` y `fake.ts` aún necesitan una línea por área con API. Derivarlos del manifiesto exigiría tipos que dependen de las vistas (circulares) o que `api.ts` conozca su `fake.ts`.
