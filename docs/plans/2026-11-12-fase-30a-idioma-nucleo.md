# Fase 30a — Idioma del núcleo: infraestructura y códigos de error estables

Pedido del dueño (vía la sesión de front): cero mezcla de idiomas. El inventario está en `docs/plans/2026-11-07-idioma-nucleo.md`. Esta fase es el paso 1 de 3.

## Regla de compatibilidad (obligatoria)
Sin el metadato `accept-language`, o con `es`, cada respuesta del núcleo es IDÉNTICA byte por byte a la de hoy: mensajes de error, notes, texto. La interfaz aún parsea texto en español y no debe romperse. Hay una prueba de regresión que compara los mensajes actuales con los del catálogo `es`.

## 1. Infraestructura
- Paquete `internal/i18n` (o el nombre que encaje con archcheck; es compartido como `internal/service`):
  - Un catálogo es/en de códigos estables. Cada código lleva el texto y los argumentos con nombre, en plantillas con `{arg}`.
  - `T(ctx, code, args)` devuelve el texto en el idioma del contexto.
  - `Locale(ctx)` devuelve `es` o `en`.
- Prueba de cobertura: todo código tiene `es` y `en`, con los mismos argumentos, y ningún argumento sobra ni falta en la plantilla.
- Interceptor gRPC (unario y de stream), registrado en `internal/core`. Lee el metadato `accept-language` y deja el locale en el contexto:
  - acepta `es`, `en`, `es-MX`, `en-US`, … y listas con q;
  - desconocido o ausente = `es`.
- Errores: un helper `service.Err(ctx, codes.X, code, args)` arma `status.New(c, T(ctx, code, args))` con `WithDetails(&errdetails.ErrorInfo{Reason: code, Domain: "macuahuitl", Metadata: args}, &errdetails.LocalizedMessage{Locale, Message})`.
  - `google.golang.org/genproto/googleapis/rpc/errdetails` es Apache-2.0 y ya es dependencia indirecta. Pasa a directa; lee su LICENSE.
- Puente (`ui/bridge`):
  - Todo error que devuelve a TS conserva el texto de hoy y además expone `reason` y `metadata`. Lee los detalles de status y busca la forma en que el puente ya devuelve errores.
  - El puente manda `accept-language` desde una preferencia `ui.language`, pero SOLO si una bandera `core.localize` está activa (apagada por defecto). La sesión de front la enciende cuando termine de migrar. Documéntalo.
- mctl: `--lang` global (si no, LC_ALL / LC_MESSAGES / LANG; si no, es). Manda el metadato. Sus propios textos no se traducen en esta fase.

## 2. Primeros códigos (los de los acoplamientos del front)
a) Validación de ingest (syslog, traps y flows: `internal/diag/ingest` y la validación compartida del servicio). Reason `ingest.invalid` con metadata `{field, min, max}`:
   - `field` ∈ rate_per_source, burst_per_source, rate_global, burst_global, queue_size, rotate_mb, rotate_minutes, name_template, max_files, format, addr y protocol.
   - Además, `{template_problem}` para la plantilla.
b) `file.exists` en todos los export con overwrite=false (scripts, colecciones, hosts y respaldo de bóveda) y en `WriteFile` del puente (`ui/bridge`), con metadata `{path}`.
c) Snippets:
   - `assist.invalid_value` (InvalidArgument), con `{template, field}` y la razón como subcódigo `{why: required|range|pattern|choice|type|unknown_field}`. Los secretos nunca en metadata.
   - `assist.refused` (FailedPrecondition), con `{template, device}`.
   - Mantener el texto de hoy, con el prefijo `assist: <id>: `.
d) Sinónimos de los tokens de plantilla: `{date}`, `{time}` y `{source}` valen igual que `{fecha}`, `{hora}` y `{origen}` (en validación, en el nombre y en la regex de retención). La retención reconoce los archivos creados con cualquiera de las dos formas de la MISMA plantilla.

## 3. Detalles de las fases del Job y nombres de playbooks
Así salió en la prueba de punta a punta del 2026-11-12: con la UI en inglés, el Job mostraba «1 equipo», «1 correcto, 0 con fallas», «2 rondas» y los nombres de playbooks en español («Análisis · Evidencia para el analizador», «Cambio»).
- **Fases.** `JobPhase` (`patrol.proto`) gana `string reason = 5;` y `map<string, string> args = 6;`, sin renumerar.
  - Cada `addPhase` del núcleo (`internal/core`, búscalos con grep) manda un código estable del catálogo, por ejemplo `phase.ok_failed {ok, failed}`, `phase.devices {n}` o `phase.rounds {n}`, con sus argumentos.
  - `detail` sigue siendo el texto de hoy en `es` y sale traducido con `en`.
  - El puente expone `reason` y `args`.
- **Playbooks.** Los YAML de `playbooks/` ganan `name_en` (obligatorio). Una prueba de cobertura falla si a un playbook le falta, igual que con el catálogo.
  - `ListPlaybooks` devuelve `name` en el idioma del contexto: `es` = el de hoy, `en` = `name_en`.
  - El grupo es el prefijo antes de « · ». En inglés también, con la misma separación, para que la UI siga agrupando igual.
  - Traduce los 46 nombres con términos de Cisco TAC, sin inventar.
- Si hay más textos del núcleo de la misma clase en las respuestas de Patrol (estado de equipo, notas de omitido), aplica lo mismo y anótalo en el PR.

## 4. Auditoría siempre en inglés (decisión del dueño del 2026-11-12; es una rama aparte, 30a-2)
Esto reemplaza lo decidido antes (español). No va en esta rama, pero se diseña aquí para que la infraestructura lo permita:
- cada `d.Audit(acción, objetivo, detalle)` escribe su detalle en inglés fijo, sin pasar por el locale (`accept-language` no lo cambia);
- la acción ya es un código fijo (`job.logintest`, …) y se queda igual;
- los registros viejos NO se reescriben, porque la cadena de hashes no se toca: lo viejo queda en español y lo nuevo en inglés;
- prueba: el detalle no depende de `accept-language`, y `audit verify` sigue íntegro con registros mixtos;
- en esta rama, la regla de compatibilidad «es byte por byte» NO aplica a la auditoría: no migres sus textos aquí ni los hagas traducibles.

## 5. Contrato
Sección nueva al final de `docs/plans/contratos-front.md`:
- la forma exacta del error en TS (`{message, code, reason, metadata}`);
- la lista de reasons y metadata de esta fase;
- la bandera `core.localize`;
- la regla de compatibilidad.

## Pruebas mínimas
- Cobertura del catálogo.
- El interceptor: los valores de `accept-language`, y que un desconocido dé es.
- Regresión byte por byte en es, sin metadato, para cada error migrado.
- `en` devuelve el texto inglés.
- Cada reason llega a TS por el puente con su metadata.
- Un secreto nunca aparece en la metadata.
- Los sinónimos de plantilla, incluida la retención.
- mctl `--lang en` y LANG.
