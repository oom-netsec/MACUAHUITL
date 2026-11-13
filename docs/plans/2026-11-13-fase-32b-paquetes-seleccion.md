# Fase 32b — Selección por elemento, copia a «Mis scripts» y paquete personal

**Especificación:** ADR 0010, sección «Selección por elemento y paquete personal (fase 32b)». Este plan la parte en
dos ramas paralelas y fija lo que el ADR deja abierto.

**Ramas:** `fase-32b-visibilidad-copia` (tareas 1 y 2) y `fase-32c-export-import` (tareas 3 y 4). Las dos agregan RPC
a `PackService` en `api/proto/macuahuitl/v1/pack.proto`: cada una AL FINAL del servicio y con números de mensaje
nuevos; la segunda que entre a main resuelve el choque y regenera `gen/`.

## Restricciones globales
- Ocultar nunca cambia lo que se resuelve: un ID oculto sigue sirviendo en trabajos, `mctl`, choques y revalidación.
- Nada de esto escribe en equipos. Auditoría en inglés: `pack.items` (ocultar/mostrar), `scripts.copy`, `pack.export`,
  `pack.import`.
- i18n: errores con código del catálogo (`pack.err.*`, `scripts.err.*`); sin `accept-language` o con `es`, todo lo
  existente idéntico byte a byte.
- Campos de proto nuevos solo opcionales; `buf lint && buf generate`; contrato en `docs/plans/contratos-front.md`.
- La UI la hace Front: aquí núcleo, proto, `mctl` y puente.

## Tarea 1 — Activar u ocultar (rama 32b)
- Guardar la elección por paquete e ID (tabla nueva por migración en el store, junto a `pack_removed`). Sobrevive a
  una versión nueva del paquete; un ID nuevo entra visible; quitar el paquete borra su elección.
- Ocultar un playbook oculta también su `lib-<id>` derivado.
- RPC `SetItems(pack_id, hide[], show[])` y `Show`/`List` devuelven qué está oculto. `Install` acepta `hide[]`
  opcional para aplicar la elección al instalar.
- Filtran ocultos: `ListPlaybooks` (Patrol) y las listas de la biblioteca de scripts. No filtran: resolución por ID,
  colecciones (que marcan `hidden` en el elemento), trabajos guardados.
- `mctl pack items <id> --hide <item>… --show <item>…` y `mctl pack install … --hide <item>…`.

## Tarea 2 — Copiar a «Mis scripts» (rama 32b)
- RPC en `ScriptsService` (o `PackService` si encaja mejor con el resto): `CopyFromPack(script_id)` → script de
  usuario con ID nuevo, editable, nombre `<nombre> (copia)` vía `NombreLibre`. Si es derivado, `pre` + comandos.
- Quitar el paquete no borra las copias. `mctl scripts copy <id>`.

## Tarea 3 — Paquete personal (rama 32c)
- RPC `Export(editor_name "<editor>/<nombre>", script_ids[], include_playbooks bool, license, path)` y
  `mctl pack export`. Reglas del ADR: versión `AAAA.MMDD.HHMM` local, `min_core` = versión del núcleo (`0.0.0` si
  es `dev`), `license` `NOASSERTION` por omisión, `name_en`/`description_en` copian el español si falta, scripts como
  `lib-<editor>-<12 hex>`, playbooks con prefijo de editor en `playbooks/<id>.yaml`, README generado, sin firma.
- Plataformas exportables: `ios`, `ios-xe` y `wlc-9800` (cambio respecto al ADR: wlc-9800 es instalable desde la
  fase 34). Las demás se omiten con aviso. Los favoritos no viajan. El `.mpack` resultante debe pasar `pack.Verify`
  como no oficial.

## Tarea 4 — Importar a «Mis scripts» (rama 32c)
- RPC `Import(path, decisions)` con vista previa: mismas validaciones del instalador (pasos 1 a 6), confirmación,
  scripts por el import de siempre (editables), playbooks a `<config>/playbooks` con su ID con prefijo. Nunca un ID
  de la base, de los movidos ni de un paquete instalado. Choque de archivo o ID: renombrar u omitir, nunca
  sobrescribir. Catálogo recargado en caliente. `mctl pack import`.

## Review Focus
1. Un ID oculto que un trabajo programado pide sigue corriendo; un ID oculto no aparece en `ListPlaybooks`.
2. Reinstalar o actualizar un paquete conserva lo oculto; quitarlo lo borra.
3. Export → Import ida y vuelta: los scripts vuelven idénticos (comandos, tecnología, plataforma, etiquetas).
4. Un `.mpack` hostil importado no puede tapar la base, los movidos ni otro paquete, ni escribir fuera de
   `<config>/playbooks` (rutas con `..`, enlaces).
5. Concurrencia: ocultar mientras corre un trabajo o se recarga el catálogo (`atomic.Pointer`).
