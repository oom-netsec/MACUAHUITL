# Fase 29c — Colecciones de scripts

Pedido del dueño (vía la sesión de front). Amplía la bóveda de scripts de la fase 28c (#53: `internal/scripts`, `internal/service/scripts`, `scripts.proto`, `mctl scripts`, `modules/scripts`).

## Modelo
- **Colección.** Campos `{id, nombre (1-64, único sin importar mayúsculas con la clave de nombre que ya existe, NameKey), descripción (≤512), orden de la colección, script_ids []string ordenados, creada, actualizada}`.
- **Un solo nivel.** Una colección no contiene colecciones.
- **Referencias por ID.** Las colecciones guardan IDs de script, incluidos los de la biblioteca (`lib-*`), sin copiarlos. Un script puede estar en varias colecciones. Al borrar un script de usuario se quita de todas las colecciones.
- **«Favoritos» es la colección por defecto.** Su ID fijo es `favoritos`. No se puede borrar ni renombrar, pero sí reordenar.
  - Una migración convierte la tabla de favoritos actual en esa colección, con orden por fecha de marcado o por nombre si no la hay.
  - `SetFavorite` se mantiene como atajo: agrega o quita en `favoritos`. El campo `favorite` de `Script` sigue existiendo y se calcula.
- **`pinned`.** Es un flag por script, independiente de las colecciones, para la barra corta de la terminal. Hay un máximo de 5 fijados: el sexto da FailedPrecondition con el motivo. El orden de los fijados es configurable.

## Reglas globales
- Persistencia en el store SQLite con su migración, numerada tras la última de main. Debe correr sobre una base que ya tiene favoritos sin perder ninguno; agrega una prueba con datos de la migración 0004.
- Auditoría: crear, editar, borrar o reordenar una colección; agregar o quitar un script de una colección; fijar o desfijar; exportar e importar.
- TDD, al menos una mutación por lógica nueva, y nada de dependencias nuevas.

## Export / import de colecciones
- El export lleva colecciones completas: `{"formato":"macuahuitl-colecciones","version":1,…,"colecciones":[…],"scripts":[…],"sha256":…}`.
  - `scripts` trae solo los scripts de usuario que las colecciones referencian.
  - Los de biblioteca viajan solo por ID.
  - El archivo usa el mismo canon, la misma suma, el mismo tope de 5 MB y las mismas reglas de archivo que el export de scripts. Reutiliza `internal/scripts/exchange.go` en lugar de duplicarlo.
- El import va en 2 pasos, como el de scripts:
  - La vista previa da un estado por colección: `nueva`, `igual` o `conflicto_nombre`.
  - Los scripts incluidos se planean con el `Plan` existente: nuevo, igual, conflicto_id o conflicto_nombre.
  - Un `lib-*` que no existe en la biblioteca local se avisa y se omite de la colección.
  - Las decisiones de colecciones y de scripts se aplican en una sola transacción.
  - Los IDs renombrados o reasignados en los scripts se reflejan en las referencias de las colecciones importadas.
  - El token se saca bajo el lock.
- `favoritos` importado se fusiona con la local (agrega los que falten, sin duplicados) y nunca la reemplaza.

## Proto, mctl, puente y contrato
- `ScriptsService` gana:
  - `ListCollections`, `GetCollection`, `SaveCollection`, `DeleteCollection` y `ReorderCollections`;
  - `SetCollectionScripts(id, script_ids)` para agregar, quitar y reordenar de una vez;
  - `SetPinned(id, bool)` y `ReorderPinned`;
  - `ExportCollections(ids, path, overwrite)`, `PreviewImportCollections(path)` y `ApplyImportCollections(token, decisiones)`.
- `Script` gana `pinned` y `collections` (los IDs de las colecciones que lo contienen).
- mctl: `mctl scripts col list|show|add|edit|rm|set|export|import` y `mctl scripts pin`, con su `help.golden`.
- Puente y TS en `modules/scripts` (`api.ts` y `fake.ts`).
- Contrato: una sección nueva al final de `docs/plans/contratos-front.md`.

## Pruebas mínimas
- La migración de favoritos a la colección `favoritos`, con datos existentes.
- `favoritos` no se puede borrar ni renombrar, y `SetFavorite` sigue funcionando.
- Un script en varias colecciones. Borrarlo lo quita de todas. Un script de biblioteca se referencia sin copiarse.
- El tope de 5 fijados y el orden de los fijados.
- Export e import de ida y vuelta (una colección con 3 propios y 2 de biblioteca).
- Cada estado y cada decisión. Los IDs reasignados actualizan las referencias.
- Un `lib-*` inexistente se avisa. `favoritos` se fusiona.
- El token se rechaza en paralelo o vencido.
- mctl de punta a punta.
