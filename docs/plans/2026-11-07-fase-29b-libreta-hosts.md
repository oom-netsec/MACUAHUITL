# Fase 29b — Libreta de hosts (fuente «manual» del inventario)

Pedido del dueño (vía la sesión de front). Hoy `InventoryService.ListDevices` arma la lista de equipos conocidos a partir de sus fuentes (patrol, flota, respaldos). El proto ya declara `PutDevice` y `DeleteDevice`; revisa si están implementados.

La libreta de hosts NO es una segunda lista. Es la fuente nueva `manual` del mismo inventario: los hosts que el usuario agrega a mano aparecen en `ListDevices` con `sources` que incluye `manual`, y la terminal SSH elegirá el host de ahí y conocerá su plataforma.

## Reglas globales
- ADR 0008: todo vive en el área `inventory` (dominio, servicio, proto, mctl, puente y TS). No se crea un área nueva.
- Persistencia en el store SQLite (`d.DB()`) con su migración, numerada tras la última de main.
- **NUNCA un secreto en la libreta.** `credential_id` es una referencia a la bóveda (`internal/vault`). Al guardar se valida que exista y que no sea reservada (`vault.Reserved`). Si la bóveda está cerrada, se guarda la referencia sin validar y se avisa.
- Validación:
  - nombre de 1 a 64 caracteres;
  - dirección como IP o nombre DNS válido, sin espacios, ni `@`, ni esquema;
  - puerto de 1 a 65535 (22 por defecto);
  - plataforma de lista cerrada (ios, ios-xe, nx-os, asa, iosxr, wlc o la que ya use el inventario; reutiliza la lista existente);
  - carpeta de un solo nivel (`[A-Za-z0-9 _.-]{1,48}`, sin `/`);
  - hasta 10 etiquetas `[a-z0-9-]{1,24}`;
  - notas de hasta 2000 caracteres.
- **Dedupe por dirección** con lo que el inventario ya ve. Un host manual con la misma dirección que un equipo descubierto se fusiona en una sola fila de `ListDevices`, con las dos fuentes, y el nombre o la plataforma del manual tienen prioridad. No se pueden crear dos hosts manuales con la misma dirección y puerto (AlreadyExists).
- Auditoría de crear, editar, borrar, exportar e importar, sin notas ni datos sensibles en el detalle.
- TDD, al menos una mutación por lógica nueva, y nada de dependencias nuevas.

## Export / import (mismo esquema que la bóveda de scripts, fase 28c)
- El export es un JSON versionado `{"formato":"macuahuitl-hosts","version":1,"exportado":…,"hosts":[…],"sha256":…}`. El sha256 se calcula sobre el JSON canónico de `hosts`.
- La credencial viaja SOLO como su etiqueta (`credential_label`), nunca como id ni como secreto.
- El archivo es 0600, no sigue symlinks y no sobrescribe sin `overwrite`. Tope de 5 MB.
- El import va en 2 pasos:
  - `PreviewImportHosts(path)` devuelve un token (10 min) y un estado por host: `nuevo`, `igual` o `conflicto` (misma dirección y puerto con otros datos, o mismo nombre).
  - `ApplyImportHosts(token, decisiones)` aplica una decisión por host: renombrar, reemplazar u omitir. Todo va en una transacción. El token se saca bajo el lock (no se aplica dos veces).
- Al importar, `credential_label` se resuelve contra la bóveda local por etiqueta. Si no existe, el host queda sin credencial y la vista previa lo avisa.
- Toma como guía `internal/scripts/{exchange,importar}.go` y sus pruebas, incluidos los arreglos de la revisión de 28c (clave de nombre única, doble reemplazo y token en paralelo). Si conviene extraer lo común (archivo, suma, tokens) a un paquete compartido sin violar ADR 0008, hazlo; si no, duplica lo mínimo.

## Proto, mctl, puente y contrato
- `Device` gana los campos `name`, `folder`, `tags`, `credential_id`, `credential_label` (solo lectura) y `notes`, sin renumerar.
- `PutDevice` y `DeleteDevice` operan sobre los hosts manuales. Borrar un host manual no borra la evidencia de las otras fuentes.
- Se agregan `ExportHosts`, `PreviewImportHosts` y `ApplyImportHosts`. `ListDevices` admite filtrar por carpeta y por etiqueta.
- mctl: `mctl hosts list`, `add`, `edit`, `rm`, `export` e `import`, o bajo el área de inventario si ya existe un comando. Con su `help.golden`.
- Puente y TS en el módulo de inventario (`api.ts`/`fake.ts`).
- Contrato: una sección nueva al final de `docs/plans/contratos-front.md`.

## Pruebas mínimas
- Cada regla de validación, con su caso válido y su inválido.
- Nunca se guarda ni se exporta un secreto. Una credencial reservada se rechaza.
- Dedupe y fusión con una fuente descubierta.
- Persistencia tras reabrir el store.
- Export e import de ida y vuelta. Un byte cambiado da error de suma.
- Cada estado y cada decisión del import. El token vencido o en paralelo se rechaza.
- La credencial se resuelve por etiqueta al importar, o se avisa si no existe.
- mctl de punta a punta.
