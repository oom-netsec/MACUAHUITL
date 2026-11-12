# Fase 28c — Bóveda de scripts (área nueva)

Pedido del dueño (vía la sesión de front): scripts de comandos del usuario, más una biblioteca predefinida por tecnología, con favoritos y export/import a un archivo.

Caso de uso: el usuario A tiene 15 scripts. B importa 8 de los de A y suma 4 propios.

Esta rama entrega dominio → servicio → proto → mctl → puente → `api.ts`/`fake.ts`, más su sección en `docs/plans/contratos-front.md`. La vista la hace la sesión de front.

## Reglas globales
- ADR 0008: el área es un módulo vertical nuevo, `scripts`. Se registra con una línea al final de `internal/core/modules.go`, `cmd/mctl/main.go` y `tools/archcheck/domains.go`. El dominio no importa a otros dominios, salvo `internal/playbook` para `CheckDenied`, que ya es compartido; si archcheck no lo permite, el servicio calcula `read_only`.
- ADR 0007: un script nunca se aplica a un equipo desde esta área. Los usos son dos:
  - «enviar a la terminal»: la UI inserta el texto sin Enter, y la terminal ya es manual;
  - Patrol: solo si `read_only`.

  Aquí solo se expone `read_only`; integrar con Patrol va en otra rama.
- Sin dependencias nuevas. Persistencia en el store SQLite (`d.DB()`, como `internal/service/prefs`), con la migración donde el store define sus tablas.
- Todo cambio queda auditado: `scripts.crear`, `scripts.editar`, `scripts.borrar`, `scripts.favorito`, `scripts.exportar` (ruta y cuántos) y `scripts.importar` (ruta y decisiones).
- TDD; lógica nueva con al menos una mutación a mano.

## 1. Modelo y validación (`internal/scripts`)
- `Script`:
  - `ID` (16 bytes aleatorios en hex), `Name` (1–64), `Tech` (lista cerrada: `l2`, `l3`, `gestion`, `seguridad`, `qos`, `etherchannel`, `wireless`, `diagnostico`, `otro`) y `Platform` (`ios`, `ios-xe`, `nx-os`, `asa`, `cualquiera`);
  - `Description` (≤ 512), `Commands []string` (1–200 líneas de ≤ 512 caracteres, ASCII imprimible sin caracteres de control: IOS con 7 bits rompe lo demás), `Tags []string` (≤ 10, cada una `[a-z0-9-]{1,24}`);
  - `Origin` (`biblioteca` o `usuario`), `CreatedAt` y `UpdatedAt`.
- `ReadOnly(s)`: verdadero si todos sus comandos pasan `playbook.CheckDenied(plataforma, cmd)`. Con plataforma `cualquiera`, se usa la regla más estricta.
- Favoritos: una tabla aparte de IDs, porque también se marcan scripts de la biblioteca.

## 2. Biblioteca predefinida (solo lectura)
- Embebida con `go:embed` en `internal/scripts/biblioteca/*.yaml` (yaml.v3 ya es dependencia).
  - Se genera una vez desde los playbooks existentes (`playbooks/cisco/...`): un script de diagnóstico por playbook, con sus comandos `show`. El generador va en `tools/` o en una prueba que verifique que siguen en sincronía. Elige lo más simple y documéntalo.
  - Más unos 10 scripts de configuración comunes (VLAN de acceso, trunk, NTP, logging, SNMP RO, banner), marcados como no `read_only`.
- IDs estables `lib-<nombre>`. No se editan ni se borran. «Duplicar» crea una copia `usuario`.

## 3. Export / import
- Export de una selección de IDs (de usuario o de biblioteca) a una ruta elegida. El archivo:

  ```json
  {"formato":"macuahuitl-scripts","version":1,"exportado":"RFC3339","scripts":[…],"sha256":"<hex>"}
  ```

  - `sha256` se calcula sobre el JSON canónico del arreglo `scripts`. Es integridad contra corrupción, no autenticidad; dilo en el contrato.
  - Los favoritos no viajan.
  - Archivo 0600. No sobrescribe si existe, salvo `overwrite`.
- Import en dos pasos:
  1. `PreviewImport(path)` valida el archivo: ≤ 5 MB, ≤ 1000 scripts, formato y versión, sha256 y cada script con las reglas de §1. Devuelve un `token` (válido 10 min, en memoria) y, por script, su estado:
     - `nuevo`;
     - `igual` (mismo ID y contenido; se omite solo);
     - `conflicto_id` (mismo ID, contenido distinto);
     - `conflicto_nombre` (otro ID, mismo nombre).
  2. `ApplyImport(token, decisiones)` aplica. Cada decisión es `renombrar` (ID nuevo y nombre `<nombre> (importado)`, con sufijo numérico si hace falta), `reemplazar` u `omitir`. Faltar una decisión para un conflicto es un error. Todo en una transacción.
- Lo importado queda con `Origin = usuario`, aunque venga de la biblioteca de otro: si el ID es `lib-*`, se le asigna uno nuevo.

## 4. Proto, servicio, mctl, puente, contrato
- `scripts.proto`, `ScriptsService`: `ListScripts(filtro: tech, platform, tag, texto, solo_favoritos)`, `GetScript`, `SaveScript` (crear o editar; rechaza `lib-*`), `DeleteScript`, `SetFavorite(id, bool)`, `DuplicateScript`, `ExportScripts(ids, path, overwrite)`, `PreviewImport(path)` y `ApplyImport(token, decisiones)`. `Script` en el proto lleva `read_only` y `favorite`.
- mctl: área `scripts` con `list`, `show`, `add` (los comandos desde un archivo o stdin), `edit`, `rm`, `fav`, `dup`, `export` e `import` (vista previa y luego decisiones por bandera `--decision ID=renombrar|reemplazar|omitir` o `--all=omitir`). Con su `help.golden`.
- Puente `ui/bridge/scripts.go` y el módulo TS `modules/scripts/api.ts` + `fake.ts`, sin vista. Compón `core.ts`/`fake.ts` agregando al final.
- Contrato: sección nueva al final de `docs/plans/contratos-front.md`.

## Pruebas mínimas
- Validación: cada regla, con un caso válido y uno inválido.
- `ReadOnly`: un script de `show` → verdadero; uno con `interface`/`conf t` → falso.
- La biblioteca carga, sus IDs son únicos y no se puede editar ni borrar.
- Ida y vuelta del export/import (15 scripts, importar 8): la suma no corrompida; un byte cambiado da error de suma.
- Cada estado de la vista previa y cada decisión; una decisión faltante da error; el token vencido o desconocido da error; el tope de tamaño y de cantidad.
- Persistencia tras reabrir el store. Favoritos de la biblioteca y de usuario. El export no sobrescribe sin `overwrite`.
- mctl: `list` y `export`/`import` de punta a punta contra el núcleo de prueba.
