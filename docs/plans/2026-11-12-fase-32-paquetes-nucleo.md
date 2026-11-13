# Fase 32: paquetes de contenido (.mpack) en el núcleo

Este plan implementa la parte de backend del [ADR 0010](../adr/0010-paquetes-de-contenido.md), que es la fuente de verdad: si algo de aquí lo contradice, gana el ADR. Release ya entregó la llave pública (`internal/pack/oom.pub`, PR #16) y se encarga de la firma en CI y de `mpack-keygen`. Front hace Ajustes → Paquetes cuando se abra su sesión.

**Fuera de esta fase:**
- el paquete `ios`, que no lleva playbooks nuevos hasta que el dueño lo pida;
- los paquetes de otras plataformas;
- el job de release que firma.

## Reglas comunes
- Para todo el contenido que no se mueve, la compatibilidad es exacta: mismos IDs, mismos scripts derivados (`lib-<id>`) y los mismos favoritos.
- **Seguridad, en las fronteras de confianza** (el `.mpack` es dato no confiable):
  - topes de tamaño y de entradas que cuentan los bytes leídos;
  - sin rutas fuera de las del formato, sin `..`, sin enlaces y sin entradas de directorio;
  - un paquete solo puede traer contenido de lectura: cada comando de sus playbooks pasa por `CheckDenied`.
- **Sin dependencias nuevas.** Se usa lo que ya está: `archive/zip`, `crypto/ed25519`, `crypto/sha256` y el yaml que ya usa el repo.
- **i18n (30a–30c):**
  - errores gRPC con `service.Err`/`ErrFrom` y códigos estables en inglés (`pack.err.*`, `pack.missing`), con catálogo es/en en `internal/i18n/catalog_pack.go`;
  - la auditoría siempre en inglés con `clave=valor`.
- **ADR 0008:** `internal/pack` es infraestructura y queda fuera de `Domains`. `PackService`, `cmd/mctl/pack` y `ui/bridge/pack.go` siguen el molde vertical. En las listas de registro, agrega al final.
- **TDD:** la prueba que falla va primero. Cada lógica nueva lleva al menos una mutación a mano.

## Tarea 1: `internal/pack`, leer y validar un `.mpack`
- `Verify(data []byte, coreVersion string, pub []ed25519.PublicKey) (*Pack, error)` hace los pasos 2 a 6 del ADR sobre bytes que ya están en memoria:
  - zip con sus rutas, topes e índice;
  - firma;
  - manifiesto con `KnownFields`;
  - `min_core`, con la regla de `dev`;
  - playbooks con `playbook.Load` y `CheckDenied`, solo para `ios`/`ios-xe` y que estén en `platforms`;
  - scripts con `Validate`, `origin: biblioteca` e ID `lib-…`;
  - prefijo de editor en los IDs de terceros;
  - el editor `oom` exige firma oficial.
- La llave oficial se carga con `//go:embed oom.pub` (base64 estándar de 32 bytes con `\n` final). Las pruebas generan su par con `ed25519.GenerateKey` y nunca usan la llave real.
- `Pack` expone el manifiesto, `Official bool`, los playbooks, los scripts, el README y el sha256 del archivo.
- **Motivos de rechazo con código estable**, uno por regla: `signature.invalid`, `zip.path`, `zip.dup`, `zip.too_big`, `index.mismatch`, `manifest.invalid`, `core.too_old`, `playbook.denied`, `playbook.platform`, `script.invalid`, `id.prefix`, `editor.reserved`…
- Las pruebas arman zips a mano para cada regla: válido oficial, válido de terceros, y una prueba por cada motivo. Incluye una bomba de compresión (lo que se mide son los bytes leídos, no la cabecera) y un README de más de 64 KB.
- Lo mismo vale para una carpeta fuente `packs/<nombre>/` sin `SIGNATURE`: necesita una función que arme el zip determinista desde la carpeta (`Build(dir) ([]byte, error)`) o que valide la carpeta. Úsala en la prueba de CI de la Tarea 4.

## Tarea 2: almacén de paquetes instalados
- `<datos>/packs/<editor>/<nombre>/`, con extracción atómica: `.tmp-*`, luego `rename`, y la versión anterior se borra solo después. Al abrir se limpian los `.tmp-*` que hayan quedado.
- `Install`:
  - aplica los choques del paso 7 (base, otros paquetes y scripts derivados de playbooks; los playbooks de `<config>/playbooks` no cuentan);
  - solo una versión más nueva del mismo paquete reemplaza a la anterior;
  - un paquete oficial solo lo reemplaza otro oficial;
  - una versión igual o más vieja exige quitar la instalada primero.
- `Remove(id)` y `Show(id)` buscan el id entre los instalados y nunca lo unen a una ruta. `Remove` deja anotados los IDs del paquete quitado, para `pack.missing`.
- `List` da id, versión, si es oficial, cuántos playbooks y scripts trae, y los IDs que quedan tapados.
- **Al arrancar se revalida cada paquete instalado** (sha256, índice, firma, sin archivos de más ni enlaces). El origen sale de esa revalidación. Si uno falla, se omite, se audita el aviso y el núcleo sigue funcionando.

## Tarea 3: catálogo en el núcleo, en caliente, con `pack.missing`
- **Precedencia:** base embebido < paquetes < `<config>/playbooks`. Hoy `loadPlaybooks` está en `internal/core/core.go:186` y `c.pbs` se usa en `core.go:365` y en `services.go:202,534`.
- **El catálogo se publica bajo lock**, o con un `atomic.Pointer` a un snapshot inmutable. Instalar o quitar arma una copia nueva y la publica. Un trabajo armado conserva el snapshot que tenía al armarse: revisa `patrol.Deps.Playbooks`.
- **Biblioteca de scripts:** hoy `dom.LibraryWithEN(playbooks.FS)` en `internal/service/scripts/scripts.go:69`, con `sync.Once`. Debe salir del catálogo vigente, con el mismo ID `lib-<id>` y el mismo texto en inglés, más los scripts de los paquetes. Su caché se invalida al instalar o quitar.
- **Al quitar un paquete** se borran los favoritos de sus scripts.
- **`pack.missing`:**
  - Un trabajo que pide un ID movido a `oom/ios-xe` (lista compilada en el binario) o un ID de un paquete quitado falla con el reason estable `pack.missing`, con metadata `{playbook, pack}` y un texto que dice qué paquete instalar.
  - Cualquier otro ID inexistente da el error de siempre, byte por byte.
- **Auditoría:** `pack.install`, `pack.remove` y `pack.rejected`, con `id=… version=… sha256=… origin=official|third-party reason=…`.

## Tarea 4: migración de `ios-xe` a `packs/ios-xe`
- **Se mueve todo `playbooks/cisco/ios-xe/*`** a `packs/ios-xe/playbooks/` con `git mv`, para conservar el historial, salvo los cinco que quedan en la base: `pre-post`, `upgrade-check`, `metricas`, `analisis` y `tac-baseline`.
- **Los IDs no cambian.** El resto de `playbooks/cisco` (cat9k, ftd, ise, nx-os, sda, wlc-*) se queda donde está.
- **`packs/ios-xe/manifest.yaml`:** `id: oom/ios-xe`, `version: 1.0.0`, `min_core` igual a la versión actual del núcleo, name/name_en, description/description_en, `platforms: [ios-xe]`, `author` y `license: Apache-2.0`.
  - Antes de fijar `license`, revisa la licencia del repo: el paquete lleva la misma.
- **`packs/ios-xe/README.md`:** qué trae y cómo se carga, en español y en inglés (`mctl pack install`, Ajustes → Paquetes), con un tope de 64 KB.
- **La lista compilada de IDs movidos** (para `pack.missing`) sale de lo que se movió. Una prueba la compara con el contenido de `packs/ios-xe/playbooks`.
- **Prueba de CI** (`go test`, sin job nuevo): cada `packs/*` del repo pasa las reglas del instalador salvo la firma.
- **Pruebas que hoy usan playbooks movidos:**
  - el arnés de pruebas del núcleo instala el paquete desde `packs/ios-xe` (con una llave de prueba, o como de terceros con permiso) cuando la prueba lo necesite;
  - o la prueba pasa a usar un playbook base.
  - No debilites ninguna prueba.
- **`pack.missing` de punta a punta:** sin el paquete, un trabajo con `ios-xe/<movido>` falla con `pack.missing`; tras `pack install`, ese mismo trabajo sí arma.

## Tarea 5: `PackService`, `mctl pack`, puente y contrato
- **Proto** `api/proto/macuahuitl/v1/pack.proto`: `Install{path, allow_unsigned}`, `List`, `Show{id}` (manifiesto y README) y `Remove{id}`. Después, `buf lint && buf generate`.
- **`Install` recibe la ruta:**
  - se lee una sola vez con tope de 20 MB;
  - con `allow_unsigned=false`, un paquete de terceros se rechaza con `pack.err.unsigned`.
- **Servicio** en `internal/service/pack`, registrado al final de `internal/core/modules.go`.
- **`mctl pack install <archivo> [--allow-unsigned] | list | show <id> | remove <id>`.** Va en `cmd/mctl/pack` y se registra con una línea en `cmd/mctl/main.go`.
- **`ui/bridge/pack.go`:** `packInstall`, `packList`, `packShow` y `packRemove`. Los errores pasan por `wrapErr`.
  - El README y los nombres viajan como texto plano. El front lo dibuja sin HTML (el ADR prohíbe pedir recursos a la red).
  - En el front: tipos y la parte de Wails en `modules/<área>/api.ts` más su `fake.ts`, si el patrón lo pide. La vista la hace front.
- **Contrato:** sección nueva al final de `docs/plans/contratos-front.md` con:
  - la forma de cada método;
  - los reasons `pack.err.*` y `pack.missing` con su metadata;
  - qué muestra la lista (oficial/terceros, tapados);
  - la regla de mostrar el README como texto plano.

## Pruebas mínimas
- Una prueba por cada regla de rechazo.
- Ida y vuelta: install → list → show → remove.
- Reemplazo por una versión más nueva, y rechazo de una igual, de una más vieja o de un oficial por uno de terceros.
- Revalidación al arrancar: un archivo alterado en disco hace que el paquete se omita con aviso.
- En caliente: el catálogo y la biblioteca cambian sin reiniciar, y un trabajo armado conserva su snapshot.
- `pack.missing`, de punta a punta.
- Auditoría en inglés.
- Ningún secreto ni ruta absoluta del usuario en la metadata, salvo la ruta que el usuario mismo pasó.
- La lista de IDs movidos coincide con `packs/ios-xe`.
- `packs/*` válidos.

## Review Focus
1. Recorrer el zip: nombres con `..`, `\`, rutas absolutas, Unicode que se parece a `/`, entradas de directorio y nombres repetidos que solo cambian en mayúsculas.
2. Firma: un índice que no cubre algún archivo, y que el orden de bytes sea estable.
3. Carrera entre instalar o quitar y un trabajo que arma en ese momento.
4. Choque de IDs con los scripts derivados.
5. Un usuario que viene de una versión anterior y no tiene el paquete.
