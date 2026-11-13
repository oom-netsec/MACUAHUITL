# ADR 0010: Paquetes de contenido (.mpack)

Fecha: 2026-11-12 · Estado: aceptado

## Contexto

Hoy todos los playbooks viven embebidos en el binario (`playbooks/cisco`, 57 de IOS-XE), junto con la biblioteca de scripts que se deriva de ellos (`internal/scripts/biblioteca.go`). Cada contenido nuevo obliga a sacar una versión del núcleo. Quien trabaja solo con ACI recibe también el contenido de wireless y de firewall, que no ocupa. La comunidad no tiene cómo aportar contenido sin tocar el núcleo, y faltan tecnologías completas, como los playbooks de IOS clásico.

El dueño pidió paquetes cargables por tecnología y por uso, con las instrucciones de carga dentro del mismo paquete.

## Decisión

El contenido sale del binario en **paquetes de contenido** (`.mpack`), que se instalan a mano. El núcleo sigue igual.

### Formato

Un `.mpack` es un zip con **exactamente** estas rutas, sin subcarpetas ni entradas de directorio:

```
manifest.yaml              obligatorio
README.md                  obligatorio; qué trae y cómo se carga (español e inglés); tope de 64 KB
playbooks/<nombre>.yaml    mismo formato que playbooks/cisco (internal/playbook); <nombre> cumple ^[a-z0-9][a-z0-9._-]{0,63}$
scripts.json               opcional; formato de export de scripts (internal/scripts/exchange.go, «macuahuitl-scripts» v1)
SIGNATURE                  opcional; solo la llevan los paquetes oficiales
```

- **Manifiesto** (`KnownFields`):
  - `id`: cumple `^[a-z0-9][a-z0-9-]{0,31}/[a-z0-9][a-z0-9-]{0,31}$` (`<editor>/<nombre>`, p. ej. `oom/ios-xe`).
  - `version` y `min_core`: cumplen `^\d+\.\d+\.\d+$`, sin `v` ni prerelease.
  - `name` y `name_en`, `description` y `description_en`.
  - `platforms`: plataformas de los playbooks, de la lista `knownPlatforms` de `internal/playbook`, y de los scripts, de `scripts.Platforms`.
  - `author` y `license` (identificador SPDX).
- **Índice:** no viaja en el zip: se calcula de sus entradas como una línea `sha256  ruta` por cada archivo menos `SIGNATURE`, ordenadas por ruta en orden de bytes y terminadas en `\n`. Eso es lo que se firma.
- **`SIGNATURE`:** la firma Ed25519 de ese índice, en base64 y en una sola línea. Se usa `crypto/ed25519` de la biblioteca estándar, sin dependencias nuevas.
- **Editor `oom` reservado:** solo pueden usar `oom/*` los paquetes con firma oficial válida.
- **IDs de terceros con prefijo:** en un paquete de terceros, el `id` de cada playbook va como `<plataforma>/<editor>-<id>` y el de cada script como `lib-<editor>-<id>`, para que un tercero no ocupe un ID que un trabajo ya usa o que un paquete oficial usará después.
- **Editores reservados:**
  - Como los IDs oficiales también llevan `-` (`l2-stp`, `svc-aaa`), el prefijo solo no basta.
  - El editor de un paquete de terceros cumple `^[a-z0-9]{1,16}$`, sin guion; así `l2-stp` no puede ser editor.
  - Tampoco puede ser `oom` ni un segmento reservado. Los segmentos reservados son una lista compilada en el binario: los nombres de plataforma, el primer segmento de los IDs de la base y de los movidos a `oom/ios-xe` (`l1`, `l2`, `l3`, `plat`, `svc`, `tac`, `vpn`…) y los previstos para paquetes oficiales.
  - CI rechaza un paquete oficial que use un segmento fuera de esa lista.
  - Los IDs movidos y sus `lib-<id>` quedan reservados para paquetes oficiales aunque `oom/ios-xe` no esté instalado.

### Instalación (todo o nada)

`mctl` o la app le pasan al núcleo la **ruta** del `.mpack`, y el núcleo lo valida, lo extrae y lo da de alta así:

1. **Lectura única.** El núcleo abre la ruta una sola vez y lee el archivo a memoria con tope de 20 MB. El sha256 auditado, la validación y la extracción salen de esos mismos bytes; no hay segunda lectura del disco.
2. **Zip.**
   - Solo las rutas de la sección Formato.
   - Sin nombres repetidos ni enlaces.
   - Como máximo 2000 entradas y 20 MB descomprimidos, contados con los bytes que realmente se leen (`io.LimitReader`), no con las cabeceras del zip.
   - El índice se calcula de las entradas leídas (sha256 de los bytes reales, no de las cabeceras), así que cubre todo archivo del zip.
3. **Firma.**
   - Si hay `SIGNATURE` y valida con la llave oficial compilada en el binario, el paquete es **oficial**.
   - Si hay `SIGNATURE` y no valida, se rechaza con el motivo `signature.invalid`.
   - Si no hay `SIGNATURE`, el paquete es de **terceros**. Se instala solo con confirmación explícita: `--allow-unsigned` en `mctl` o el diálogo con aviso en la app.
   - La firma solo indica el origen; ningún paquete se salta las validaciones de los pasos 4 a 6.
4. **Manifiesto.**
   - Cumple la gramática de la sección Formato.
   - `min_core` ≤ versión del núcleo, quitando la `v`. Un núcleo `dev` acepta cualquier `min_core` y lo anota en la auditoría.
5. **Playbooks.**
   - Se cargan con `playbook.Load` sobre `playbooks/`.
   - Cada comando pasa por `CheckDenied`: un solo comando que no sea de lectura rechaza el paquete entero.
   - Solo se aceptan plataformas que ya tengan driver de Patrol y driver de Patrol; `CheckDenied` es el mismo de `ios-xe` (hoy `ios`, `ios-xe` y `wlc-9800`, sin reglas propias para ninguna). Las demás se rechazan hasta que su fase les dé driver y reglas, porque, por ejemplo, NX-OS encadena comandos con `;` y redirige con `>`.
   - La plataforma de cada playbook debe estar en `platforms` del manifiesto.
   - El script derivado `lib-…` de cada playbook pasa `Validate`; si no, se rechaza el paquete, porque uno solo inválido tumbaría la biblioteca entera.
6. **Scripts.**
   - Llevan `origin: biblioteca` e ID `lib-…`, así que quedan de solo lectura por `IsLib`.
   - Se validan con las mismas reglas que un archivo importado a mano (`Validate`, ASCII imprimible, topes).
   - Pueden traer texto de configuración, igual que la biblioteca actual, porque un script nunca se ejecuta: la terminal lo inserta sin Enter y Patrol solo corre los de lectura (ADR 0007).
7. **Choques.**
   - Se rechaza la instalación si un ID de playbook o de script, o el nombre de un script (`NameKey`), choca con el contenido base, con otro paquete o con los scripts derivados de playbooks.
   - La única excepción es una versión más nueva del mismo paquete, que reemplaza a la anterior. Un paquete oficial instalado solo lo reemplaza otro con firma oficial.
   - Para instalar una versión igual o más vieja que la instalada, primero se quita la instalada.
8. **Extracción atómica.**
   - Se extrae a `<datos>/packs/.tmp-*`, conservando `SIGNATURE` y `manifest.yaml`, y el instalador escribe ahí el índice calculado como `INDEX`.
   - Entra con `rename` a `<datos>/packs/<editor>/<nombre>/`.
   - La versión anterior se borra solo después del `rename`.
   - Al arrancar se limpian los `.tmp-*` que hayan quedado.

`remove` y `show` buscan el `id` entre los paquetes instalados y nunca lo unen a una ruta.

### Carga y catálogo

- **Al arrancar** se revalida cada paquete instalado: se recalculan los sha256 contra `INDEX` (sin archivos de más ni de menos; `INDEX` y `SIGNATURE` no cuentan), se verifica la firma de `INDEX`, que no haya enlaces, y se reaplican los pasos 4 a 7 en orden estable (oficiales primero), así un `oom/*` alterado a mano o una regla nueva del núcleo también se revisan. El origen (oficial o de terceros) se deriva de esa revalidación, nunca de un campo guardado. Si un paquete no pasa, se omite y se avisa; el núcleo sigue funcionando.
- **Precedencia:** contenido base < paquetes < `<config>/playbooks`. Los playbooks del usuario siguen reemplazando por ID y no cuentan como choque al instalar. `pack list` marca los IDs que quedan tapados.
- **Scripts derivados:** cada playbook de un paquete genera su script `lib-<id>` igual que hoy, con el mismo ID que tenía embebido, así que los favoritos sobreviven al mover `ios-xe` a un paquete.
- **En caliente:** instalar y quitar recargan el catálogo sin reiniciar el núcleo. Se arma una copia nueva y se publica bajo lock, y se invalida la caché de la biblioteca de scripts. Un trabajo armado conserva los playbooks que tenía al armarse.
- **Al quitar un paquete** se borran también los favoritos de sus scripts.
- **Contenido base** (sigue embebido): `ios-xe/pre-post`, `ios-xe/upgrade-check`, `ios-xe/metricas`, `ios-xe/analisis` e `ios-xe/tac-baseline`, que el código o las ayudas de `mctl` y de la UI usan por ID, más los scripts de configuración de la biblioteca. El resto de `playbooks/cisco/ios-xe` pasa al paquete oficial `oom/ios-xe` y conserva sus IDs.
- **`pack.missing`:**
  - Un trabajo que pide un ID de la lista de IDs movidos a `oom/ios-xe` (compilada en el binario) o un ID de un paquete quitado (se anota en la base al quitarlo) falla con el motivo estable `pack.missing`, que dice qué paquete instalar.
  - Cualquier otro ID inexistente sigue con el error actual.
- **No-egress:** la app nunca descarga paquetes ni busca actualizaciones. Los paquetes se bajan a mano de los releases de GitHub o se reciben por otro medio.

### Interfaces

- **CLI:**
  - `mctl pack install <archivo.mpack> [--allow-unsigned]`
  - `mctl pack list`
  - `mctl pack show <id>`: muestra el manifiesto y el README.
  - `mctl pack remove <id>`
- **App:** Ajustes → Paquetes.
  - Muestra la lista de instalados: id, versión, oficial o de terceros, cuántos playbooks y scripts trae, y los IDs tapados.
  - Permite instalar desde un archivo y quitar.
  - Muestra el README de cada paquete como texto plano, o como Markdown sin HTML, sin imágenes y sin enlaces clicables. Nombre y descripción también van como texto plano, para que nada del paquete pida recursos a la red ni meta HTML en el webview.
- **Código:**
  - `internal/pack` es infraestructura del núcleo, igual que `internal/playbook`; queda fuera de `Domains` en `tools/archcheck/domains.go`.
  - `core` arma el catálogo y lo expone a los servicios por `service.Deps`.
  - El `PackService` (gRPC), `cmd/mctl/pack`, `ui/bridge/pack.go` y el módulo de la UI siguen el molde vertical del ADR 0008.
- **Auditoría** (siempre en inglés): `pack.install`, `pack.remove` y `pack.rejected`, con id, versión, sha256 del archivo, origen (`official` o `third-party`) y, si aplica, el motivo.

### Paquetes oficiales y release

- **Fuente:** `packs/<nombre>/` en el repo, con la misma estructura del zip pero sin `SIGNATURE`.
- **Paquetes oficiales:**
  - Primeros: `ios-xe`, que sale de la migración, e `ios`, nuevo, para IOS clásico.
  - Después, cada uno tras la fase que le dé driver y reglas de `CheckDenied` a su plataforma (reglas propias de `CheckDenied` cuando la plataforma las necesite): `nx-os`, `fw` (ASA/FTD), `aci`, `wireless` (9800/AireOS), `ise` y `sda`.
  - Un paquete sin playbooks no se publica.
- **Firma en CI:** el job de release arma cada paquete con un zip determinista (orden fijo y fechas fijas), lo firma con la llave privada del secret `MPACK_SIGNING_KEY` y lo sube como asset (`oom-<nombre>-<versión>.mpack`) con su entrada en `SHA256SUMS`.
- **La llave es del dueño:**
  - Se genera una sola vez con `go run ./tools/packaging/mpack-keygen`. La pública se sube al repo (`internal/pack/oom.pub`); la privada vive solo en el secret y en un respaldo fuera de línea del dueño.
  - **Si se rota:** el núcleo nuevo acepta la llave anterior durante una versión, y en ese tiempo se vuelven a firmar los paquetes oficiales.
- **CI en cada PR:** valida cada `packs/*` con las mismas reglas del instalador, salvo la firma.

### Selección por elemento y paquete personal (fase 32b)

- **Activar u ocultar.**
  - Al instalar, la app muestra la lista de playbooks y scripts del paquete con casillas. Lo que no se marque se instala igual y solo queda oculto, y el diálogo lo dice. Después se cambia en Ajustes → Paquetes o con `mctl pack items <id> --hide|--show <item>…`.
  - Ocultar solo afecta listas y selectores. El ID sigue resolviéndose (`mctl` y los trabajos lo pueden pedir), cuenta para los choques y se revalida al arrancar, porque la firma cubre el paquete entero.
  - Ocultar un playbook oculta también su `lib-<id>`. En las colecciones, un script oculto se ve marcado como oculto.
  - La elección se guarda por paquete y por ID y se respeta al instalar una versión nueva; un elemento nuevo de esa versión entra visible. Al quitar el paquete se borra la elección junto con sus favoritos.
- **Copiar a «Mis scripts».**
  - Cualquier script de un paquete se copia a la colección del usuario con un ID nuevo de usuario y queda editable. Así se toma 1 script de un paquete y 3 de otro. Quitar el paquete no borra las copias.
  - Como el nombre original sigue ocupado mientras el paquete esté instalado, la copia recibe el nombre libre `<nombre> (copia)` (`NombreLibre`).
  - Si es un script derivado, la copia lleva los comandos de `pre` más los del playbook.
- **Paquete personal (export).** `mctl pack export` y Ajustes → Paquetes → Exportar arman un `.mpack` sin firma con los scripts del usuario que se elijan (con su tecnología, plataforma y etiquetas), sus playbooks de `<config>/playbooks` si se piden, y un README generado.
  - El usuario da `<editor>/<nombre>`, con las reglas de editores reservados.
  - Versión: `AAAA.MMDD.HHMMSS` de la hora local (con segundos para que dos exports en el mismo minuto no den la misma versión; son tres números, así que pasa `semverRe`), así que crece sola en cada export.
  - `min_core`: la versión del núcleo, o `0.0.0` si el núcleo es `dev`.
  - `license`: `NOASSERTION` si el usuario no da otra. `name_en` y `description_en` copian el texto en español si falta.
  - IDs: los scripts salen como `lib-<editor>-<12 hex>`, únicos dentro del paquete, para no pasar el tope de `Validate`. Los playbooks salen con el prefijo de editor, cada uno en `playbooks/<id con prefijo>.yaml`.
  - Solo se exportan los playbooks de `ios`, `ios-xe` y `wlc-9800`; los demás no se exportan, y se avisa cuáles quedaron fuera.
  - Los favoritos no viajan, igual que en el export de scripts.
- **Importar a «Mis scripts» (respaldo).**
  - Cualquier `.mpack` sin firma, personal o no (no se distinguen), se puede instalar como paquete de solo lectura o importar. Importar pide la misma confirmación y pasa las mismas validaciones del instalador (pasos 1 a 6).
  - Los scripts entran editables por el import de scripts de siempre.
  - Los playbooks van a `<config>/playbooks` **con su ID con prefijo**; el import no restaura IDs sin prefijo, porque eso dejaría a cualquier paquete sin firma tapar la base. Ningún playbook importado puede tener un ID de la base, de los movidos ni de un paquete instalado.
  - Si ya existe el mismo archivo o el mismo ID, se pide renombrar u omitir, igual que en el import de scripts; nunca se sobrescribe.
  - Se audita `pack.import` (id, sha256 y origen) y el catálogo se recarga en caliente, igual que al instalar.

## Consecuencias

- El contenido y el núcleo se versionan por separado. Agregar playbooks ya no exige una versión nueva del núcleo, y la comunidad puede publicar paquetes sin tocarlo.
- Cada ingeniero ve en las listas solo lo que instaló.
- Patrol sigue siendo de solo lectura: los playbooks de un paquete pasan por `CheckDenied` igual que los embebidos, y solo en plataformas con reglas propias. Las plantillas de cambio asistido (ADR 0007) se quedan en el núcleo; los paquetes no pueden traer plantillas de escritura.
- Quien venga de una versión anterior pierde los playbooks movidos hasta que instale `oom/ios-xe`. Las notas del release lo dicen, y un trabajo que los use falla con `pack.missing`.
- Aparece una llave que hay que custodiar. Si se pierde o se filtra, sale un núcleo nuevo con otra llave pública y se vuelven a firmar los paquetes.

### Gemelo de playbook

Un playbook elegido corre en su gemelo (`ios/x` por `ios-xe/x` y al revés) solo entre `ios` e `ios-xe`, y solo si los dos son del mismo paquete o los dos oficiales (base, propios del usuario u `oom/*`).

## Enmienda (fase 34): wlc-9800 como plataforma instalable

`wlc-9800` entra en las plataformas instalables de un paquete porque tiene driver: el de IOS-XE, con detección propia por «C9800» en `show version`. Sus playbooks pasan por el mismo `CheckDenied` que los de `ios-xe`, sin reglas propias. El gemelo `ios/ios-xe` no aplica a `wlc-9800`: un 9800 usa los playbooks de `ios-xe` directamente. Los playbooks pueden además declarar datos (`params`: MAC, AP, interfaz, IP) que el núcleo valida y sustituye antes de volver a pasar `CheckDenied`. El paquete oficial `oom/wlc-9800` los usa para los casos de un cliente o un AP puntual.

## Enmienda (fase 32c): export e import del paquete personal

Se implementa tal como lo describe «Selección por elemento y paquete personal», con estas precisiones:

- **Plataformas del export:** `ios`, `ios-xe` y `wlc-9800` (wlc-9800 es instalable desde la fase 34). Los playbooks de otras plataformas, y los que un paquete no aceptaría (ID con caracteres fuera de `a-z0-9-` o script derivado inválido), se omiten y se avisa por ID.
- **El import es de dos pasos sin token** (`Import` sin y con `confirm`) y se revalida completo en cada uno. Un `.mpack` con firma oficial no se importa: se instala. Un playbook que choca (ID de la base, de los movidos, de un paquete instalado o de `<config>/playbooks`, o archivo existente) pide renombrar (`<id>-2`…) u omitir; `reemplazar` se rechaza. Los archivos se crean con `O_EXCL` y sin seguir enlaces dentro de un `os.Root` sobre `<config>/playbooks`, y la escritura es todo o nada junto con la base de scripts.
- **Versión con segundos:** el export usa `AAAA.MMDD.HHMMSS` en vez de `AAAA.MMDD.HHMM`; sigue siendo semver de tres números y crece dentro del día.
- **Un paquete instalado después de un import** con los mismos IDs de playbook queda tapado por la copia importada en `<config>/playbooks` (`Shadowed`); es de diseño, igual que con cualquier playbook del usuario.
- **Vista previa atada a lo aplicado:** `Import` acepta el `sha256` de la vista previa y con `confirm` falla (`pack.err.import.changed`) si el archivo cambió.
