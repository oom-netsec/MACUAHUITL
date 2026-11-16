Fixtures en el formato de la documentación pública de Cisco ASA 9.x.
Sin validar en laboratorio.

Ninguno es una transcripción de un equipo real: cada archivo sigue el formato de un ejemplo publicado por Cisco, con valores adaptados (IPs de documentación o 10.x, series falsas `FCH0000A00N`, hostnames genéricos, credenciales `clave-de-prueba`). Las MAC del cluster (`0015.c500.*`) y la red del enlace de control (`127.2.x.x`) se dejaron como en el ejemplo de Cisco. Los archivos `sys_`, `aa_` y `ctx_` describen un mismo par: dos FPR-2130 con 9.17(1) en activo/activo, con los contextos admin, ctx1 y ctx2. Prefijos: `sys_` espacio del sistema en multicontexto, `ctx_` dentro de un contexto, `aa_` failover activo/activo, `cl_` cluster.

**Cotejo pendiente.** cisco.com no deja descargar sus páginas fuera del navegador; se leyeron con un lector que resume. Hay dos tipos de archivo:

- **Citados** (líneas del ejemplo publicado, con valores adaptados): `show failover state`, `show failover history` (con y sin `details`), `show resource usage` (sistema, resumen y un contexto), `show version`, `show mode` y `show cluster info` con MASTER/SLAVE.
- **Reconstruidos en el formato de 9.x** a partir de la documentación y del conocimiento de la salida del ASA, sin una salida publicada completa delante: `aa_show-failover.txt` (el ejemplo publicado es de 7.0; se le agregaron las líneas de 9.x `Version: Ours/Mate`, `Serial Number: Ours/Mate`, `Reconnect timeout`, `MAC Address Move Notification Interval`, `Normal (Monitored)`, las filas nuevas de la tabla y `Logical Update Queue Information`), `sys_show-context.txt` (columnas Class y Mode de 9.x), `sys_show-context-detail.txt`, los `show running-config` / `more system:running-config` del sistema y del cluster, `cl_show-cluster-conn-count.txt` y `cl_show-cluster-info-control-data.txt` (derivado del de MASTER/SLAVE cambiando solo las palabras de estado; no trae los campos nuevos de 9.20, como `Cluster Member Limit` o `Site ID`).

**Fixtures de 42c** (todas reconstruidas, sin validar en laboratorio, "not yet tested in a lab"; prefijo `as_` = contexto único, A/S, 9.22): `as_show-failover.txt`, `as_show-failover-state.txt`, `as_show-checksum.txt`, `as_show-conn-count.txt`, `as_show-xlate-count.txt`, `as_show-asp-drop.txt`, `as_show-packet-tracer.txt`, `as_show-packet-tracer-drop.txt`, `as_show-packet-tracer-xml.txt` y `cl_show-cluster-info-health.txt` (no hay salida publicada de `health`: el formato es una suposición razonable). `aa_show-failover.txt` se ajustó con rasgos observados en un equipo real, sin copiar su salida: sangrías y columnas con tabulaciones, la línea `Link :`, la fila `Umbrella Device-ID` y la cola con columnas Cur/Max/Total por tabulaciones; `as_show-failover.txt` trae además la línea de la unidad con un espacio al final y filas de 9.22 con valores inventados. Los parsers tratan tabulaciones y espacios por igual y guardan las filas desconocidas de la tabla de estadísticas.

Antes de que un parser dependa de un detalle (espacios, orden de campos), coteja ese archivo con la página abierta en el navegador o con una salida de laboratorio.

Las URL de la columna «Fuente» son las páginas de Cisco de donde sale el formato. Abreviatura: CR = https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/S/asa-command-ref-S (ASA Command Reference, show commands); CFG = https://www.cisco.com/c/en/us/td/docs/security/asa (CLI Book 1, General Operations).

## Archivos

| Archivo | Comando | Versión del ejemplo | Fuente |
|---|---|---|---|
| sys_show-mode.txt | show mode (sistema) | 9.x | Aviso de seguridad cisco-sa-asa-scpcxt-filecpy (https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-asa-scpcxt-filecpy-rgeP73nE.html): solo muestra la línea `Security context mode: multiple` |
| ctx_show-mode.txt | show mode (en un contexto) | 9.x | Igual; la salida es la misma línea, solo cambia el prompt |
| sys_show-context.txt | show context | 9.x | CFG/asa917/configuration/general/asa-917-general-config/ha-contexts.html (View Context Information) |
| sys_show-context-detail.txt | show context detail | 9.17 | ha-contexts.html y CR/show-b-to-show-cq-commands.html; los contextos `system` y `null` y sus Flags/ID son la forma de la documentación, con valores ilustrativos |
| sys_show-resource-usage-system.txt | show resource usage system | 9.x | CR/m_show_p-show_r.html |
| sys_show-resource-usage-summary.txt | show resource usage summary | 9.x | CR/m_show_p-show_r.html |
| sys_show-resource-usage-context-admin.txt | show resource usage context admin | 9.x | CR/m_show_p-show_r.html |
| ctx_show-resource-usage-context-admin.txt | show resource usage, dentro del contexto admin (sin la palabra `context`, que solo existe en el sistema) | 9.x | Igual; cambian el prompt y el comando |
| sys_show-version.txt | show version (Firepower 2130, multicontexto, A/A, 2 contextos) | 9.17(1) | CR/m_show_u-show_z.html; versión, serie e imágenes sustituidas por valores de prueba |
| sys_show-running-config.txt | show running-config (sistema, con class, context, allocate-interface, config-url) | 9.17 | Armado con las líneas de configuración de ha-contexts.html (context, allocate-interface, config-url, member, class); no hay en la documentación una salida completa del sistema |
| sys_show-running-config-cred.txt | more system:running-config con `config-url ftp://…` y `https://usuario:clave-de-prueba@…`, y `failover key clave-de-prueba` | 9.17 | CFG/asa917/.../ha-failover.html (failover key, failover group, join-failover-group) |
| sys_show-running-config-failover-key-hex.txt | more system:running-config \| include ^failover, con `failover key hex 0123...` | 9.17 | Igual (sintaxis `failover key [0 \| 8] {hex key \| shared_secret}`) |
| aa_show-failover.txt | show failover (A/A, grupos 1 y 2) | 9.17, reconstruido sobre el ejemplo de 7.0(0)79 (ver Cotejo pendiente) | CR/show-f-to-show-ipu-commands.html (muestra Active/Active) |
| aa_show-failover-state.txt | show failover state (A/A) | 9.x | CR/show-f-to-show-ipu-commands.html |
| aa_show-failover-history.txt | show failover history | 9.x | CR/show-f-to-show-ipu-commands.html |
| aa_show-failover-history-details.txt | show failover history details (con el historial del par) | 9.9(2) o posterior | CR/show-f-to-show-ipu-commands.html |
| cl_show-cluster-info.txt | show cluster info (4 unidades, MASTER/SLAVE) | 9.5(2) | CFG/asa922/configuration/general/asa-922-general-config/ha-cluster-fp.html (Monitoring Cluster Status) |
| cl_show-cluster-info-control-data.txt | igual con CONTROL_NODE/DATA_NODE | 9.20 (renombre en 9.19(1)) | Mismo formato; solo cambian las palabras de estado, según la nota de 9.19(1) del comando `prompt` y de las guías de cluster |
| cl_show-cluster-conn-count.txt | show cluster conn count | 9.17 | CFG/asa917/.../ha-cluster-asav.html |
| cl_show-running-config-cluster-group.txt | more system:running-config \| begin cluster group, con `key clave-de-prueba` | 9.17 | CFG/asa917/.../ha-cluster-asav.html (Configure Control Node Bootstrap Settings) |
| prompts.txt | prompts del driver (4.2) | 9.x | CR/I-R/asa-command-ref-I-R/pr-pz-commands.html (comando `prompt`) |

## Para probar el enmascarado

En `show running-config` el ASA ya muestra `failover key *****` y `key *****`; las claves solo salen en claro con `more system:running-config`. Por eso estos archivos usan ese comando.

- **sys_show-running-config-cred.txt**: `config-url` con credencial en claro por ftp y https (`usuario:clave-de-prueba@`) y `failover key clave-de-prueba`.
- **sys_show-running-config-failover-key-hex.txt**: `failover key hex` (la otra forma de la clave).
- **cl_show-running-config-cluster-group.txt**: la clave del cluster. La documentación de 9.17 en adelante usa `key` dentro de `cluster group`, no `cluster-key`; el enmascarado tiene que cubrir `key` en ese contexto. No se encontró un ejemplo publicado con `cluster-key`.

## prompts.txt

Formato del comando `prompt` de cada grupo (el orden de las palabras fija el orden de los segmentos, separados por `/`):

0. Espacio del sistema o modo de un solo contexto: solo el hostname (`asa#`).
1. `prompt hostname context`: es el prompt por omisión en multicontexto.
2. `prompt hostname priority state`.
3. `prompt hostname context priority state`.
4. `prompt hostname priority state context`.
5. `prompt hostname priority state` con failover apagado: `actNoFailover` y `stbyNoFailover`.
6. `prompt hostname cluster-unit state`, 9.19(1) o posterior (control/data).
7. Igual, antes de 9.19(1) (master/slave).
8. `prompt hostname domain priority state`: el dominio lleva puntos.
9. `prompt hostname context domain priority state`.

El ejemplo de la documentación del comando `prompt` muestra `ciscoasa/cl2/data node`, con un espacio dentro del segmento. No se incluye: aceptar espacios en el prompt haría que más líneas de salida terminadas en `#` pasaran por prompt. Queda en Pendientes hasta cotejarlo (puede ser `data_node` o `data`).

La documentación dice que en multicontexto el prompt extendido solo aparece en el espacio del sistema y en el contexto admin; los demás contextos muestran el prompt por omisión (grupo 1).

## Diferencias entre versiones y observaciones para los parsers

- **master/slave frente a control/data:** el cambio llegó en 9.19(1). En `show cluster info` pasa de `MASTER`/`SLAVE` a `CONTROL_NODE`/`DATA_NODE`; en el prompt, de `master`/`slave` a control/data. La palabra clave `enable as-slave` sigue en la sintaxis.
- **Orden del prompt:** la documentación del comando dice que el orden de los segmentos es el de las palabras clave, pero su ejemplo `prompt hostname context slot state priority` da `ciscoasa/admin/pri/act` (priority antes de state, y sin slot). No se debe asumir un orden fijo.
- **`show failover history`:** la versión con `details` (9.9(2)) añade el bloque `PEER History`; las entradas son «hora» y luego «From/To/Reason», con líneas `This Host:N` / `Other Host:N` bajo `Interface check`.
- **`show failover state`:** en A/A hay una fila por grupo bajo cada host; en A/S el estado va en una sola línea bajo el host.
- **`show version`:** el ejemplo de plataforma Firepower trae «SSP Operating System Version» y «Device Manager Version»; en un ASA clásico o ASAv no aparecen.
- **`show context detail`:** las versiones con IPS añaden `Real IPS Sensors` y `Mapped IPS Sensors`.
- **Cluster:** `cluster group` usa `key`, no `cluster-key`, en las guías 9.17 a 9.22.

## Pendientes

Sin ejemplo publicado que se pudiera consultar, no se inventaron:

- `show resource usage context all` (todos los contextos): la documentación solo trae sistema, resumen y un contexto.
- `show failover group 1`: la documentación solo describe la sintaxis.
- `show cluster history`, `show cluster info conn-distribution`, `show cluster info packet-distribution`, `show cluster cpu`, `show cluster memory`: las páginas de Cisco que se pudieron leer los describen sin salida de ejemplo (la referencia de comandos de la sección show cluster no se pudo leer completa). Hay que revisar esa referencia a mano.
- `cluster-key`: no hay ejemplo publicado con ese comando.
- `show running-config` completo del sistema: solo hay fragmentos; el fixture está armado con ellos.
- `show running-config` dentro de un contexto (con `ASA Version … <context>`).
- `show conn count` y `show xlate count` por contexto.
- Prompt de cluster con espacio (`data node`) del ejemplo del comando `prompt`.
- `show mode` en la referencia de comandos: no se encontró la sección; el formato sale del aviso de seguridad de Cisco.
