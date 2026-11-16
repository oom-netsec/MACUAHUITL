# Fase 42: ASA a fondo

Pedido del dueño (2026-11-14): «para el ASA cubre contextos, todos los modos de redundancia, todo lo que uno puede hacer…
algo que ni TAC ha intentado automatizar». Va después de v0.5.1.

Este documento es el plan para revisión: **no hay código hasta que Release lo apruebe**. Las decisiones abiertas
(sección 3) necesitan respuesta antes de empezar. Revisado por un experto el 2026-11-14: las correcciones están
incorporadas. Todo comando o campo que no está confirmado contra la Command Reference dice «a verificar en la Command
Reference 9.x».

## 1. Lo que ya existe

- **Paquete oom/asa 1.0.x.** Tiene 67 playbooks de solo lectura:
  - `ctx-contextos` y `ctx-recursos`;
  - `ha-failover-estado`, `ha-failover-historial` y `ha-cluster-estado`;
  - `tac-failover-inesperado` y `tac-cluster-miembro`;
  - `l1-descartes-asp`, `tac-trafico-no-pasa` (packet-tracer con datos `interface`/`src`/`dst`), VPN y el resto.

  Todos están **sin validar** en laboratorio, salvo lo que el CML valide esta noche.
  `ctx-contextos` y `ctx-recursos` mezclan comandos que solo corren en el espacio del sistema (ver 4.1).
- **Driver** (`internal/platform/iosxe`). Detecta ASA, maneja `terminal pager 0`, el «--More--» del ASA y el `>` sin
  enable. `anyPrompt` ya acepta `/` en el nombre (`host/ctx#`, `host/pri/act#`), pero **no hay pruebas** de esas
  combinaciones. El primer login del ASA 9.x aborta con ErrFirstLogin (PR en curso).
- **CheckDenied del ASA** (`internal/playbook/deny_asa.go`):
  - permite `packet-tracer input IF {tcp|udp} SRC SPORT DST DPORT [detailed|xml]` y la variante icmp;
  - **rechaza** `changeto`, `failover active`, `failover reload-standby` y `cluster exec`; hay prueba que lo exige.
  - Es una función pura del texto del comando. Eso no cambia en esta fase.
- **Parsers:** solo existe `internal/parse/iosxe`. **No hay** `internal/parse/asa`: el ASA no tiene parsers.
- **Análisis:**
  - `internal/analyze` aplica reglas YAML con `check` (mem_low, mem_leak…) a la evidencia de Patrol, por ronda y entre rondas;
  - `internal/metrics` arma series y deltas de contadores (`counterDelta`);
  - los dos leen con `internal/parse/iosxe`.
- **Tipos de dato de los playbooks:** `mac`, `ap`, `wlan`, `interface`, `ip`, `vrf` y `vnid`. Cada uno es **un valor**
  por trabajo: no hay listas.
- **Enmascarado:** cubre `failover key` e `ipsec pre-shared-key`. Tiene un hueco real, hallado hoy: la línea citada
  `*** Output from config line N, "…"` de `show tech-support` (ver sección 5; se arregla en v0.5.1, antes de esta fase).

## 2. Alcance

| Bloque | Qué | Dónde |
|---|---|---|
| 42a | Prompts multicontexto y de failover en el driver (parser por segmentos, 4.2) y **`changeto` del ejecutor de Patrol** (D1), con su ADR. Pruebas de todas las combinaciones, incluido `host/ctx(config)#` (tiene que dar ErrConfigPrompt). | internal/platform/iosxe, internal/patrol |
| 42b | Playbooks nuevos: espacio del sistema, por contexto, failover A/S, failover A/A (grupos), cluster. oom/asa 1.1.0, y mover los comandos de sistema de `ctx-*` a `sys-*`. | packs/asa |
| 42c | **Dominio nuevo `internal/parse/asa`** con los parsers de show (lista en 4.3). Va en la lista *Shared* de archcheck, igual que `internal/parse`. | internal/parse/asa, tools/archcheck |
| 42d | Comparación entre las dos unidades de un par (4.4). | dominio nuevo (decisión D3) |
| 42e | Deltas entre rondas con umbrales: asp drop, conn count, xlate count, resource usage por contexto, interfaces y failover (4.5). | internal/analyze (checks nuevos) |
| 42f | Matriz de packet-tracer: varios flujos, tabla por fase (4.6). | playbook + parse/asa + analyze (decisión D2) |
| 42g | proto, mctl, puente y contrato front de lo nuevo (42d y 42f). | api/proto, cmd/mctl, ui/bridge |
| 42h | Fixtures de la documentación de Cisco para multicontexto, A/A y cluster, marcadas «sin validar en laboratorio». | testdata de cada paquete |

Fuera de alcance:
- escribir en el ASA, incluido cualquier comando de failover;
- `cluster exec` y `failover exec` como comando de playbook (a futuro, como operación del ejecutor: ver D4);
- el modo transparente como función aparte (los mismos playbooks sirven, con las notas del caso);
- FTD, que tiene su propio paquete.

## 3. Decisiones (aprobadas por el dueño el 2026-11-16)

Resumen de lo aprobado:
- **D1:** el `changeto` lo hace el ejecutor, con verificación del prompt, lista blanca contra `show context` de la
  misma ronda, auditoría `patrol.changeto` y vuelta con `defer`. Lleva su ADR.
- **D2:** opción A, el tipo `flows`, con un tope de **256 flujos por trabajo** («no sabemos en qué ambientes lo van a
  probar»), carga desde CSV y un **aviso de impacto antes de armar**: cuántos `packet-tracer`, el tiempo estimado, y
  que suben los hitcnt y pueden iniciar IKE.
- **D3:** opción A, una herramienta aparte con su propia tabla de diferencias.
- **D4:** el par se detecta por **(serie, contexto)**.
- **No hay ASA físico.** Multicontexto, A/A y cluster salen con fixtures reconstruidas y la marca «not yet tested in
  a lab». Contexto único y failover A/S se validan en el ASAv de CML. El anuncio de la v1.0.0 lleva una convocatoria
  abierta a quien tenga un ASA físico.

Lo que sigue es el razonamiento de cada decisión.

### D1. Multicontexto: ¿cómo se llega al sistema y a cada contexto?

**Dato clave:** en `mode multiple` el espacio del sistema **no tiene IP de gestión**. Se llega por consola, o por SSH
al contexto admin y luego `changeto system`. Por eso la antigua opción A (una sesión al sistema por su IP) **no
sirve**: no se podrían correr los `sys-*`.

**Propuesta para esta fase: `changeto` hecho por el ejecutor de Patrol, no por el texto del playbook.**
- El destino del trabajo lleva **equipo + contexto**: `"system"` o el nombre de un contexto. La sesión SSH entra por
  el contexto admin (o por el que tenga IP).
- Antes de correr los playbooks del destino, Patrol manda `changeto system` o `changeto context X` y **verifica el
  prompt nuevo** (hostname y contexto esperados). Solo si coincide corre los playbooks. Si no coincide, el destino
  falla y no se guarda evidencia.
- Guarda el contexto en cada salida de la evidencia.
- `CheckDenied` **sigue siendo una función pura** y sigue negando `changeto` en los playbooks: el `changeto` no sale
  de ningún texto de playbook, solo del ejecutor.
- `changeto` dura lo que la sesión y **no cambia nada en el equipo**. El riesgo real es guardar evidencia del contexto
  equivocado; por eso se verifica el prompt.
- Controles:
  - lista blanca de nombres de contexto declarada en el trabajo (dato nuevo de tipo `context`, validado igual que
    `interface`), verificada contra `show context` de **la misma ronda**: un nombre que no esté ahí no se manda;
  - auditoría de cada `changeto` (`patrol.changeto`, con contexto y ronda);
  - vuelta a `changeto system` (o al contexto de entrada) al final del bloque, aunque haya error, con `defer` en el
    ejecutor.
- Hace falta un **ADR** (entra con 42a) y revisión de seguridad propia.

**Alternativa:** consola por servidor de terminal (la consola del sistema es la que tiene el prompt del sistema).
Requiere un ADR corto y que el dueño tenga ese servidor. Queda como opción si el `changeto` del ejecutor no se aprueba.

**Descartada:** una corrida por IP de gestión de cada contexto como único camino. Sirve para los `ctx-*`, pero deja
sin cubrir el espacio del sistema.

### D2. ¿Cómo se declaran varios flujos para la matriz de packet-tracer?

Hoy cada dato es un solo valor.

- **Opción A: un tipo de dato nuevo `flows`.** Lista de flujos, hasta **256** por trabajo, separados por `;` o
  cargados desde un **CSV** (una fila por flujo, mismas columnas). Cada flujo es
  `IF PROTO SRC SPORT DST DPORT` para tcp/udp, y **admite la forma icmp** (`IF icmp SRC TYPE CODE DST`; a verificar en
  la Command Reference 9.x). `Expand` genera un `packet-tracer` por flujo, y cada uno pasa CheckDenied como hoy.
  Un playbook `tac-matriz-packet-tracer`; el análisis arma la tabla flujo × fase (ACCESS-LIST, NAT, ROUTE-LOOKUP, VPN,
  INPUT, OUTPUT…) con el resultado y el motivo del drop.
- **Opción B: un trabajo por flujo** (ya funciona hoy) y una vista que junta los trabajos. Sin tipo nuevo, pero la matriz
  queda fuera de una sola evidencia.

**Aprobada:** A, con un tope de 256. Ojo: packet-tracer sube los hitcnt de las ACL y puede iniciar IKE si el flujo es
de un crypto map. Antes de armar el trabajo, la app muestra un **aviso de impacto**: cuántos `packet-tracer` va a correr,
el tiempo estimado, y que suben los hitcnt y pueden iniciar IKE. El playbook lleva la misma nota.

**Lista blanca de opciones: se mantiene en `detailed|xml`.** Las versiones nuevas traen `transmit` (manda el paquete de
verdad) y `persist`; no se permiten. La matriz usa solo `xml` para el parser.

### D3. ¿Dónde vive la comparación entre las dos unidades?

ADR 0008: un dominio no importa otro; los parsers son *Shared*.

- **Opción A, dominio nuevo.** Entra la evidencia de un trabajo con dos destinos marcados como par. Sale un informe de
  diferencias. Tiene su servicio, proto, mctl `ha compare JOB` y puente.
- **Opción B, regla de `internal/analyze`** con un check nuevo que mira dos equipos. Hoy `analyze` trabaja por equipo:
  habría que extender el motor.

**Aprobada:** A. Es una herramienta con salida propia (tabla de diferencias), no una alerta. Nombre: si cubre cluster,
`hapair` le queda chico, así que va como **`internal/fwha`** (alta disponibilidad de firewalls: par y cluster).

### D4. ¿Cómo se marca un par en el trabajo?

- Por detección: `show failover` trae `Serial Number: Ours X, Mate Y` y `Version: Ours …, Mate …` (campos a verificar en
  la Command Reference 9.x). **Con una sola sesión ya se ven la serie y la versión de la otra unidad.**
- O un dato explícito del trabajo.

**Aprobada:** detección, agrupando por **(serie, contexto)** y no por IP: en un failover la IP activa pasa a la otra
unidad, así que la IP no identifica a la unidad.

- El aviso de «más de dos ASA en failover» **se rediseña**: con un destino por contexto, la misma pareja aparece varias
  veces y el aviso saltaría en falso. El aviso cuenta series distintas dentro del trabajo, no destinos.
- Límite conocido: muchas redes no configuran IP de standby, así que el standby no se alcanza por SSH y el par queda
  cojo (solo se ve la activa, con los datos de la pareja que da `show failover`).
- A futuro, fuera de esta fase: `failover exec mate show …` como **operación del ejecutor**, con el comando de adentro
  pasado por CheckDenied. Mismo patrón que el `changeto` de D1. Hoy `failover exec` sigue denegado.

## 4. Detalle

### 4.1 Playbooks nuevos (oom/asa 1.1.0)

**Mover comandos de sistema fuera de `ctx-*` (paquete 1.0.x).** `ctx-contextos` y `ctx-recursos` incluyen comandos que
solo corren en el espacio del sistema: `show admin-context`, `show running-config context`, `show running-config class`,
`show resource allocation`, `show resource types` y `show resource usage context all`. Pasan a `sys-*`. En `ctx-*`
quedan `show context`, `show mode` y `show resource usage` (a verificar en la Command Reference 9.x si este último corre
dentro de un contexto).

**Espacio del sistema (`sys-*`).** Solo corren con el prompt del sistema (D1); en un contexto, los comandos de sistema
dan Invalid y labcheck lo marca.

| ID | Comandos clave |
|---|---|
| sys-contextos | show mode, show context, show context detail, show admin-context, show running-config context |
| sys-recursos | show resource allocation, show resource allocation detail, show resource usage all, show resource usage context all, show resource usage summary, show resource types, show running-config class |
| sys-failover-grupos | show failover, show failover state, show failover group 1, show failover group 2, show failover history |
| sys-interfaces | show interface, show context detail y show running-config context (la asignación de interfaces por contexto se ve ahí, no en `show interface ip brief`) |

**Failover A/S (`ha-*`, se suman a los actuales).**
- `ha-failover-detalle`: show failover, show failover state, show failover interface, show failover history details,
  show failover statistics, show monitor-interface, show failover descriptor, **show checksum** (sincronización
  inmediata: más barato que comparar configuraciones). A verificar en la Command Reference 9.x: `history detail` o
  `details`, y `show failover descriptor`.
- La sincronización se ve con `show checksum`, `show failover` y `show running-config failover`.
- `failover exec` y `cluster exec` los rechaza la lista blanca: **prueba explícita** de ambos. `show failover exec` no
  hace falta.

**Failover A/A.** `ha-activo-activo`: show failover group N, show failover state y `show failover` por grupo.
Requiere multicontexto.

**Cluster (`cl-*`).** Los comandos `show cluster …` se corren desde la unidad de control: agregan a todos los miembros,
son de solo lectura y evitan `cluster exec`.

| ID | Comandos clave |
|---|---|
| cl-estado | show cluster info, show cluster info health, show cluster info trace (pesado, ver abajo) |
| cl-ccl | show cluster info conn-distribution, show cluster info packet-distribution, show interface (CCL), show port-channel summary, show lacp cluster system-id |
| cl-miembros | show cluster history, show cluster info flow-mobility counters |
| cl-agregado | show cluster conn count, show cluster xlate count, show cluster cpu, show cluster memory, show cluster traffic, show cluster interface-mode, show cluster resource usage |
| cl-version (por versión) | show cluster info unit-join-acceleration (9.20+), show cluster info health details, show cluster info load-monitor (versiones recientes) |

Los de `cl-version` se marcan por versión: en una anterior dan Invalid y no es falla del equipo. La versión exacta de
cada uno y la sintaxis de la familia `show cluster {…}` quedan a verificar en la Command Reference 9.x.

**Matriz (D2-A):** `tac-matriz-packet-tracer` con el dato `flows`.

**Comandos pesados en producción:** `show conn detail`, `show xlate`, `show local-host`, `show asp table`,
`show cluster info trace` y `show tech-support` (en el sistema recorre todos los contextos). Preferir `count` y filtros
(`| include`, `| grep`), con timeouts largos; los playbooks que los usen lo avisan.

Todos los comandos salen de la Command Reference del ASA 9.x. Los que no existan en una versión se marcan como en los
otros paquetes.

### 4.2 Driver (42a)

El orden y los segmentos del prompt **no dependen de la versión**: los fija el administrador con
`prompt hostname context domain slot state priority cluster-unit [cluster-state]`. Por omisión, en multicontexto es
`hostname/context`. Hoy el driver falla en cuatro puntos:

- **`atPrompt`** compara con `hostname+"#"` exacto. Si el prompt lleva el rol (`host/pri/act#` pasa a
  `host/pri/stby#` en un failover), cada Run espera hasta el timeout. Se guarda solo la parte **estable** (hostname y
  contexto) y se acepta cualquier sufijo de rol. Prueba con **cambio de rol a mitad de corrida**. Ojo: en un failover
  la IP activa pasa a la otra unidad y la sesión SSH se corta; eso es un error de sesión, no de prompt.
- **`atConfigPrompt`** recorta a 16 caracteres como IOS. El ASA no recorta, así que `asa/admin/pri/act(config)#` no se
  reconoce y termina en timeout en vez de ErrConfigPrompt. **No recortar en el ASA.**
- **`anyPrompt`** corta en 63 caracteres: un hostname de 63 + contexto de 32 + `/pri/act` lo pasa y daría
  ErrFirstLogin falso. Se sube el tope para el ASA.
- **Orden de segmentos:** parser genérico por segmentos separados por `/`:
  - el primero es el hostname;
  - prioridad: `pri` o `sec`;
  - estado: `act`, `stby`, `actNoFailover` o `stbyNoFailover`;
  - cluster: `control` o `data` (`master`/`slave` en versiones viejas);
  - lo demás es contexto, unidad o dominio (el dominio lleva puntos).
  - No se asume `unit-1-1` (es de FXOS). **Límite a documentar:** un contexto llamado `act` o `pri` es ambiguo.

Pruebas: `host/ctx#`, `host/ctx>`, `host/pri/act#`, `host/sec/stby#`, `host/ctx/pri/act#`, `host/pri/stby/ctx#` y
variantes de cluster, todos con sus `(config)#` (ErrConfigPrompt). El hostname y el contexto estables se guardan; el
rol se expone como dato aparte del equipo, para el informe y para D4.

**Verificación del `changeto` (D1):** después de mandar `changeto`, el driver compara el prompt nuevo con el hostname y
contexto esperados, con el mismo parser por segmentos.

### 4.3 Parsers (`internal/parse/asa`, 42c)

`show failover` (estado, unidades, `Serial Number: Ours/Mate`, `Version: Ours/Mate`, interfaces monitoreadas, motivo e
historial; contadores de *Stateful Failover Logical Update Statistics*), `show failover state`, `show failover history`,
`show checksum`, `show context`, `show mode`, `show resource usage`, `show asp drop`, `show conn count`,
`show xlate count`, `show cluster info`, `show cluster info health`, `show version` (versión, serie, licencia y modo),
`show running-config` normalizada (sin líneas volátiles: cryptochecksum, «: Saved», fecha) y `packet-tracer`
(fases y resultado; también la salida `xml`, que es estable y es la única que usa la matriz).

Cada parser lleva fixture de la documentación de Cisco, marcada «sin validar en laboratorio», y su fuzz como los de
iosxe.

**Cotejo del `show failover` real (Release, 2026-11-16).** Se comparó un par A/S de ASAv 9.22(1)1 en CML, con un
failover forzado, contra la fixture reconstruida `aa_show-failover.txt`. La evidencia queda local y no se sube.
- Las líneas de cabecera coinciden (Reconnect timeout, Unit Poll, Interface Policy, Monitored Interfaces, MAC Address
  Move…, Version Ours/Mate, Serial Number Ours/Mate).
- El equipo real **sangra con tabulaciones**, no con espacios. La línea de la unidad es `This host: Primary - Active`
  con un espacio al final.
- La tabla de estadísticas trae, justo después del título, una línea `Link : <nombre> <interfaz> (up)`. En 9.22 trae
  además muchas filas que la fixture no tiene: sys cmd, IPv6 ND tbl, VPN IKEv1/IKEv2 SA/P2, SIP, Router ID,
  User-Identity, CTS SGTNAME/PAC, TrustSec-SXP, IPv6 Route, STS Table y Umbrella Device-ID.
- En «Logical Update Queue Information», las columnas Cur/Max/Total van separadas por tabulaciones.
- **Para el parser:** tolerar tabulaciones y espacios por igual, aceptar filas desconocidas en la tabla de estadísticas
  y aceptar la línea `Link :`. La fixture reconstruida se ajusta con estos rasgos, **sin copiar la salida real**.

### 4.4 Comparación del par (42d)

Entrada: un trabajo con las dos unidades (o una sola, si el standby no tiene IP: D4). Salida: un informe con estas
secciones:
- **Sincronización:** `show checksum` en las dos unidades. Es la comprobación principal. El diff de la running-config
  normalizada casi siempre sale vacío (la configuración se replica), así que queda como detalle opcional, salvo las
  líneas propias de cada unidad (`failover lan unit`, prioridades).
- **Estado:** quién es activa, si el standby está «Standby Ready», y si los grupos A/A están repartidos como dice
  `preempt`. **Split-brain** (las dos unidades activas): alerta crítica.
- **Interfaces monitoreadas:** las que están en *Failed*, *Waiting* o *Not-Monitored* en una sola unidad.
- **Versión, licencia y hardware:** versión, licencia, modelo, módulos y cantidad de interfaces distintos entre las dos
  unidades. Eso bloquea el failover o lo deja en *Mismatch*.
- **Enlace de failover y estado:** contadores xerr/rerr de *Stateful Failover Logical Update Statistics*; errores,
  overruns y no buffer del enlace de failover.
- **Parámetros de failover:** `polltime`, `interface-policy`; `mac-address auto` en A/A y en multicontexto (sin él, un
  failover puede cambiar las MAC).
- **Último failover:** el motivo y el historial de los dos lados, alineados por hora. Se mide antes la **diferencia de
  reloj** entre las unidades para alinear bien.
- **Cluster:** en lugar del par, cada miembro contra el control (rol, health, versión y la config de cluster).

### 4.5 Deltas entre rondas (42e)

Checks nuevos de `internal/analyze` para ASA, con umbrales en las reglas YAML como los de IOS-XE:
- `asp_drop_delta`: un motivo cuyo contador sube más de N por minuto entre rondas (lista de motivos «ruidosos» aparte).
  - Maneja `clear asp drop`: lee la línea «Last clearing» y descarta los deltas negativos.
  - Los contadores son **globales del equipo**: se deduplican por serie (varios contextos del mismo equipo no suman
    varias veces).
  - Una **tabla de motivos** con explicación y acción, al estilo de msgkb: `acl-drop`, `rpf-violated`,
    `nat-rpf-failed`, `tcp-not-syn`, `sp-security-failed`, `cluster-*`… (lista final a verificar en la Command
    Reference 9.x y en la guía de asp drop).
- `conn_growth` y `xlate_growth`: crecimiento sostenido de `show conn count` y `show xlate count` (patrón de fuga o de
  ataque).
- `resource_ctx`: por contexto, avisa ante todo cuando sube la columna **Denied** de `show resource usage`; el
  porcentaje contra el límite de la clase es secundario. Contempla los límites `unlimited` (no hay porcentaje) y separa
  los recursos de **tasa** (conns/s, xlates/s, etc.) de los de cantidad.
- `iface_delta`: deltas de overrun y no buffer por interfaz.
- `policy_drop_delta`: drops de `show service-policy`.
- `failover_xerr_delta`: xerr de los contadores de failover (mismo cuidado de deduplicar por serie).

Todo marcado «sin validar» hasta tener rondas reales.

## 5. Seguridad

- Nada escribe en el ASA. Siguen denegados `changeto` en los playbooks (el del ejecutor de D1 es otra ruta, con su ADR),
  `failover active|reload-standby|reset`, `failover exec` y `cluster exec` (los dos con **prueba explícita**),
  `cluster group` y `configure`.
- `show running-config context` y `class` llevan `may_contain_secrets`. El enmascarado del ASA ya cubre las claves de
  `failover key` e `ipsec pre-shared-key`. Hay que **revisar** que cubra la `failover key` en sus dos formas (con y sin
  `hex`) y la `cluster-key` antes de publicar.
- **Con `changeto system`, el `config-url` de cada contexto** puede traer `ftp://usuario:clave@…` en claro (y otros
  esquemas con credencial): el enmascarado tiene que cubrirlo, con prueba.
- **Línea citada de show tech:** `*** Output from config line N, "…"` repite líneas de la configuración y se halló hoy
  como hueco real del enmascarado. Se arregla en v0.5.1, antes de esta fase; aquí se confirma con prueba en los
  fixtures de `show tech-support`.
- La verificación del prompt tras `changeto` evita guardar evidencia de un contexto equivocado (D1).
- La matriz de packet-tracer simula tráfico: aviso en el plan y en el README (hitcnt e IKE). Sin `transmit` ni
  `persist` (D2).
- Por cada parser, fuzz y revisión del manejo de salidas enormes (`show running-config` o `show tech-support` de un
  sistema con muchos contextos).

## 6. Validación

- **CML (Release):** dos ASAv en failover A/S, incluido un failover provocado por Release (la app solo observa). Ya hay
  una primera corrida (68 playbooks en 2 rondas, con failover forzado entre ellas), y su evidencia está en local.
  Release valida contexto único y A/S en el ASAv con la primera build de cada bloque. Es lo realista. Con eso se validan 42a (prompts de failover y cambio de rol), 42b (A/S), 42c (failover,
  version, conn, xlate, asp) y 42d (par A/S).
- **Multicontexto y A/A:** el ASAv no admitiría `mode multiple` (a verificar en las notas de la versión de la imagen
  del CML). A/A necesita multicontexto, así que queda con **fixtures** de la documentación y la marca «sin validar»,
  como pidió el dueño. El `changeto` del ejecutor (D1) se prueba con un simulador.
- **Cluster:** en el ASAv solo desde 9.17+ en KVM/VMware, en modo de interfaces individuales, con el enlace de control
  a MTU de 1600 o más (los enlaces del CML vienen en 1500). Es posible pero frágil. Los miembros que no son la unidad
  de control necesitan su IP local de gestión. Si no se logra, queda con fixtures.
- labcheck sobre cada corrida, con el mismo procedimiento de `docs/plans/validacion-labs.md`.

## 7. Orden propuesto

1. **42a** (driver con parser de prompt por segmentos, pruebas y `changeto` del ejecutor con su ADR; D1) y **42c**
   (parsers con fixtures). Son la base.
2. 42b (playbooks, incluido el movimiento a `sys-*`), validados en CML A/S.
3. 42d (par) y 42e (deltas).
4. 42f (matriz con `flows`, D2-A) y 42g (proto, mctl, puente y contrato).
5. Laboratorio otra vez, ajustes y release.

Cada bloque es un PR con su revisión independiente, CI verde y, cuando toque, validación en CML.

**Ventana antes de la v1.0.0 (pedido de Release, 2026-11-16):** el código de la fase 42 se implementa en ramas
(42a…), cada una con su revisión y su verificación, pero **no se mergea a main hasta que salga la v1.0.0**. Durante la
ventana de 2 a 3 días sin hallazgos solo entran a main los arreglos de hallazgos.
