# Fase 42: ASA a fondo

Pedido del dueño (2026-11-14): «para el ASA cubre contextos, todos los modos de redundancia, todo lo que uno puede hacer…
algo que ni TAC ha intentado automatizar». Va después de v0.5.1.

Este documento es el plan para revisión: **no hay código hasta que Release lo apruebe**. Las decisiones abiertas
(sección 3) necesitan respuesta antes de empezar.

## 1. Lo que ya existe

- **Paquete oom/asa 1.0.x.** Tiene 67 playbooks de solo lectura:
  - `ctx-contextos` y `ctx-recursos`;
  - `ha-failover-estado`, `ha-failover-historial` y `ha-cluster-estado`;
  - `tac-failover-inesperado` y `tac-cluster-miembro`;
  - `l1-descartes-asp`, `tac-trafico-no-pasa` (packet-tracer con datos `interface`/`src`/`dst`), VPN y el resto.

  Todos están **sin validar** en laboratorio, salvo lo que el CML valide esta noche.
- **Driver** (`internal/platform/iosxe`). Detecta ASA, maneja `terminal pager 0`, el «--More--» del ASA y el `>` sin
  enable. `anyPrompt` ya acepta `/` en el nombre (`host/ctx#`, `host/pri/act#`), pero **no hay pruebas** de esas
  combinaciones. El primer login del ASA 9.x aborta con ErrFirstLogin (PR en curso).
- **CheckDenied del ASA** (`internal/playbook/deny_asa.go`):
  - permite `packet-tracer input IF {tcp|udp} SRC SPORT DST DPORT [detailed|xml]` y la variante icmp;
  - **rechaza** `changeto`, `failover active`, `failover reload-standby` y `cluster exec`; hay prueba que lo exige.
- **Parsers:** solo existe `internal/parse/iosxe`. **No hay** `internal/parse/asa`: el ASA no tiene parsers.
- **Análisis:**
  - `internal/analyze` aplica reglas YAML con `check` (mem_low, mem_leak…) a la evidencia de Patrol, por ronda y entre rondas;
  - `internal/metrics` arma series y deltas de contadores (`counterDelta`);
  - los dos leen con `internal/parse/iosxe`.
- **Tipos de dato de los playbooks:** `mac`, `ap`, `wlan`, `interface`, `ip`, `vrf` y `vnid`. Cada uno es **un valor**
  por trabajo: no hay listas.

## 2. Alcance

| Bloque | Qué | Dónde |
|---|---|---|
| 42a | Prompts multicontexto y de failover en el driver: `host/ctx#`, `host/pri/act#`, `host/sec/stby#`, `host/ctx/pri/act#`, `host>` (sin enable), cluster `host/unit#`. Pruebas de todas las combinaciones, incluido `host/ctx(config)#` (tiene que dar ErrConfigPrompt). | internal/platform/iosxe |
| 42b | Playbooks nuevos: espacio del sistema, por contexto, failover A/S, failover A/A (grupos), cluster. oom/asa 1.1.0. | packs/asa |
| 42c | **Dominio nuevo `internal/parse/asa`** con los parsers de show (lista en 4.3). Va en la lista *Shared* de archcheck, igual que `internal/parse`. | internal/parse/asa, tools/archcheck |
| 42d | Comparación entre las dos unidades de un par (4.4). | dominio nuevo (decisión D3) |
| 42e | Deltas entre rondas con umbrales: asp drop, conn count, xlate count y resource usage por contexto (4.5). | internal/analyze (checks nuevos) |
| 42f | Matriz de packet-tracer: varios flujos, tabla por fase (4.6). | playbook + parse/asa + analyze (decisión D2) |
| 42g | proto, mctl, puente y contrato front de lo nuevo (42d y 42f). | api/proto, cmd/mctl, ui/bridge |
| 42h | Fixtures de la documentación de Cisco para multicontexto, A/A y cluster, marcadas «sin validar en laboratorio». | testdata de cada paquete |

Fuera de alcance:
- escribir en el ASA, incluido cualquier comando de failover;
- `cluster exec`;
- el modo transparente como función aparte (los mismos playbooks sirven, con las notas del caso);
- FTD, que tiene su propio paquete.

## 3. Decisiones abiertas (Release y el dueño)

### D1. Multicontexto: ¿cómo se llega a cada contexto?

**Opción A, sin `changeto` (recomendada para empezar).**
- Una corrida del **espacio del sistema** (la sesión a la IP de gestión del sistema) con los playbooks `sys-*`:
  - `show context`, `show context detail`, `show mode`, `show admin-context`, `show resource allocation`,
    `show resource usage all`, `show failover group N`, `show running-config context` y `show running-config class`.
- Una corrida **por contexto**, entrando por la IP de gestión de ese contexto, con los playbooks `ctx-*` y el resto del
  paquete. El trabajo de Patrol ya admite varios destinos, uno por contexto.
- Lo bueno: CheckDenied no cambia y cada sesión ve solo su contexto.
- Lo malo: necesita IP de gestión y credencial en cada contexto (lo normal en producción, no siempre en laboratorio).

**Opción B, `changeto` controlado.** Se abre `changeto context NOMBRE` y `changeto system` solo:
- dentro de una sesión de Patrol que empezó en el espacio del sistema (el driver lo sabe por el prompt sin `/ctx`);
- con una **lista blanca de nombres de contexto** declarada en el trabajo (dato nuevo de tipo `context`, validado igual
  que `interface`) y verificada contra `show context` de la misma ronda: un nombre que no esté ahí no se manda;
- con auditoría de cada `changeto` (`patrol.changeto`, contexto y ronda);
- volviendo siempre a `changeto system` al final del bloque, aunque haya error, con `defer` en el ejecutor.

  Costo: CheckDenied pasa a depender del contexto de la sesión. Hoy es una función pura del texto. Es un cambio de
  diseño con revisión de seguridad propia, y un ADR. Sin B, el «por contexto» depende de la IP de gestión.

**Propuesta:** A en la fase 42. B como fase aparte, si después del laboratorio hace falta.

### D2. ¿Cómo se declaran varios flujos para la matriz de packet-tracer?

Hoy cada dato es un solo valor.

- **Opción A: un tipo de dato nuevo `flows`.** Lista de `IF PROTO SRC SPORT DST DPORT`, hasta 20, separados por `;`.
  `Expand` genera un `packet-tracer` por flujo, y cada uno pasa CheckDenied como hoy. Un playbook
  `tac-matriz-packet-tracer`; el análisis arma la tabla flujo × fase (ACCESS-LIST, NAT, ROUTE-LOOKUP, VPN, INPUT,
  OUTPUT…) con el resultado y el motivo del drop.
- **Opción B: un trabajo por flujo** (ya funciona hoy) y una vista que junta los trabajos. Sin tipo nuevo, pero la matriz
  queda fuera de una sola evidencia.

**Propuesta:** A. Ojo: packet-tracer sube los hitcnt de las ACL y puede iniciar IKE si el flujo es de un crypto map. La
nota va en el playbook y el plan muestra cuántos flujos va a simular.

### D3. ¿Dónde vive la comparación entre las dos unidades?

ADR 0008: un dominio no importa otro; los parsers son *Shared*.

- **Opción A, dominio nuevo `internal/hapair`.** Entra la evidencia de un trabajo con dos destinos marcados como par.
  Sale un informe de diferencias. Tiene su servicio, proto, mctl `ha compare JOB` y puente.
- **Opción B, regla de `internal/analyze`** con un check nuevo que mira dos equipos. Hoy `analyze` trabaja por equipo:
  habría que extender el motor.

**Propuesta:** A. Es una herramienta con salida propia (tabla de diferencias), no una alerta.

### D4. ¿Cómo se marca un par en el trabajo?

- Por detección: los dos equipos del trabajo responden `show failover` con el mismo par de números de serie (*this host*
  y *other host*).
- O un dato explícito del trabajo.

**Propuesta:** detección, con aviso si el trabajo tiene más de dos ASA en failover.

## 4. Detalle

### 4.1 Playbooks nuevos (oom/asa 1.1.0)

**Espacio del sistema (`sys-*`).** Solo corren si el prompt es del sistema; en un contexto, los comandos de sistema dan
Invalid y labcheck lo marca.

| ID | Comandos clave |
|---|---|
| sys-contextos | show mode, show context, show context detail, show admin-context, show running-config context |
| sys-recursos | show resource allocation, show resource allocation detail, show resource usage all, show resource usage summary, show resource types |
| sys-failover-grupos | show failover, show failover state, show failover group 1, show failover group 2, show failover history |
| sys-interfaces | show interface, show interface ip brief (asignación por contexto) |

**Failover A/S (`ha-*`, se suman a los actuales).**
- `ha-failover-detalle`: show failover, show failover state, show failover interface, show failover history detail,
  show failover statistics, show monitor-interface, show failover descriptor.
- `ha-sincronizacion`: show failover exec mate…?

  **No.** `failover exec` corre comandos en la otra unidad: va **denegado** como `cluster exec`. La sincronización se
  ve con show failover y con `show running-config failover`.

**Failover A/A.** `ha-activo-activo`: show failover group N, show failover state y `show failover` por grupo.

**Cluster (`cl-*`).**

| ID | Comandos clave |
|---|---|
| cl-estado | show cluster info, show cluster info health, show cluster info health details, show cluster info trace |
| cl-ccl | show cluster info conn-distribution, show cluster info packet-distribution, show interface (CCL), show port-channel summary |
| cl-miembros | show cluster info unit-join-acceleration, show cluster history, show cluster info flow-mobility counters |
| cl-trafico | show cluster info load-monitor, show conn count, show xlate count |

**Matriz (D2-A):** `tac-matriz-packet-tracer` con el dato `flows`.

Todos los comandos salen de la Command Reference del ASA 9.x. Los que no existan en una versión se marcan como en los
otros paquetes.

### 4.2 Driver (42a)

- Pruebas de prompt y detección de `host/ctx#`, `host/ctx>`, `host/pri/act#`, `host/sec/stby#`, `host/ctx/pri/act#`,
  `host/pri/stby/ctx#` (el orden cambia según la versión) y del cluster (`host/unit-1-1#`).
- `host/ctx(config)#` y `host/pri/act(config)#` dan ErrConfigPrompt.
- El hostname que se guarda queda completo; la parte de contexto y rol se expone como dato aparte del equipo, para el
  informe y para D4.

### 4.3 Parsers (`internal/parse/asa`, 42c)

`show failover` (estado, unidades, interfaces monitoreadas, motivo e historial), `show failover state`,
`show failover history`, `show context`, `show mode`, `show resource usage`, `show asp drop`, `show conn count`,
`show xlate count`, `show cluster info`, `show cluster info health`, `show version` (versión, serie, licencia y modo),
`show running-config` normalizada (sin líneas volátiles: cryptochecksum, «: Saved», fecha) y `packet-tracer`
(fases y resultado; también la salida `xml`, que es estable).

Cada parser lleva fixture de la documentación de Cisco, marcada «sin validar en laboratorio», y su fuzz como los de
iosxe.

### 4.4 Comparación del par (42d)

Entrada: un trabajo con las dos unidades. Salida: un informe con estas secciones:
- **Configuración:** diff de la running-config normalizada. En failover, la del standby debería ser idéntica salvo las
  líneas propias de cada unidad (`failover lan unit`, prioridades).
- **Estado:** quién es activa, si el standby está «Standby Ready», y si los grupos A/A están repartidos como dice
  `preempt`.
- **Interfaces monitoreadas:** las que están en *Failed*, *Waiting* o *Not-Monitored* en una sola unidad.
- **Versión y licencia:** distintas en las dos unidades. Eso bloquea el failover o lo deja en *Mismatch*.
- **Último failover:** el motivo y el historial de los dos lados, alineados por hora.
- **Cluster:** en lugar del par, cada miembro contra el control (rol, health, versión y la config de cluster).

### 4.5 Deltas entre rondas (42e)

Checks nuevos de `internal/analyze` para ASA, con umbrales en las reglas YAML como los de IOS-XE:
- `asp_drop_delta`: un motivo cuyo contador sube más de N por minuto entre rondas (lista de motivos «ruidosos» aparte).
- `conn_growth` y `xlate_growth`: crecimiento sostenido de `show conn count` y `show xlate count` (patrón de fuga o de
  ataque).
- `resource_ctx`: por contexto, el uso de conns, xlates, hosts y rate contra el límite de su clase, en `show resource
  usage`; avisa por encima del X %.

Todo marcado «sin validar» hasta tener rondas reales.

## 5. Seguridad

- Nada escribe en el ASA. Siguen denegados `changeto` (salvo D1-B con su ADR), `failover active|reload-standby|reset`,
  `failover exec` (se agrega a la prueba), `cluster exec`, `cluster group` y `configure`.
- `show running-config context` y `class` llevan `may_contain_secrets`. El enmascarado del ASA ya cubre las claves de
  `failover key` e `ipsec pre-shared-key`. Hay que **revisar** que cubra la `failover key` en sus dos formas (con y sin
  `hex`) y la `cluster-key` antes de publicar.
- La matriz de packet-tracer simula tráfico: aviso en el plan y en el README (hitcnt e IKE).
- Por cada parser, fuzz y revisión del manejo de salidas enormes (`show running-config` de un sistema con muchos
  contextos).

## 6. Validación

- **CML (Release, esta noche):** dos ASAv en failover A/S, incluido un failover provocado por Release (la app solo
  observa). Además, ver si el ASAv acepta `mode multiple` y clustering. Con eso se validan 42a, 42b (A/S), 42c
  (failover, version, conn, xlate, asp) y 42d (par A/S).
- **A/A y cluster:** solo si el ASAv los acepta en CML. Si no, quedan con fixtures de la documentación y la marca «sin
  validar», como pidió el dueño.
- labcheck sobre cada corrida, con el mismo procedimiento de `docs/plans/validacion-labs.md`.

## 7. Orden propuesto

1. 42a (driver y pruebas de prompts) y 42c (parsers con fixtures). Son la base.
2. 42b (playbooks), validados en CML A/S.
3. 42d (par) y 42e (deltas).
4. 42f (matriz, si se aprueba D2-A) y 42g (proto, mctl, puente y contrato).
5. Laboratorio otra vez, ajustes y release.

Cada bloque es un PR con su revisión independiente, CI verde y, cuando toque, validación en CML.
