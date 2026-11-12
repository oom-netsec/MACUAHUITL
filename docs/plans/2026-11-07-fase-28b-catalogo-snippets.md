# Fase 28b — Catálogo de snippets por tecnología (infraestructura + L2 por puerto)

El dueño pidió, vía la sesión de front, un catálogo lleno de snippets asistidos, divididos por tecnología. La UI debe armar el formulario de cada uno sin código por snippet. Esta rama hace dos cosas:

- **La infraestructura del catálogo:** las plantillas con campos tipados, un RPC de lista y un camino genérico de plan.
- **El primer lote:** L2 por puerto.

Lotes siguientes, en ramas aparte sobre esta infraestructura:

- **28d:** L3 y Gestión (ruta estática, loopback, ip helper-address, servidor NTP, logging host con nivel de trap, community SNMP RO con ACL, usuario SNMPv3, banner motd, ACL de vty con chequeo de no quedar fuera).
- **28e:** QoS trust por puerto y añadir un miembro a un EtherChannel.

El usuario local queda fuera hasta que el dueño decida: la reversa sería `no username`, que la lista negra global prohíbe. AAA queda fuera por pedido.

## Reglas globales
- ADR 0007: nada se aplica sin el modo asistido. Cada plantilla trae su lista cerrada (`Function`), su reversa capturada de la línea base y su `Expect`.
- La verificación de la reversa contra la línea base es la de #47 (`run.go`) y no se toca. Por eso cada plan debe llevar en `Pre`/`Baseline` el `show running-config interface X` (o la sección) que la reversa debe dejar igual.
- Una plantilla rechaza (`ErrSnippetRefused`, con el motivo en español) lo que su reversa no sabría deshacer exactamente.
- Fixtures de la documentación de Cisco, marcadas "sin validar en laboratorio".
- TDD; lógica nueva con al menos una mutación a mano.
- El dominio no importa servicios. Los parsers de `show` nuevos van en `internal/parse/iosxe`.

## 1. Infraestructura (`internal/assist/templates.go`)
- `FieldType`: `text`, `int`, `decimal`, `bool`, `choice`, `ipv4`, `ipv4_mask`, `interface`, `interfaces` (lista y rangos como `ports set`; reutiliza `normIfaces`), `vlan_id`, `secret`.
- `Field{Name, Label (es), Type, Required, Min, Max, Pattern, Choices []string, Default, Help (es)}`.
- `Template{ID, Tech, Name (es), Platforms []string, Fields []Field, Fn Function, Pre func(Values) ([]string, error), Plan func(device string, v Values, outs map[string]string) (DevicePlan, error)}`.
  - `Values` es `map[string]string`.
  - `Tech` va en este orden: `l2`, `l3`, `gestion`, `seguridad`, `qos`, `etherchannel`.
  - Plataformas: `ios`, `ios-xe`.
- `Templates()` devuelve la lista en orden de catálogo y `TemplateByID(id)`.
- `ValidateValues(t, v)` es la validación autoritativa. Rechaza:
  - claves desconocidas, faltantes requeridas y tipos y rangos;
  - lo que no sea ASCII imprimible (reutiliza `asciiOnly`).
  - Los `secret` nunca aparecen en errores; van a `DevicePlan.Secrets` y la `Function` lleva `Scrub`.
- Las plantillas existentes entran al catálogo como adaptadores sin cambiar su lógica:
  - `vlan` (crear, nombrar o borrar), `trunk` (agregar o quitar VLAN), `svi`;
  - `descripcion` (envuelve `PortsPlan` solo con `Description`).

## 2. Lote L2 por puerto (campo `interfaces`; un plan por equipo cubre todas)
Para cada uno: el pre lee `show running-config interface X`, `show interfaces X switchport` y lo que haga falta. La reversa restaura la línea capturada o manda el `no` exacto si no había.

| ID | Apply | Rechaza | Reversa |
|---|---|---|---|
| `speed-duplex` | `speed auto/10/100/1000`, `duplex auto/full/half` (al menos uno) | interfaz inexistente, miembro de canal, ruteada | línea capturada o `no speed`/`no duplex`; aviso de rebote del enlace |
| `storm-control` | `storm-control {broadcast,multicast,unicast} level P` (0.00–100.00, dos decimales) y `storm-control action {shutdown,trap}` opcional | miembro de canal | capturado o `no storm-control <tipo> level` / `no storm-control action <a>` |
| `portfast-bpduguard` | `spanning-tree portfast` y/o `spanning-tree bpduguard enable` | trunk o modo dinámico (solo puertos de acceso) | capturado o `no …`. Respeta la regla de #47 sobre el `portfast edge` que IOS agrega |
| `port-security` | `switchport port-security`, `… maximum N` (1–3072), `… violation {protect,restrict,shutdown}`, `… aging time M` (0–1440) opcional | puerto que no está en `switchport mode access` explícito; puerto que ya tiene port-security (la reversa no restauraría las MAC aprendidas o sticky) | `no switchport port-security` + `no` de cada subcomando agregado, en orden inverso |
| `errdisable-recovery` | global: `errdisable recovery cause C` (lista cerrada: bpduguard, psecure-violation, storm-control, link-flap, udld, loopback) e `errdisable recovery interval S` (30–86400) opcional | — | `no errdisable recovery cause C` si no estaba; el intervalo capturado o `no errdisable recovery interval`. Pre: `show running-config \| include errdisable recovery` |

Cada `Function` es una lista cerrada con `Check` que valida los argumentos exactos (como `Ports.Check`). La `CheckDevice` exige que la reversa sea la inversa del apply.

## 3. Proto, servicio, mctl, puente, contrato
- `assist.proto`:
  - `rpc ListSnippetTemplates(ListSnippetTemplatesRequest{string platform}) returns (ListSnippetTemplatesResponse{repeated SnippetTemplate templates})`;
  - `SnippetTemplate{id, tech, name, repeated string platforms, repeated SnippetField fields}`;
  - `SnippetField{name, label, type, required, min, max, pattern, repeated string choices, default_value, help}`, con `min`/`max` como `double` y 0 = sin límite si `type` no es numérico;
  - `PlanSnippetRequest` agrega `TemplateSnippet template = 7 {string id; map<string,string> values}` al `oneof`, sin renumerar.
- Servicio: el caso nuevo valida con `ValidateValues` y usa `t.Pre`/`t.Plan` igual que los otros tres casos.
- mctl:
  - `mctl snippet list [--platform P] [--json]`;
  - `mctl snippet run ID --set campo=valor … --asistido` (repetible);
  - los `secret` se piden por la terminal sin eco si no vienen.
  - Actualiza `help.golden`.
- Puente y TS: `listSnippetTemplates` y `planTemplateSnippet` en el módulo de asistido (`api.ts` y `fake.ts` con dos plantillas de ejemplo).
- Contrato: sección nueva al final de `docs/plans/contratos-front.md`, con:
  - la forma de `SnippetTemplate`;
  - cómo mapear cada `type` a un control;
  - que la validación de la UI es solo ayuda (la autoritativa es la del núcleo);
  - las claves i18n sugeridas `snippet.<id>.name` y `snippet.<id>.field.<name>`, con `name`/`label` en español como respaldo.

## Pruebas mínimas
- `ValidateValues`: cada tipo con uno válido y uno inválido; desconocida, faltante, no ASCII, y que un secreto no salga en el error.
- `Templates()`: IDs únicos, toda `Tech` válida y todo campo con tipo conocido. Cada plantilla genera un plan que pasa `Validate` con un fixture.
- Por plantilla: el plan con estado previo vacío y con estado previo distinto (la reversa restaura el valor capturado), y cada rechazo de la tabla.
- Servicio: `PlanSnippet` con `template` desconocido da `InvalidArgument`; con uno válido contra el simulador, el plan completo.
- mctl: `snippet list` y `snippet run` con `--set`.
