# Fase 15c: capa única de parsers (ADR 0008, punto 3)

Rama `fase-15c-parsers`. Sin cambio de comportamiento: las pruebas de `analyze`, `topo`, `change`, `fleet` y `upgrade` pasan con las mismas aserciones.

## Qué se movió a `internal/parse/iosxe`
- `analyze`: CPU, memoria (`show processes memory` y `show memory statistics`), interfaces (contadores con la línea de evidencia), uptime y razones de reinicio (ahora dentro de `ParseVersion`), STP detail, BGP, OSPF, HSRP, duraciones de IOS (`IOSDuration`), `show clock detail` y `show logging` (`ParseLogLine`). En `analyze/parse.go` quedan adaptadores finos (`parseInterfaces`, `parseUptime`) y las claves de presentación.
- `topo`: CDP, LLDP, raíces STP, port-channels, versión y `ShortIf`. Se borró `topo.Neighbor`; el grafo usa `iosxe.Neighbor`.
- `change`: interfaces (`ParseIPBrief`), CDP, LLDP, OSPF, BGP, resumen de rutas (`ParseRouteSummary`), MAC, ARP, HSRP, STP root (`ParseSTPRootTable`) y versión/uptime. `change.Parse` solo arma el `Snapshot`.
- `upgrade`: `ParseVersion` (imagen, register, modo install/bundle), `ParseDir` (archivos), `ParseBoot`, `ParseInstallSummary`, `ParseRedundancy`, `ParseVerifyMD5`, `ParseConfigHeader`. `upgrade` conserva solo la lógica de las verificaciones.
- `fleet` ya consumía `iosxe`; no importa `topo`. Se ajustó a los campos nuevos.

## Decisiones
- Unificación: el parser único es la unión de los dos. `ParseCDP`/`ParseLLDP` aceptan IOS-XE y NX-OS y llenan plataforma, versión, VLAN nativa, dúplex y capacidades. `ParseVersion` entiende IOS-XE y NX-OS (`Device name`, `NXOS: version`).
- Nombres de interfaz: `Neighbor` trae `LocalIf/RemoteIf` abreviados (contrato de `fleet`) y `LocalRaw/RemoteRaw` tal como los imprime el equipo (los que necesita `change`); `Iface` e `IPBrief` traen `Raw`. Las aserciones de `topo` sobre nombres largos pasaron a los campos `*Raw` con el mismo valor.
- `Iface.Evidence` guarda la línea sin recortar (la pide `analyze`); `fleet` la recorta al mostrarla.
- `ShortIf` toma la lista completa de `topo` (también normaliza `gi1/0/1` a `Gi1/0/1`).
- Fixtures: los de CDP/LLDP/STP/port-channel de `topo` y las secciones `show` que usaban `analyze` y `change` están en `internal/parse/iosxe/testdata`. Las carpetas de trabajo de Patrol que usan los dominios (`LoadPatrolDir`, `analyze` bundle, `fleet`, `upgrade`) se quedan donde están: son la entrada del cargador de cada dominio, no de un parser.

## Diferencias visibles (mínimas)
- `change`: los conteos de ARP por interfaz usan el nombre abreviado (`Gi1/0/1`), como `fleet`; antes salía el nombre largo en interfaces físicas ruteadas. En Vlan no cambia.
- NX-OS: `ParseVersion` toma `Device name` como host y lee el uptime de `Kernel uptime is N day(s)`; antes `fleet` leía "Kernel" como nombre.
- `ParseLLDP` ahora incluye entradas NX-OS que abren con `Local Port id` o `Chassis id` (antes `fleet` las descartaba) y usa el chassis id como nombre si falta `System Name`.
- CDP: el nombre del vecino es `System Name` cuando existe; antes se usaba `Device ID`.
- CDP: `Mgmt address(es)` llena `MgmtIP` en `fleet`; antes quedaba vacío.
- `change`: el estado BGP sale completo (`Idle (Admin)`; antes salía solo `(Admin)`), se leen vecinos IPv6 y las filas que la salida parte en dos líneas.
- `change`: OSPF, BGP y HSRP exigen la línea de encabezado de su tabla; sin ella no se lee ninguna fila.

## Pendiente
- Error tipado (ADR 0008 §3): los parsers siguen devolviendo `(T, bool)`, como los ~20 existentes. Pasarlos a error tipado cambia la firma de todos y de sus pruebas; se hace en una pasada aparte, con un `FormatError` y los dominios mostrándolo como aviso.
- `topo` ignora el `ok` de CDP/LLDP (igual que antes): no avisa de formato desconocido.
- Dependencias entre dominios que quedan: `change` → `iosconf` y `capture`; `compliance` → `iosconf`; `upgrade` → `capture`; `analyze` → `audit` y `pcapan`; `topo` → `pcapan`. Son bibliotecas compartidas (sin ser parsers de `show`): `iosconf` y `pcapan` quedan declarados en `Shared` de `tools/archcheck` (y siguen revisados como dominios), y `audit` es infraestructura, fuera de `Domains`. Mover `iosconf` a `internal/parse/iosxe` queda como opción.
- Cargadores de carpetas de Patrol duplicados en `topo`, `fleet` y `analyze` (`header` regexp + lectura por rondas): son entrada, no parsers de `show`; candidatos a `internal/capture`.
- `iosconf` (árbol de `show running-config`) y `compliance` quedan como están.
