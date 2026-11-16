# oom/ios-xe

## Español

Paquete oficial con los playbooks de diagnóstico de solo lectura para IOS-XE (capa 1, 2 y 3, plataforma, servicios,
VPN, WAN de routers y casos TAC). Desde la 1.1.0 cubre también los routers IOS-XE (ISR 1000/4000, Catalyst
8200/8300/8500, ASR 1000, Cat8000v) con los playbooks `wan-` (interfaces WAN, GRE, DMVPN, FlexVPN/IKEv2, BFD, PBR,
tracking e IP SLA, ZBFW, PPPoE, DHCP, NAT de borde, QoS, redundancia) y cuatro casos `tac-` de router. Cada playbook
trae su script de la biblioteca con el mismo ID de siempre (`lib-<id>`), así que tus favoritos se conservan. Los
playbooks de línea base, pre/post, métricas, análisis y verificación de actualización siguen dentro de la aplicación.

Comandos revisados en un Catalyst 9000v (IOS-XE 17.15) de DevNet el 2026-11-14. Desde la 1.1.2 ya no traen
`show mls qos` (sigue en oom/ios) ni `show monitor` sin `session`. Los que solo existen en routers (QFP, DMVPN, ZBFW,
PPPoE, `show bootvar`, `show ip flow`, `show control-plane host open-ports`) llevan `# no existe en Cat9k`;
`show license feature` solo existe en routers 16.x, y lo que falla en el Cat9000v virtual (stack, SVL, PoE,
`show calendar`) lleva su comentario.

Desde la 1.1.3 también se probó en un Cat8000v 17.15 sin nivel de licencia en CML (2026-11-14). Los comentarios al final de la línea significan: `# no existe en routers IOS-XE (solo switches)`, el comando es de switch y un router lo rechaza; `# falla en Cat8000v virtual`, lo rechaza la plataforma virtual aunque exista en hardware; `# requiere nivel de licencia (en Cat8000v sin licencia no existe)`, necesita un nivel de licencia que el Cat8000v de prueba no tenía.

Cómo cargarlo (la aplicación nunca descarga paquetes):

1. Baja `oom-ios-xe-<versión>.mpack` de los releases de GitHub y verifica su suma en `SHA256SUMS`.
2. Con la línea de comandos: `mctl pack install oom-ios-xe-<versión>.mpack`.
   En la aplicación: Ajustes → Paquetes → Instalar paquete…
3. Revisa con `mctl pack list` o en Ajustes → Paquetes.

## English

Official package with the read-only diagnostic playbooks for IOS-XE (layers 1, 2 and 3, platform, services, VPN,
router WAN and TAC cases). Since 1.1.0 it also covers IOS-XE routers (ISR 1000/4000, Catalyst 8200/8300/8500, ASR
1000, Cat8000v) with the `wan-` playbooks (WAN interfaces, GRE, DMVPN, FlexVPN/IKEv2, BFD, PBR, tracking and IP SLA,
ZBFW, PPPoE, DHCP, edge NAT, QoS, redundancy) and four router `tac-` cases. Each playbook brings its library script
with the same ID as before (`lib-<id>`), so your favorites are kept. The baseline, pre/post, metrics, analysis and
upgrade-check playbooks stay inside the application.

Commands checked on a Catalyst 9000v (IOS-XE 17.15) DevNet sandbox on 2026-11-14. Since 1.1.2 they no longer include
`show mls qos` (still in oom/ios) or `show monitor` without `session`. Router-only ones (QFP, DMVPN, ZBFW, PPPoE,
`show bootvar`, `show ip flow`, `show control-plane host open-ports`) carry `# no existe en Cat9k`; `show license
feature` only exists on 16.x routers, and what fails on the virtual Cat9000v (stack, SVL, PoE, `show calendar`)
carries its comment.

Since 1.1.3 it was also tested on a Cat8000v 17.15 with no license level in CML (2026-11-14). The end-of-line comments mean: `# no existe en routers IOS-XE (solo switches)`, a switch-only command that a router rejects; `# falla en Cat8000v virtual`, rejected by the virtual platform even if it exists on hardware; `# requiere nivel de licencia (en Cat8000v sin licencia no existe)`, it needs a license level the test Cat8000v did not have.

How to load it (the application never downloads packages):

1. Download `oom-ios-xe-<version>.mpack` from the GitHub releases and check its sum in `SHA256SUMS`.
2. From the command line: `mctl pack install oom-ios-xe-<version>.mpack`. In the app: Settings → Packs → Install pack…
3. Check with `mctl pack list` or in Settings → Packs.
