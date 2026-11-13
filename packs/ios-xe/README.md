# oom/ios-xe

## Español

Paquete oficial con los playbooks de diagnóstico de solo lectura para IOS-XE (capa 1, 2 y 3, plataforma, servicios,
VPN, WAN de routers y casos TAC). Desde la 1.1.0 cubre también los routers IOS-XE (ISR 1000/4000, Catalyst 8200/8300/8500, ASR 1000, Cat8000v)
con los playbooks `wan-` (interfaces WAN, GRE, DMVPN, FlexVPN/IKEv2, BFD, PBR, tracking e IP SLA, ZBFW, PPPoE, DHCP,
NAT de borde, QoS, redundancia) y cuatro casos `tac-` de router. Cada playbook trae su script de la biblioteca con el mismo ID de siempre (`lib-<id>`), así que tus
favoritos se conservan. Los playbooks de línea base, pre/post, métricas, análisis y verificación de actualización
siguen dentro de la aplicación.

Cómo cargarlo (la aplicación nunca descarga paquetes):

1. Baja `oom-ios-xe-<versión>.mpack` de los releases de GitHub y verifica su suma en `SHA256SUMS`.
2. Con la línea de comandos: `mctl pack install oom-ios-xe-<versión>.mpack`. En la aplicación: Ajustes → Paquetes → Instalar.
3. Revisa con `mctl pack list` o en Ajustes → Paquetes.

## English

Official package with the read-only diagnostic playbooks for IOS-XE (layers 1, 2 and 3, platform, services, VPN, router WAN and
TAC cases). Since 1.1.0 it also covers IOS-XE routers (ISR 1000/4000, Catalyst 8200/8300/8500, ASR 1000, Cat8000v)
with the `wan-` playbooks (WAN interfaces, GRE, DMVPN, FlexVPN/IKEv2, BFD, PBR, tracking and IP SLA, ZBFW, PPPoE,
DHCP, edge NAT, QoS, redundancy) and four router `tac-` cases. Each playbook brings its library script with the same ID as before (`lib-<id>`), so your favorites are
kept. The baseline, pre/post, metrics, analysis and upgrade-check playbooks stay inside the application.

How to load it (the application never downloads packages):

1. Download `oom-ios-xe-<version>.mpack` from the GitHub releases and check its sum in `SHA256SUMS`.
2. From the command line: `mctl pack install oom-ios-xe-<version>.mpack`. In the app: Settings → Packages → Install.
3. Check with `mctl pack list` or in Settings → Packages.
