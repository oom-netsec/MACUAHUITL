# oom/wlc-9800

## Español

Paquete oficial con playbooks de diagnóstico de solo lectura para el controlador inalámbrico Catalyst 9800 con
IOS-XE 17.x: chasis (9800-L/40/80), 9800-CL y EWC en APs 9100/9120. Áreas: `ctrl` (salud, versión, licencias, HA,
CPU/memoria, certificados), `ap` (unión CAPWAP, inventario, imágenes, tags, reinicios, un AP), `cli` (resumen y un
cliente), `rf` (radios, RRM, CleanAir, perfiles), `wlan`, `sec` (AAA, rogues, webauth), `mob` (movilidad, roaming
11k/v/r), `svc` (mDNS, multicast) y casos `tac` (WiFi lento, sticky client, roaming, autenticación, asociación, AP
que no se une; con versión general y versión para un cliente o AP).

Los playbooks que declaran datos piden la MAC del cliente (`mac`) o el nombre del AP (`ap`); el núcleo los valida
antes de armar los comandos. Validado en un C9120AXI-A en modo EWC con IOS-XE 17.12.6a (2026-11-13). Lo que el EWC no tiene y un
9800 de chasis o CL sí (grupos de movilidad, Smart Licensing, VLAN/trunks/CDP/LLDP, `show chassis rmi`) lleva el
comentario `# no existe en EWC`. No hay debugs, trazas ni nada que escriba en flash.
Los comandos vienen de la documentación pública de Cisco.

Cómo cargarlo (la aplicación nunca descarga paquetes):

1. Baja `oom-wlc-9800-<versión>.mpack` de los releases de GitHub y verifica su suma en `SHA256SUMS`.
2. Con la línea de comandos: `mctl pack install oom-wlc-9800-<versión>.mpack`. En la aplicación: Ajustes → Paquetes → Instalar.
3. Revisa con `mctl pack list` o en Ajustes → Paquetes.

## English

Official package with read-only diagnostic playbooks for the Catalyst 9800 wireless controller running IOS-XE 17.x:
appliance (9800-L/40/80), 9800-CL and EWC on 9100/9120 APs. Areas: `ctrl` (health, version, licensing, HA, CPU/memory,
certificates), `ap` (CAPWAP join, inventory, images, tags, reboots, a single AP), `cli` (summary and a single client),
`rf` (radios, RRM, CleanAir, profiles), `wlan`, `sec` (AAA, rogues, webauth), `mob` (mobility, 11k/v/r roaming),
`svc` (mDNS, multicast) and `tac` cases (slow WiFi, sticky client, roaming, authentication, association, AP does not
join; each with a general version and a per-client or per-AP version).

Playbooks that declare data ask for the client MAC (`mac`) or the AP name (`ap`); the core validates them before
building the commands. Validated on a C9120AXI-A in EWC mode running IOS-XE 17.12.6a (2026-11-13). What EWC lacks and an appliance or
9800-CL has (mobility groups, Smart Licensing, VLAN/trunks/CDP/LLDP, `show chassis rmi`) carries the comment
`# no existe en EWC`. No debugs, traces or anything that writes to flash.
Commands come from Cisco's public documentation.

How to load it (the application never downloads packages):

1. Download `oom-wlc-9800-<version>.mpack` from the GitHub releases and check its sum in `SHA256SUMS`.
2. From the command line: `mctl pack install oom-wlc-9800-<version>.mpack`. In the app: Settings → Packages → Install.
3. Check with `mctl pack list` or in Settings → Packages.
