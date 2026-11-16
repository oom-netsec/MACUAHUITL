# oom/wlc-aireos

## Español

Paquete oficial con playbooks de diagnóstico de solo lectura para controladores inalámbricos Cisco AireOS 8.5 a 8.10
(2504, 3504, 5508, 5520, 8540 y vWLC). Requiere el núcleo 0.4.3 o posterior. Todos los nombres empiezan con
«AireOS ·». Áreas: `plat` (versión, salud, CPU y memoria, tech-support, logs y traps, base de datos), `ctrl`
(configuración global, redundancia, hora y certificados, interfaces, puertos y LAG, rutas), `ap` (resumen, unión
CAPWAP, inventario, un AP, radios, eventos, grupos), `cli` (clientes, detalle por MAC, por AP y por WLAN, roaming),
`wlan` (resumen, detalle, band select), `rf` (RRM por banda, perfiles, CleanAir, RF de un AP), `mob` (movilidad y
anchors), `sec` (RADIUS, TACACS, rogues, ACLs, WebAuth), `svc` (SNMP, DHCP, mDNS y multicast) y casos `tac` (AP que
no se une, autenticación, asociación, roaming, cobertura, interferencia, CPU y memoria, lentitud, reinicios).

Los playbooks que declaran datos piden el AP (`ap`, el nombre del AP), el cliente (`mac`) o la WLAN (`wlan`, su
número). Todo está sin validar en laboratorio (no hay AireOS en el laboratorio). La app solo permite en AireOS
`show`, `ping` acotado y `grep include|exclude "patrón" "show …"`; nunca manda `config` (tampoco
`config paging disable`: la paginación se contesta con espacio), `show run-config` (pregunta y/N), `debug`, `save`,
`reset`, `transfer` ni `clear`. Los que pueden mostrar claves (tech-support, RADIUS, TACACS, WLANs, SNMP, usuarios)
llevan `may_contain_secrets`. Muchos controladores piden `User:` y `Password:` dentro del shell SSH; la app los
contesta con la credencial del equipo.

Cómo cargarlo (la aplicación nunca descarga paquetes):

1. Baja `oom-wlc-aireos-<versión>.mpack` de los releases de GitHub y verifica su suma en `SHA256SUMS`.
2. Con la línea de comandos: `mctl pack install oom-wlc-aireos-<versión>.mpack`. En la aplicación: Ajustes → Paquetes → Instalar paquete…
3. Revisa con `mctl pack list` o en Ajustes → Paquetes.

## English

Official package with read-only diagnostic playbooks for Cisco AireOS wireless controllers 8.5 to 8.10 (2504, 3504,
5508, 5520, 8540 and vWLC). It needs core 0.4.3 or later. Every name starts with "AireOS ·". Areas: `plat`
(version, health, CPU and memory, tech-support, logs and traps, database), `ctrl` (global configuration, redundancy,
time and certificates, interfaces, ports and LAG, routes), `ap` (summary, CAPWAP join, inventory, one AP, radios,
events, groups), `cli` (clients, detail by MAC, by AP and by WLAN, roaming), `wlan` (summary, detail, band select),
`rf` (RRM per band, profiles, CleanAir, RF of one AP), `mob` (mobility and anchors), `sec` (RADIUS, TACACS, rogues,
ACLs, WebAuth), `svc` (SNMP, DHCP, mDNS and multicast) and `tac` cases (AP not joining, authentication, association,
roaming, coverage, interference, CPU and memory, slowness, reboots).

Playbooks that declare data ask for the AP (`ap`, the AP name), the client (`mac`) or the WLAN (`wlan`, its number).
Everything is unvalidated in the lab (there is no AireOS in the lab). On AireOS the app only allows `show`, bounded
`ping` and `grep include|exclude "pattern" "show …"`; it never sends `config` (not even `config paging disable`:
paging is answered with a space), `show run-config` (asks y/N), `debug`, `save`, `reset`, `transfer` or `clear`.
Those that can show keys (tech-support, RADIUS, TACACS, WLANs, SNMP, users) carry `may_contain_secrets`. Many
controllers ask for `User:` and `Password:` inside the SSH shell; the app answers with the device credential.

How to load it (the application never downloads packages):

1. Download `oom-wlc-aireos-<version>.mpack` from the GitHub releases and check its sum in `SHA256SUMS`.
2. From the command line: `mctl pack install oom-wlc-aireos-<version>.mpack`. In the app: Settings → Packs → Install pack…
3. Check with `mctl pack list` or in Settings → Packs.
