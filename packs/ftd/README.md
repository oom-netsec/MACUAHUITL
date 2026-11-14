# oom/ftd

## Español

Paquete oficial con playbooks de diagnóstico de solo lectura para Cisco Secure Firewall Threat Defense (FTD 7.x,
gestionado por FMC o FDM). Requiere el núcleo 0.4.3 o posterior, que reconoce FTD. Todos los nombres empiezan con
«FTD ·». Áreas: `plat` (versión, salud, CPU, memoria, bloques, configuración, tech-support y logs), `l1`
(interfaces, errores, EtherChannel, inline-sets), `fw` (conexiones, xlate y NAT, ACL de lina, política de control de
acceso, descartes de ASP, service-policy, recursos), `snort` (estadísticas, estado, descartes), `vpn` (IKEv1, IKEv2,
IPsec, sesiones sitio a sitio y AnyConnect, certificados), `ha` (failover y cluster), `mgmt` (registro con el FMC,
red y acceso de gestión), `l3` (rutas, OSPF, BGP, EIGRP), `svc` (NTP, SNMP, DHCP) y casos `tac` (tráfico que no pasa
con packet-tracer, Snort que descarta, FMC desconectado, failover y cluster, VPN y AnyConnect, CPU alta, descartes de
ASP, NAT, lentitud, OSPF y BGP).

Los playbooks que declaran datos piden la interfaz (`interface`, el nombre `nameif` en packet-tracer), la IP (`ip`,
`src`, `dst`) o el peer (`peer`); el núcleo los valida antes de armar los comandos. Todo está sin validar en
laboratorio (no hay FTD en el laboratorio). Solo se usa la CLI normal (prompt `> `, sin enable ni abreviaturas): la
app solo permite en FTD `show`, `ping`, `traceroute` y `packet-tracer` (forma estricta); nunca entra a
`system support diagnostic-cli` ni a `expert`, y no permite `configure`, `clear`, `capture`, `capture-traffic`,
`debug`, `cluster exec`, `ping system`, `| redirect` ni `show … file`. Ojo: `packet-tracer` es una simulación, pero
sube los contadores `hitcnt` de las ACL que toca. Si el equipo pide cambiar la contraseña o aceptar el EULA en el
primer inicio de sesión, la conexión se aborta sin escribir nada: hazlo a mano una vez.

Cómo cargarlo (la aplicación nunca descarga paquetes):

1. Baja `oom-ftd-<versión>.mpack` de los releases de GitHub y verifica su suma en `SHA256SUMS`.
2. Con la línea de comandos: `mctl pack install oom-ftd-<versión>.mpack`. En la aplicación: Ajustes → Paquetes → Instalar.
3. Revisa con `mctl pack list` o en Ajustes → Paquetes.

## English

Official package with read-only diagnostic playbooks for Cisco Secure Firewall Threat Defense (FTD 7.x, managed by
FMC or FDM). It needs core 0.4.3 or later, which recognizes FTD. Every name starts with "FTD ·". Areas: `plat`
(version, health, CPU, memory, blocks, configuration, tech-support and logs), `l1` (interfaces, errors, EtherChannel,
inline sets), `fw` (connections, xlate and NAT, lina ACLs, access control policy, ASP drops, service-policy,
resources), `snort` (statistics, status, drops), `vpn` (IKEv1, IKEv2, IPsec, site-to-site and AnyConnect sessions,
certificates), `ha` (failover and cluster), `mgmt` (FMC registration, management network and access), `l3` (routes,
OSPF, BGP, EIGRP), `svc` (NTP, SNMP, DHCP) and `tac` cases (traffic not passing with packet-tracer, Snort dropping
traffic, FMC disconnected, failover and cluster, VPN and AnyConnect, high CPU, ASP drops, NAT, slowness, OSPF and
BGP).

Playbooks that declare data ask for the interface (`interface`, the `nameif` name in packet-tracer), the IP (`ip`,
`src`, `dst`) or the peer (`peer`); the core validates them before building the commands. Everything is unvalidated
in the lab (there is no FTD in the lab). Only the normal CLI is used (prompt `> `, no enable, no abbreviations): on
FTD the app only allows `show`, `ping`, `traceroute` and `packet-tracer` (strict form); it never enters
`system support diagnostic-cli` or `expert`, and does not allow `configure`, `clear`, `capture`, `capture-traffic`,
`debug`, `cluster exec`, `ping system`, `| redirect` or `show … file`. Note: `packet-tracer` is a simulation, but it
increments the `hitcnt` counters of the ACLs it touches. If the device asks to change the password or accept the
EULA at first login, the connection is aborted without writing anything: do it by hand once.

How to load it (the application never downloads packages):

1. Download `oom-ftd-<version>.mpack` from the GitHub releases and check its sum in `SHA256SUMS`.
2. From the command line: `mctl pack install oom-ftd-<version>.mpack`. In the app: Settings → Packages → Install.
3. Check with `mctl pack list` or in Settings → Packages.
