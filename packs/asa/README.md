# oom/asa

## Español

Paquete oficial con playbooks de diagnóstico de solo lectura para Cisco ASA 9.x (ASAv, 5500-X y Firepower con imagen
ASA), en modo simple y multicontexto. Requiere el núcleo 0.4.3 o posterior, que reconoce ASA. Todos los nombres
empiezan con «ASA ·». Áreas: `plat` (salud, versión y licencias, CPU, memoria, bloques, logs, crashinfo, ambiente,
configuración y tech-support), `l1` (interfaces, errores, descartes de ASP, EtherChannel), `fw` (conexiones, xlate y
NAT, ACL con hitcnt, service-policy e inspección, threat-detection, recursos), `vpn` (IKEv1, IKEv2, IPsec, sesiones
L2L y AnyConnect, certificados), `ha` (failover y cluster), `ctx` (contextos y recursos), `l3` (rutas, OSPF, BGP,
EIGRP, ARP), `sec` (AAA, gestión, shun), `svc` (NTP, SNMP, logging, DNS, DHCP) y casos `tac` (tráfico que no pasa con
packet-tracer, NAT, túnel que no sube, AnyConnect, failover inesperado, CPU alta, bloques, descartes de ASP,
lentitud, OSPF/BGP y cluster).

Los playbooks que declaran datos piden la interfaz (`interface`, el nombre `nameif` en packet-tracer), la IP (`ip`,
`src`, `dst`) o el peer (`peer`); el núcleo los valida antes de armar los comandos. Comandos revisados en un ASAv 9.x de CML
con un solo contexto (2026-11-14); también con dos ASAv en failover A/S, incluido un failover provocado; el
multicontexto y el cluster siguen sin revisar (el ASAv no acepta `mode multiple`). La app solo permite en ASA comandos de lectura: `show`, `ping`,
`traceroute`, `packet-tracer` (forma estricta) y `dir`; sin `more`, `copy`, `capture`, `changeto`, `failover`,
`clear`, `debug`, `| redirect` ni `show … file`. Los comandos vienen de la documentación pública de Cisco. Ojo: `packet-tracer` es una simulación, pero sube los
contadores `hitcnt` de las ACL que toca y, si el flujo es tráfico interesante para un crypto map, puede iniciar la
negociación IKE; los playbooks que lo usan lo avisan en su cabecera.

Anotaciones al final de la línea de un comando (revisadas en un ASAv 9.x de CML el 2026-11-14): `# no existe en ASAv`, el comando es de hardware (por ejemplo `show environment`) y el ASAv virtual lo rechaza; `# solo multicontexto (espacio del sistema)`, solo funciona en modo multicontexto y desde el espacio del sistema.

Primer inicio de sesión: según la versión y la configuración, el ASA 9.x puede pedir a un usuario nuevo que cambie su
contraseña al entrar por primera vez («This is your first login»). La aplicación no la cambia: el Login Test falla de inmediato con «primer inicio de sesión». Entra
una vez por consola o SSH y fija la contraseña (el ASAv 9.x del laboratorio pidió de 8 a 127 caracteres, sin 3 caracteres seguidos ni repetidos).

Cómo cargarlo (la aplicación nunca descarga paquetes):

1. Baja `oom-asa-<versión>.mpack` de los releases de GitHub y verifica su suma en `SHA256SUMS`.
2. Con la línea de comandos: `mctl pack install oom-asa-<versión>.mpack`. En la aplicación: Ajustes → Paquetes → Instalar paquete…
3. Revisa con `mctl pack list` o en Ajustes → Paquetes.

## English

Official package with read-only diagnostic playbooks for Cisco ASA 9.x (ASAv, 5500-X and Firepower with ASA image),
in single and multiple context mode. It needs core 0.4.3 or later, which recognizes ASA. Every name starts with
"ASA ·". Areas: `plat` (health, version and licensing, CPU, memory, blocks, logs, crashinfo, environment,
configuration and tech-support), `l1` (interfaces, errors, ASP drops, EtherChannel), `fw` (connections, xlate and
NAT, ACLs with hit counts, service-policy and inspection, threat-detection, resources), `vpn` (IKEv1, IKEv2, IPsec,
L2L and AnyConnect sessions, certificates), `ha` (failover and cluster), `ctx` (contexts and resources), `l3`
(routes, OSPF, BGP, EIGRP, ARP), `sec` (AAA, management, shun), `svc` (NTP, SNMP, logging, DNS, DHCP) and `tac`
cases (traffic not passing with packet-tracer, NAT, tunnel not coming up, AnyConnect, unexpected failover, high CPU,
blocks, ASP drops, slowness, OSPF/BGP and cluster).

Playbooks that declare data ask for the interface (`interface`, the `nameif` name in packet-tracer), the IP (`ip`,
`src`, `dst`) or the peer (`peer`); the core validates them before building the commands. Commands checked on an ASAv 9.x in
CML with a single context (2026-11-14); also with two ASAv in A/S failover, including a forced failover; multiple
context and clustering remain unchecked (ASAv does not accept `mode multiple`). On ASA the app only allows read commands: `show`, `ping`, `traceroute`,
`packet-tracer` (strict form) and `dir`; no `more`, `copy`, `capture`, `changeto`, `failover`, `clear`, `debug`,
`| redirect` or `show … file`. Commands come from Cisco's public documentation. Note: `packet-tracer` is a simulation, but it increments the `hitcnt`
counters of the ACLs it touches and, if the flow is interesting traffic for a crypto map, it can start the IKE
negotiation; the playbooks that use it say so in their header.

Notes at the end of a command line (checked on an ASAv 9.x in CML on 2026-11-14): `# no existe en ASAv` means the command is hardware-only (for example `show environment`) and the virtual ASAv rejects it; `# solo multicontexto (espacio del sistema)` means it only works in multiple context mode from the system execution space.

First login: depending on the version and configuration, ASA 9.x may require a new user to change their password on
the first login («This is your first login»). The
application does not change it: the Login Test fails right away with «first login». Log in once over console or SSH
and set the password (the lab ASAv 9.x required 8 to 127 characters, no 3 sequential or repeated characters).

How to load it (the application never downloads packages):

1. Download `oom-asa-<version>.mpack` from the GitHub releases and check its sum in `SHA256SUMS`.
2. From the command line: `mctl pack install oom-asa-<version>.mpack`. In the app: Settings → Packs → Install pack…
3. Check with `mctl pack list` or in Settings → Packs.
