# oom/nx-os

## Español

Paquete oficial con playbooks de diagnóstico de solo lectura para Cisco Nexus con NX-OS (9000, 7000, 5000/6000 y
3000). Requiere el núcleo 0.4.1 o posterior, que reconoce NX-OS. Áreas: `plat` (salud, versión y licencias, módulos,
CPU y memoria, logs y cores, ambiente, TCAM, alta disponibilidad y tech-support), `l1` (interfaces, errores,
transceptores DOM, err-disabled), `l2` (VLAN/STP, port-channel y LACP, MAC y ARP, vPC: peer, consistencia y puertos
huérfanos, CDP/LLDP, IGMP snooping), `vxlan` (NVE, VNIs, BGP EVPN, ARP suppression, L3VNI, underlay), `l3` (ruteo,
OSPF, EIGRP, BGP, HSRP/VRRP, multicast, BFD), `fex`, `sec` (ACL, CoPP, AAA, DHCP snooping/DAI), `svc` (NTP, SNMP,
logging, PTP, SPAN/flujos, QoS, tracking) y casos `tac` (lentitud, descartes, vPC inconsistente, flapping, BGP que no
sube, CPU alta, MAC moviéndose, bucles, OSPF, conectividad y VXLAN sin tráfico; con versión general y versión para
una interfaz, una IP o una MAC).

Los playbooks que declaran datos piden la interfaz (`interface`), la IP (`ip`) o la MAC (`mac`); el núcleo los valida
antes de armar los comandos. Los comandos son de NX-OS 9.x/10.x en Nexus 9000; los que son de otra plataforma o
dependen de la versión llevan un comentario en su línea. Todo está sin validar en laboratorio (pendiente el Nexus
9000v de DevNet). La app solo permite en NX-OS comandos de lectura: sin `| redirect`, `>`, `copy`, `run bash` ni
debugs. Los comandos vienen de la documentación pública de Cisco.

Cómo cargarlo (la aplicación nunca descarga paquetes):

1. Baja `oom-nx-os-<versión>.mpack` de los releases de GitHub y verifica su suma en `SHA256SUMS`.
2. Con la línea de comandos: `mctl pack install oom-nx-os-<versión>.mpack`. En la aplicación: Ajustes → Paquetes → Instalar.
3. Revisa con `mctl pack list` o en Ajustes → Paquetes.

## English

Official package with read-only diagnostic playbooks for Cisco Nexus switches running NX-OS (9000, 7000, 5000/6000
and 3000). It needs core 0.4.1 or later, which recognizes NX-OS. Areas: `plat` (health, version and licensing,
modules, CPU and memory, logs and cores, environment, TCAM, high availability and tech-support), `l1` (interfaces,
errors, DOM transceivers, err-disabled), `l2` (VLAN/STP, port-channel and LACP, MAC and ARP, vPC: peer, consistency
and orphan ports, CDP/LLDP, IGMP snooping), `vxlan` (NVE, VNIs, BGP EVPN, ARP suppression, L3VNI, underlay), `l3`
(routing, OSPF, EIGRP, BGP, HSRP/VRRP, multicast, BFD), `fex`, `sec` (ACL, CoPP, AAA, DHCP snooping/DAI), `svc` (NTP,
SNMP, logging, PTP, SPAN/flows, QoS, tracking) and `tac` cases (slowness, drops, inconsistent vPC, flapping, BGP not
establishing, high CPU, MAC moving, loops, OSPF, connectivity and VXLAN with no traffic; each with a general version
and a per-interface, per-IP or per-MAC version).

Playbooks that declare data ask for the interface (`interface`), the IP (`ip`) or the MAC (`mac`); the core validates
them before building the commands. Commands are NX-OS 9.x/10.x on Nexus 9000; those that belong to another platform
or depend on the version carry a comment on their line. Everything is unvalidated in the lab (pending the DevNet Nexus
9000v). On NX-OS the app only allows read commands: no `| redirect`, `>`, `copy`, `run bash` or debugs. Commands come
from Cisco's public documentation.

How to load it (the application never downloads packages):

1. Download `oom-nx-os-<version>.mpack` from the GitHub releases and check its sum in `SHA256SUMS`.
2. From the command line: `mctl pack install oom-nx-os-<version>.mpack`. In the app: Settings → Packages → Install.
3. Check with `mctl pack list` or in Settings → Packages.
