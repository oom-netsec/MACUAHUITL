# oom/aci

## Español

Paquete oficial con playbooks de diagnóstico de solo lectura para **leaf y spine Nexus 9000 en modo ACI**, desde su CLI.
Requiere el núcleo 0.4.4 o posterior. Usa la plataforma `nx-os` (los nodos ACI corren NX-OS); los IDs son `nx-os/aci-…` y
todos los nombres empiezan con «ACI ·». Áreas: `plat` (versión, módulos y logs), `fabric` (IS-IS, VTEP y túneles, MP-BGP de
los spine), `ep` (endpoints por IP o MAC, VLAN y BD), `pol` (contratos: zoning-rule y zoning-filter), `l1`, `l2` (LLDP,
port-channel, vPC), `l3` (VRF, BGP, OSPF y BFD de L3Out) y casos `tac`.

**El APIC no está cubierto:** su CLI corre sobre una shell de Linux y pide su propia plataforma. Todo va **sin validar en
laboratorio**. En un NX-OS standalone los comandos propios de ACI salen inválidos (como cat9k sobre ios-xe), y en un spine
los de vPC o L3Out no aplican. La app solo permite comandos de lectura: nada de `vsh`, `moquery`, `acidiag` ni bash.

### Datos
- `ip`, `mac` e `interface`: como en el paquete oom/nx-os.
- `vrf`: se escribe como `tenant:vrf` (p. ej. `common:default`); la app lo pide con el tipo "interfaz": debe empezar con letra, medir hasta 48 caracteres y no llamarse como un esquema (`tftp:`, `http:`…), porque la app lo rechaza.
- `vnid`: número de VNID (p. ej. `2850817`); la app lo pide con el tipo "AP".

Cómo cargarlo (la aplicación nunca descarga paquetes): baja `oom-aci-<versión>.mpack` de los releases de GitHub, verifica
su suma en `SHA256SUMS` e instálalo con `mctl pack install oom-aci-<versión>.mpack` o en Ajustes → Paquetes → Instalar.

## English

Official package with read-only diagnostic playbooks for **Nexus 9000 leaf and spine switches in ACI mode**, from their
CLI. It needs core 0.4.4 or later. It uses the `nx-os` platform (ACI nodes run NX-OS); IDs are `nx-os/aci-…` and every name
starts with "ACI ·". Areas: `plat` (version, modules and logs), `fabric` (IS-IS, VTEPs and tunnels, spine MP-BGP), `ep`
(endpoints by IP or MAC, VLANs and BDs), `pol` (contracts: zoning-rule and zoning-filter), `l1`, `l2` (LLDP, port-channel,
vPC), `l3` (VRF, L3Out BGP, OSPF and BFD) and `tac` cases.

**The APIC is not covered:** its CLI runs on a Linux shell and needs its own platform. Everything is **unvalidated in the
lab**. On a standalone NX-OS the ACI-only commands come back invalid (like cat9k on ios-xe), and on a spine the vPC or
L3Out ones do not apply. The app only allows read commands: no `vsh`, `moquery`, `acidiag` or bash.

### Data
- `ip`, `mac` and `interface`: as in the oom/nx-os package.
- `vrf`: written as `tenant:vrf` (e.g. `common:default`); the app asks for it with the type "interface": it must start with a letter, be at most 48 characters and not be named like a scheme (`tftp:`, `http:`…), because the app rejects it.
- `vnid`: VNID number (e.g. `2850817`); the app asks for it with the type "AP".

How to load it (the application never downloads packages): download `oom-aci-<version>.mpack` from the GitHub releases,
check its sum in `SHA256SUMS` and install it with `mctl pack install oom-aci-<version>.mpack` or Settings → Packages → Install.
