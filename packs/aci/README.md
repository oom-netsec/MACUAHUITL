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
- `vrf`: se escribe como `tenant:vrf` (p. ej. `common:default`), con un solo `:` y cada parte de hasta 64 caracteres (letras, dígitos, `_`, `.` y `-`, sin empezar con `-`). Desde la 1.0.1 la app lo pide con su propio tipo «vrf». No se aceptan un tenant con nombre de esquema (`tftp:x`, `ftp:x`, `http:x`…), porque el filtro de solo lectura lo tomaría por ruta remota, ni nombres que lleven `:` dentro.
- `vnid`: número de VNID entre 1 y 16777215 (p. ej. `2850817`); desde la 1.0.1 la app lo pide con su propio tipo «vnid».

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
- `vrf`: written as `tenant:vrf` (e.g. `common:default`), with a single `:` and each part up to 64 characters (letters, digits, `_`, `.` and `-`, not starting with `-`). Since 1.0.1 the app asks for it with its own "vrf" type. A tenant named like a scheme (`tftp:x`, `ftp:x`, `http:x`…) is not accepted, because the read-only filter would take it for a remote path, nor are names containing `:`.
- `vnid`: VNID number between 1 and 16777215 (e.g. `2850817`); since 1.0.1 the app asks for it with its own "vnid" type.

How to load it (the application never downloads packages): download `oom-aci-<version>.mpack` from the GitHub releases,
check its sum in `SHA256SUMS` and install it with `mctl pack install oom-aci-<version>.mpack` or Settings → Packages → Install.
