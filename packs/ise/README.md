# oom/ise

## Español

Paquete oficial con playbooks de diagnóstico de solo lectura para nodos Cisco ISE 3.x (PAN, MnT, PSN y pxGrid), desde
la CLI de ADE-OS (prompt `host/admin#`, sin enable). Requiere el núcleo 0.4.4 o posterior, que reconoce ISE. Todos los
nombres empiezan con «ISE ·». Áreas: `plat` (versión y parches, estado de la aplicación, CPU, memoria y discos,
hardware, configuración, tech-support, usuarios conectados, respaldos), `l1` (interfaces y errores), `l3` (rutas,
puertos en escucha, DNS, conectividad a una IP), `svc` (NTP, SNMP, RADIUS, TACACS+, pxGrid, certificados, Active
Directory, replicación), `logs` (sistema, aplicación, errores de ise-psc, Catalina) y casos `tac` (proceso caído,
disco lleno, NTP desfasado, nodo que no sincroniza, lentitud, no autentica, interfaz web que no abre, reinicio).

El de conectividad (`l3-conectividad-ip`) pide la IP (`ip`); el núcleo la valida antes de armar los comandos. Todo
está sin validar en laboratorio (no hay ISE en el laboratorio). La app solo permite en ISE `show` (nunca `tail`,
`file` ni `show top`), `ping` acotado, `traceroute`, `nslookup` y `terminal length 0`, con un solo filtro de pipe
(`include`, `exclude`, `begin`, `count`, `last` o `end`); nunca `application start/stop/reset-config`, `reload`,
`backup`, `restore`, `patch`, `configure`, `copy`, `debug` ni `tech`. Los logs se leen con `| last N`. El
tech-support, `show running-config` y `show startup-config` llevan `may_contain_secrets`. Si el equipo pide cambiar la
contraseña o contestar una pregunta (y/n) en el primer inicio de sesión, la conexión se aborta sin escribir nada:
hazlo a mano una vez.

Cómo cargarlo (la aplicación nunca descarga paquetes):

1. Baja `oom-ise-<versión>.mpack` de los releases de GitHub y verifica su suma en `SHA256SUMS`.
2. Con la línea de comandos: `mctl pack install oom-ise-<versión>.mpack`. En la aplicación: Ajustes → Paquetes → Instalar.
3. Revisa con `mctl pack list` o en Ajustes → Paquetes.

## English

Official package with read-only diagnostic playbooks for Cisco ISE 3.x nodes (PAN, MnT, PSN and pxGrid), from the
ADE-OS CLI (prompt `host/admin#`, no enable). It needs core 0.4.4 or later, which recognizes ISE. Every name starts
with "ISE ·". Areas: `plat` (version and patches, application status, CPU, memory and disks, hardware,
configuration, tech-support, logged-in users, backups), `l1` (interfaces and errors), `l3` (routes, listening
ports, DNS, connectivity to an IP), `svc` (NTP, SNMP, RADIUS, TACACS+, pxGrid, certificates, Active Directory,
replication), `logs` (system, application, ise-psc errors, Catalina) and `tac` cases (process down, full disk, NTP
out of sync, node not synchronizing, slowness, not authenticating, web interface not opening, restart).

The connectivity one (`l3-conectividad-ip`) asks for the IP (`ip`); the core validates it before building the
commands. Everything is unvalidated in the lab (there is no ISE in the lab). On ISE the app only allows `show`
(never `tail`, `file` or `show top`), bounded `ping`, `traceroute`, `nslookup` and `terminal length 0`, with a single
pipe filter (`include`, `exclude`, `begin`, `count`, `last` or `end`); never `application start/stop/reset-config`,
`reload`, `backup`, `restore`, `patch`, `configure`, `copy`, `debug` or `tech`. Logs are read with `| last N`.
Tech-support, `show running-config` and `show startup-config` carry `may_contain_secrets`. If the device asks to
change the password or answer a (y/n) question at first login, the connection aborts without writing anything: do
it by hand once.

How to load it (the application never downloads packages):

1. Download `oom-ise-<version>.mpack` from the GitHub releases and check its sum in `SHA256SUMS`.
2. From the command line: `mctl pack install oom-ise-<version>.mpack`. In the app: Settings → Packages → Install.
3. Check with `mctl pack list` or in Settings → Packages.
