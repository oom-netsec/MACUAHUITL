# oom/cat9k

## Español

Paquete oficial con playbooks de diagnóstico de solo lectura para Catalyst 9200, 9300, 9400, 9500 y 9600 con IOS-XE
17.x. Requiere el núcleo 0.4.1 o posterior. Un Catalyst 9000 se sigue detectando como `ios-xe`: estos playbooks son
contenido sobre ios-xe (plataforma `cat9k`), y solo un equipo `ios-xe` los ve; `ios`, `wlc-9800` y `nx-os` no. Todos los
nombres empiezan con «Catalyst 9K ·». Áreas: `plat` (salud, hardware, CPU y memoria, ambiente, licencias Smart, modo
install, logs y reinicios, TCAM y SDM), `stack` (miembros, anillo, prioridad), `svl` (StackWise Virtual: enlaces y
dual-active), `poe`, `asic` (TCAM y QoS en el ASIC con `show platform hardware fed`), `cpu` (punt, CoPP), `sec`
(802.1X/MAB, MACsec, DHCP snooping/DAI, ACL, device-tracking), `svc` (NTP, SPAN, QoS, SNMP), `l1`, `l2`, `l3` y casos
`tac` (stack dividido, PoE, descartes en el ASIC, CPU por punt, TCAM llena, uplinks, flapping, host sin red, bucles,
dual-active y 802.1X).

Los playbooks que declaran datos piden la interfaz (`interface`) o la MAC (`mac`); el núcleo los valida antes de armar
los comandos. Los comandos solo de un chasis o de un modo llevan un comentario en su línea (`# 9400/9600`, `# SVL`).
Todo está sin validar en laboratorio (sin equipo; pendiente el sandbox de DevNet). Los comandos vienen de la
documentación pública de Cisco y pasan las mismas reglas de solo lectura que los de IOS: sin `debug`, `clear`,
`to-file`, `install` (salvo `show install`) ni redirecciones.

Cómo cargarlo (la aplicación nunca descarga paquetes):

1. Baja `oom-cat9k-<versión>.mpack` de los releases de GitHub y verifica su suma en `SHA256SUMS`.
2. Con la línea de comandos: `mctl pack install oom-cat9k-<versión>.mpack`. En la aplicación: Ajustes → Paquetes → Instalar.
3. Revisa con `mctl pack list` o en Ajustes → Paquetes.

## English

Official package with read-only diagnostic playbooks for Catalyst 9200, 9300, 9400, 9500 and 9600 running IOS-XE
17.x. It needs core 0.4.1 or later. A Catalyst 9000 is still detected as `ios-xe`: these playbooks are content on top
of ios-xe (platform `cat9k`), and only an `ios-xe` device sees them; `ios`, `wlc-9800` and `nx-os` do not. Every name
starts with "Catalyst 9K ·". Areas: `plat` (health, hardware, CPU and memory, environment, Smart licensing, install
mode, logs and reloads, TCAM and SDM), `stack` (members, ring, priority), `svl` (StackWise Virtual: links and
dual-active), `poe`, `asic` (TCAM and QoS in the ASIC with `show platform hardware fed`), `cpu` (punt, CoPP), `sec`
(802.1X/MAB, MACsec, DHCP snooping/DAI, ACL, device tracking), `svc` (NTP, SPAN, QoS, SNMP), `l1`, `l2`, `l3` and `tac`
cases (split stack, PoE, ASIC drops, punt CPU, full TCAM, uplinks, flapping, host with no network, loops, dual-active
and 802.1X).

Playbooks that declare data ask for the interface (`interface`) or the MAC (`mac`); the core validates them before
building the commands. Commands that only apply to one chassis or mode carry a comment on their line (`# 9400/9600`,
`# SVL`). Everything is unvalidated in the lab (no device; pending the DevNet sandbox). Commands come from Cisco's
public documentation and pass the same read-only rules as IOS: no `debug`, `clear`, `to-file`, `install` (except
`show install`) or redirections.

How to load it (the application never downloads packages):

1. Download `oom-cat9k-<version>.mpack` from the GitHub releases and check its sum in `SHA256SUMS`.
2. From the command line: `mctl pack install oom-cat9k-<version>.mpack`. In the app: Settings → Packages → Install.
3. Check with `mctl pack list` or in Settings → Packages.
