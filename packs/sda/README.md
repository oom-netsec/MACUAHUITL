# oom/sda

## Español

Paquete oficial con playbooks de diagnóstico de solo lectura para el fabric SD-Access (edge, border y control plane)
sobre Catalyst 9000 con IOS-XE 17.x. Requiere el núcleo 0.4.1 o posterior. Un equipo de SD-Access se sigue detectando
como `ios-xe`: estos playbooks son contenido sobre ios-xe (plataforma `sda`), y solo un equipo `ios-xe` los ve; `ios`,
`wlc-9800` y `nx-os` no. Todos los nombres empiezan con «SD-Access ·». Áreas: `lisp` (sesiones, registros del control
plane, map-cache, base de datos local, publicaciones, un EID por IP o MAC), `fabric` (roles, VN y VRF, túneles de
acceso, SGT y CTS, credenciales y PAC, AAA hacia ISE), `edge` (sesiones de endpoints, device-tracking, DHCP), `border`
(handoff BGP, rutas externas, tránsito) y casos `tac` (endpoint sin conectividad por MAC o IP, onboarding que falla,
roaming entre edges, border sin rutas, tráfico denegado por SGT).

Los playbooks que declaran datos piden la MAC (`mac`), la IP (`ip`) o la interfaz (`interface`); el núcleo los valida
antes de armar los comandos. Los comandos usan `show lisp all instance-id *` para cubrir todas las instancias. Todo
está sin validar en laboratorio (sin equipo; pendiente el sandbox de SD-Access de DevNet): la sintaxis de LISP cambia
entre versiones 17.x y un comando no soportado queda marcado como fallido sin afectar al resto. Los comandos pasan las
reglas de solo lectura de IOS: sin `debug`, `clear`, `to-file` ni redirecciones; `show cts credentials` y `show cts
pacs` están marcados como posibles secretos.

Cómo cargarlo (la aplicación nunca descarga paquetes):

1. Baja `oom-sda-<versión>.mpack` de los releases de GitHub y verifica su suma en `SHA256SUMS`.
2. Con la línea de comandos: `mctl pack install oom-sda-<versión>.mpack`. En la aplicación: Ajustes → Paquetes → Instalar.
3. Revisa con `mctl pack list` o en Ajustes → Paquetes.

## English

Official package with read-only diagnostic playbooks for the SD-Access fabric (edge, border and control plane) on
Catalyst 9000 running IOS-XE 17.x. It needs core 0.4.1 or later. An SD-Access device is still detected as `ios-xe`:
these playbooks are content on top of ios-xe (platform `sda`), and only an `ios-xe` device sees them; `ios`,
`wlc-9800` and `nx-os` do not. Every name starts with "SD-Access ·". Areas: `lisp` (sessions, control-plane
registrations, map-cache, local database, publications, one EID by IP or MAC), `fabric` (roles, VNs and VRFs, access
tunnels, SGTs and CTS, credentials and PACs, AAA to ISE), `edge` (endpoint sessions, device tracking, DHCP), `border`
(BGP handoff, external routes, transit) and `tac` cases (endpoint with no connectivity by MAC or IP, failing
onboarding, roaming between edges, border with no routes, traffic denied by SGT).

Playbooks that declare data ask for the MAC (`mac`), the IP (`ip`) or the interface (`interface`); the core validates
them before building the commands. Commands use `show lisp all instance-id *` to cover every instance. Everything is
unvalidated in the lab (no device; pending the DevNet SD-Access sandbox): LISP syntax changes between 17.x releases
and an unsupported command is marked as failed without affecting the rest. Commands pass the IOS read-only rules: no
`debug`, `clear`, `to-file` or redirections; `show cts credentials` and `show cts pacs` are flagged as possible
secrets.

How to load it (the application never downloads packages):

1. Download `oom-sda-<version>.mpack` from the GitHub releases and check its sum in `SHA256SUMS`.
2. From the command line: `mctl pack install oom-sda-<version>.mpack`. In the app: Settings → Packages → Install.
3. Check with `mctl pack list` or in Settings → Packages.
