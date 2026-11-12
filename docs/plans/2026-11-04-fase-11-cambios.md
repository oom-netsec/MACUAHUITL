# Fase 11 — Ventana de cambio: Plan e implementación

**Goal:** Hacer cambios seguros sin que la app toque la configuración: pre/post checks sobre Patrol, asistente de verificación previa a upgrade y cumplimiento de configuración (plantilla dorada + endurecimiento).

**Licencias:** solo la biblioteca estándar de Go y lo que ya estaba (gRPC, protobuf, yaml.v3). Ninguna dependencia nueva.

**Architecture:**
- `internal/iosconf`: parser jerárquico de running-config IOS/IOS-XE por indentación. Cuerpos de `banner` (delimitador `^C` o cualquier carácter) y `macro name … @` son texto opaco. `Find` ancla la expresión a la línea completa (`ip http server` no coincide con `no ip http server`).
- `internal/capture`: lee una carpeta terminada de Patrol (con `manifest.json`, última ronda por equipo, carpeta `patrol.DeviceDir`) o texto pegado (cabeceras de Patrol o prompts `SW1#show …`) y lo parte en salidas por comando. Descarta los comandos marcados inválidos. Tope de 64 MiB por archivo.
- `internal/change`: `Parse` extrae de las salidas el estado del equipo; `Compare` empareja PRE y POST por dirección y da semáforo `ok` / `review` / `regression` con hallazgos `info|review|regression` por faceta.
- `internal/upgrade`: lista de verificación con `pass|fail|unknown|na` y su porqué.
- `internal/compliance`: plantilla dorada y 14 reglas de endurecimiento.
- `api/proto/macuahuitl/v1/change.proto`: `ChangeService` (CreateChange, CaptureChange, ListChanges, GetChangeReport, CheckUpgrade, CheckCompliance). Los reportes viajan como `ToolReport` (JSON + texto), igual que las herramientas de la Fase 7.
- Playbooks nuevos: `ios-xe/pre-post` y `ios-xe/upgrade-check` (solo comandos que permite `CheckDenied`).

## Cómo funciona un cambio

1. `CreateChange` recibe un `JobSpec` (equipos, credencial, carpeta; playbook por defecto `ios-xe/pre-post`). El núcleo fuerza una sola ronda, un archivo por ronda, zip al final sin borrar los sueltos, y lo valida con las mismas reglas que `CreateJob`.
2. `CaptureChange(PRE|POST)` crea un trabajo normal de Patrol (`<nombre>-pre` / `-post`) y lo arma con `ArmJob`: mismo Login Test, bóveda, EgressGuard, auditoría y manifest. Si el armado falla (p. ej. llave de host nueva), el trabajo queda creado y la respuesta trae su ID y el motivo; la UI muestra la huella del Login Test para confirmarla y reintenta; en CLI, `mctl job logintest` + `mctl change pre --accept`.
3. POST exige un PRE terminado. `GetChangeReport` lee ambas carpetas con `capture.ReadDir` y compara. También acepta dos carpetas absolutas, para comparar capturas de otra sesión.

## Qué compara (semáforo)

| Faceta | Comando | Regresión | Revisar | Info |
|---|---|---|---|---|
| interfaces | show ip interface brief | up/up → otra cosa o desaparece | — | algo → up/up |
| cdp, lldp | show cdp/lldp neighbors detail | vecino perdido | puerto remoto distinto | vecino nuevo |
| ospf | show ip ospf neighbor | FULL → no FULL, adyacencia perdida | otro cambio de estado | adyacencia nueva |
| bgp | show ip bgp summary | Established → otro estado | prefijos < 90 % | vecino nuevo o que subió |
| rutas | show ip route summary | protocolo a 0 | conteo menor | conteo mayor |
| mac, arp | show mac address-table, show ip arp | — | VLAN/interfaz < 90 % | — |
| hsrp | show standby brief | grupo perdido o en Init/Listen | cambio de estado | — |
| stp | show spanning-tree root | raíz distinta | puerto raíz distinto, VLAN perdida | VLAN nueva |
| versión | show version | — | uptime menor (recarga) | versión distinta |
| config | show running-config | — | — | diff jerárquico (`+ sección > línea`), sin `ntp clock-period` |

Si PRE tiene la salida de un comando y POST no, se marca para revisar. Un equipo que falta en POST o cuya captura POST falló es regresión.

## Upgrade (solo verificación)

Ítems: modo install/bundle (`Installation mode is`, tabla de `show version` o `packages.conf`/`.bin`), espacio libre (imagen si no está copiada + otra vez su tamaño en modo install por la expansión de paquetes), imagen presente y tamaño, MD5 (de la salida de `verify /md5`; si falta, se genera el comando), variable de boot (siguiente recarga, `MANUAL_BOOT`, `boot system`), `show install summary` sin estados U/D, configuración guardada (cabeceras `Last configuration change` vs `NVRAM config last updated`) y redundancia SSO con el par en STANDBY HOT (no aplica en equipos simplex).

## Cumplimiento

Plantilla con la misma sangría que la configuración: `+ patrón` obligatoria, `- patrón` prohibida, línea con hijos = sección (aplica a cada coincidencia), `? sección` opcional, línea suelta = obligatoria (pegar una config dorada funciona). Reglas incluidas: aaa new-model, SSH v2, VTY solo SSH, sin `ip http server` y HTTPS con autenticación, NTP autenticado, logging host, service password-encryption, secretos tipo 8/9 (tipo 5 y contraseñas de línea para revisar), banner, exec-timeout, CoPP, SNMP sin public/private ni v1/v2c sin ACL, no ip source-route, tcp-keepalives-in.

## CLI y UI

- `mctl change create -f cambio.yaml | pre|post [--accept H] [--exclude E] ID | list | report ID | report --pre DIR --post DIR [--json]`
- `mctl upgrade check --outputs ARCHIVO --image NOMBRE [--size B] [--md5 HEX] [--verify ARCHIVO] [--json]`
- `mctl compliance check --config ARCHIVO [--template ARCHIVO] [--json]`
- Terminan con código 1 si hay regresión, verificación fallida o regla fallida (para scripts).
- UI: pestaña **Cambios** con Pre/Post (crear, capturar, confirmar huella, reporte con semáforo), Upgrade y Cumplimiento.

## Decisiones

- Los cambios viven en memoria del núcleo (como los trabajos tras reiniciar); el reporte por carpetas cubre el caso de un núcleo reiniciado.
- La comparación usa salidas enmascaradas por Patrol: el enmascarado es determinista, así que no genera diferencias falsas, pero el cumplimiento sobre una config enmascarada no distingue comunidades por defecto.
- Umbral de 90 % para MAC/ARP/prefijos: las tablas fluctúan solas.
- `capture.Key` no expande abreviaturas: se usan los comandos completos de los playbooks.

## Pendientes / sin validar

- **Todas las salidas de prueba están escritas a mano según la documentación pública de Cisco; ninguna regla ni parser está validado en laboratorio.**
- NX-OS, IOS clásico con formatos distintos, IPv6 (`show ipv6 …`, filas de BGP partidas) y VRF no se comparan aún.
- Persistir cambios en la base y ligar el reporte a la UI de Patrol (progreso en vivo) quedan para después.
