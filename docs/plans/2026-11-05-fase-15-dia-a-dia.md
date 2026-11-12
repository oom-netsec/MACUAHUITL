# Fase 15 — Día a día sobre la flota: plan

**Meta:** responder en segundos las preguntas de todos los días (¿dónde está esta MAC/IP?, ¿por dónde pasa este flujo?, ¿qué interfaces están mal?, ¿qué amaneció roto?, ¿cabe esta imagen?, ¿qué tengo instalado?) usando solo la evidencia que Patrol ya guardó. Cero red nueva.

**Flota:** por equipo (carpeta `<host>_<ip>`) y por comando, la salida más reciente entre todos los trabajos de `outputs/` (o de la carpeta dada con `--dir`). Cada resultado lleva la hora de su evidencia y la antigüedad; más de 24 h se marca DATO VIEJO.

## Arquitectura
- `internal/parse/iosxe` (ADR 0008): parsers de show a tipos de Go, sin dependencias internas. arp, mac address-table, dhcp snooping, ip route, ip cef, ntp status, inventory, interfaces status, dir, version, procesos cpu/memoria, show interfaces, ip interface brief, CDP, LLDP, etherchannel. Cada uno devuelve `ok=false` si no reconoce el formato.
- `internal/fleet`: carga (`Load`), `Find`, `Trace`, `Path` (+ SVG propio), `Health`, `Summary`, `Capacity`, `Inventory` (CSV/Markdown). No importa `analyze` ni `topo`.
- `api/proto/macuahuitl/v1/fleet.proto` → `internal/core/services_fleet.go` (registro de una línea) → `mctl` (`find`, `trace`, `path`, `health interfaces`, `fleet summary|flash|inventory`) → `ui/bridge/fleet.go` → pestaña Flota.
- Playbook `ios-xe/flota` (solo lectura; pasa `CheckDenied`).

## Decisiones
- Formato inesperado o comando rechazado: aviso visible y se ignora esa salida; nunca "sin resultados" disfrazado.
- Rastreo L2: sigue la MAC por CAM; un puerto con vecino CDP/LLDP (o port-channel con miembro con vecino) salta al vecino; sin vecino es acceso. Corta por bucle (equipo+puerto repetido), vecino sin evidencia, vecino sin la MAC, o 32 saltos.
- Camino L3: LPM sobre `show ip route` (o `show ip cef` si falta, con aviso); ECMP ramifica; el tramo L2 de cada salto usa el rastreo de la MAC del siguiente salto (ARP). Cortes marcados: sin ruta, sin evidencia del siguiente equipo, bucle, sin ARP del destino.
- CSV neutraliza fórmulas (`=+-@`) porque los datos vienen de la red.

## Pendientes / deuda
- Duplicación temporal: CDP/LLDP/port-channel/uptime/cpu/mem/interfaces existen también en `internal/topo` y `internal/analyze`; se unifican en el refactor del ADR 0008 (esos paquetes pasarían a consumir `internal/parse/iosxe`).
- Sin validar en laboratorio: todos los fixtures siguen la documentación pública de Cisco. NX-OS y otras plataformas quedan fuera.
- Cada consulta recarga `outputs/`; sin caché. Con paquetes muy grandes conviene un índice.
- Contadores de interfaz son acumulados; la comparación entre rondas sigue en `mctl diff`.
- El camino no modela VRF, PBR, ACL ni NAT; el rastreo no distingue VLANs permitidas en trunks.
- Evidencias de horas distintas entre saltos: un rastreo o camino puede mezclar tablas de rondas diferentes (el aviso solo marca cada hora); falta una advertencia cuando la diferencia entre saltos supera un umbral.
- Empate de vecinos: `resolve` compara por nombre corto y `owners[""]` puede colisionar; dos equipos con el mismo nombre corto (dominios distintos) o sin IP se confunden. Falta desempatar por IP de gestión y avisar del empate.
- `ParseIfStatus` corta por las columnas de la cabecera: nombres de puerto largos, columnas desplazadas o la columna Type ausente pueden desalinear Status/Vlan/Duplex; falta una validación de la fila contra la cabecera y un aviso cuando no cuadra.
- Carpetas de equipo: solo se reconoce `<host>_<ipv4>`; los equipos con IPv6 de gestión (Patrol sanea los dos puntos a `_`) no se cargan hasta definir cómo reconocerlos.
- Rutas recursivas con varias salidas ECMP siguen solo la primera (con aviso); VRF, PBR y NAT siguen sin modelarse (el camino lo avisa siempre).
