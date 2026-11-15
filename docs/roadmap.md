# Roadmap de MACUAHUITL

Misión: poner un TAC en la laptop de cada ingeniero, útil para **todo** el trabajo diario y no solo para leer. Flujo: **recolectar → buscar → analizar → correlacionar → cambiar con seguridad → reportar**.

Principios: local primero y auditado, secretos en la bóveda, sin falsos "todo bien", licencias permisivas y sin código privilegiado. Leer y analizar es libre. **Cambiar la red** se hace con el [modo de cambio asistido](adr/0007-modo-cambio-asistido.md): comando visible, confirmación, pre/post-check, reversa y auditoría.

## Hecho hasta v0.6.5

| Área | Qué hay |
|---|---|
| Base | Núcleo, bóveda, auditoría encadenada, Patrol, CLI y app (fases 0–6) |
| Herramientas | Analizador PCAP, DNS ligero y profundo, inspector TLS, receptor syslog (7) |
| Análisis | 44 reglas, diff entre rondas, línea de tiempo correlacionada; en la app, «Análisis de trabajos» (9) |
| Campo y transferencias | Consola serie, servidores y clientes temporales TFTP/HTTP/FTP/SCP/SFTP, MD5/SHA-512 (10, 22a) |
| Cambios | Pre/post con semáforo, asistente de upgrade (verificación), plantillas doradas y hardening (11) |
| Visibilidad | Topología CDP/LLDP (SVG), SNMP y traps, NetFlow/IPFIX/sFlow, gNMI (12) |
| Calculadoras | Subredes/VLSM, MTU/MSS, TCP, QoS, óptica, selección de ruta BGP (13) |
| Seguridad | Probadores RADIUS/TACACS+, PKI de laboratorio, decodificador IKE/IPsec (14) |
| ACL | Importación, análisis (sombreadas, redundantes) y traducción IOS-XE/NX-OS/ASA (5) |
| Flota | Buscador global, rastreo L2, camino L3/L2, salud de interfaces, tablero matutino, flash/DRAM, inventario (15) |
| Operación | Modo de cambio asistido, lotes de solo lectura, snippets, aprovisionamiento de puertos, respaldo y restauración, drift, limpiador, rotación de credenciales, terminal SSH multipestaña y libreta de hosts (16) |
| Forense | Crashinfo, base de mensajes Cisco, flapping silencioso, patrones de syslog, filtro de debugs, fugas de memoria entre rondas (17) |
| Paquetes de contenido | 11 paquetes oficiales firmados (≈600 playbooks), vista previa de instalación, ocultar por elemento, paquete personal, releases `packs-AAAA-MM-DD`; un oficial aparta a un tercero que choca solo con confirmación ([ADR 0010](adr/0010-paquetes-de-contenido.md)) |
| Idioma | Inglés canónico en app, núcleo y `mctl`; español en Ajustes y con `--lang es` |
| Laboratorio | Corridas de solo lectura con `tools/labcheck` en 3560CX, 9120 EWC y Catalyst 9000v (DevNet) (v0.5.0), y en Cisco Modeling Labs: ASAv con failover A/S, Catalyst 8000v e IOSvL2 (v0.5.4); las 21 plantillas de escritura aplicadas, verificadas y revertidas en equipos de laboratorio, CML y el 3560CX (v0.5.4, v0.6.4) |
| Patrol y análisis | Cada comando corre una vez por equipo y ronda aunque lo pidan varios playbooks (v0.6.0); detecciones de routing (EIGRP, LDP, track, GLBP/VRRP, router-id OSPF duplicado, BGP sin prefijos), segmentos compartidos en la topología y diff entre rondas sin ruido (v0.6.1, v0.6.2) |
| Enmascarado y modo asistido | Enmascarado de lo citado, de `backup diff` y drift, de líneas negadas, de la terminal, los logs que citan comandos, el syslog y las abreviaturas, con aviso en la evidencia sin enmascarar (v0.5.2–v0.6.5); plantillas `snmp-trap-host` y `netflow-export`; las plantillas no cortan el puerto de la sesión y un error `%` desconocido detiene la aplicación; reversas pendientes en la app, también de rotación de credenciales; `change diff` y espera de captura; primer login de ASA detectado (v0.5.1–v0.6.5) |
| Robustez | App publicada con la etiqueta `production` de Wails; cada comando guarda como máximo 64 MiB (v0.6.5) |

## Lo que falta para 1.0.0

1. **Validación en laboratorio** de los paquetes con equipos reales, según el [runbook](plans/validacion-labs.md) y `tools/labcheck` (reporte por playbook). Hoy solo `oom/ios` está validado de punta a punta (3560CX); los comandos de `oom/wlc-9800` se revisaron en un 9120 EWC, los de `oom/ios-xe`, `oom/cat9k` y `oom/sda` en Catalyst 9000v (y `oom/ios-xe` también en Catalyst 8000v) y los de `oom/asa` en ASAv. Siguen `oom/wlc-9800` en un 9800 de chasis o 9800-CL, `oom/sda` en un fabric real, `oom/cat9k` en hardware físico (stack, StackWise Virtual, PoE), `oom/ios-xe` con nivel de licencia (crypto VPN, MPLS), `oom/asa` en multicontexto y cluster, `oom/nx-os` (DevNet) y las plataformas sin laboratorio todavía. Lo que falle se corrige en el paquete y se publica como release `packs-*`.
2. **Estabilidad**: cero hallazgos abiertos de severidad alta o media, suite completa y CI en verde sin pruebas intermitentes, e instalación limpia de los `.deb` y `.rpm` en una máquina nueva.
3. **Anuncio público** con el README y las capturas al día.

Lo que no esté en esa lista no bloquea 1.0.0: las fases de abajo siguen después.

## Prerrequisito transversal: evidencia real

Todo lo que lee salidas de equipos necesita transcripciones reales para validarse. Fuente: la [batería de laboratorio](plans/laboratorio-bateria-de-pruebas.md). Los paquetes de NX-OS, ASA y las demás plataformas ya están publicados con comandos de la documentación de Cisco; su validación con equipos reales es parte de lo que falta para 1.0.0.

## Fases

Cada fase es una rama y un PR, con su plan en `docs/plans/`, TDD, revisión independiente y como máximo 2–3 agentes a la vez.

Las fases 15 (flota), 16 (operación) y 17 (forense) ya están hechas (ver arriba). Las que siguen son posteriores a 1.0.0.

### Fase 18 — Motor PCAP L3/L7 y generador de tramas
1. **Streaming de capturas de varios GB** con memoria acotada y cancelación.
2. **Streams TCP**: latencia de handshake, retransmisiones por tramo, tormentas de RST y agotamiento de ventana.
3. **Generador de tramas L2/L3** (Ethernet/IP/UDP/TCP/GRE) para probar ACL, QoS y CoPP. Va por el modo asistido y requiere que el usuario otorgue la capacidad al binario (ADR 0004).
Con gopacket (BSD-3). tshark/Wireshark no se embeben (GPL).

### Fase 19 — Estado L2/L3 y mapa de red
1. **Depurador STP**: root e inestabilidad, puertos bloqueados y bucles potenciales.
2. **CEF/FIB y asimetría**: valida el camino de la fase 15 contra el plano de datos.
3. **VLANs y puertos huérfanos**: VLANs inexistentes, configuración legacy olvidada y puertos inactivos.
4. **SPOF y dominios de falla**: port-channels, HSRP/VRRP, stacks y fuentes («si cae este cable, aíslas el piso 3»).
5. **Mapa interactivo L2/L3** en React y **exportación a draw.io y Mermaid** (Visio vía draw.io).
6. **IPAM ligero**: IPs en uso por subred según ARP/DHCP, conflictos y direcciones libres.

### Fase 20 — Hardware y plataforma
1. **SFP y DOM**: potencias, temperatura, tendencia y degradación (conectores sucios, curvaturas) antes de los CRC. Archivos OTDR `.sor` si hay demanda.
2. **Prueba de cable** (`test cable-diagnostics tdr`) por el modo asistido, con lectura del resultado.
3. **PoE**: presupuesto por switch y puertos que no reciben potencia.
4. **TCAM y recursos de ASIC**: ACL, QoS, FIB y MRIB al 85 % o más, antes del descarte silencioso.
5. **Buffers y micro-ráfagas**: drops de cola y buffers compartidos.
6. **Requisitos de imagen y licencias**: DRAM/flash de la imagen elegida y estado de Smart Licensing.

### Fase 21 — Cambios con método
1. **Generador de MOP**: documento paso a paso desde los pre-checks, con comandos, riesgos, verificación y reversa; se ejecuta con el modo asistido.
2. **Rollback**: sugiere el script inverso ante una regresión y lo aplica con el modo asistido.
3. **Linter de configuración** (dry-run local) para IOS, IOS-XE y NX-OS antes de ejecutar.
4. **Políticas corporativas** en plantillas doradas: nombres, SNMP, NTP y logging.
5. **ACL Match Tracer**: dada una tupla (origen, destino, puerto, protocolo), qué línea permite o bloquea en IOS, NX-OS o ASA.

### Fase 22 — Upgrades y transferencias
1. **Servidores SFTP y FTP** (SCP si cabe) junto a TFTP/HTTP; carpeta cifrada de imágenes y respaldos.
2. **Repositorio de imágenes** con metadatos, hashes (agrega SHA-1/SHA-256) y compatibilidad probada.
3. **Pre-flight ampliado**: DRAM, licencias y flash en lote.
4. **Ejecución del upgrade** (copy, verify, boot, reload) por SSH o consola, en modo asistido, con progreso en vivo.
5. **Monitor de arranque por consola**: boot loops, archivo faltante, ROMMON.
6. **Post-checks automáticos** tras el reinicio (reusa pre/post).
7. **Servidor RADIUS/TACACS+ local** para validar AAA en campo.

### Fase 23 — Enrutamiento avanzado
1. **Validador de políticas L3**: route-maps, prefix-lists, as-path y redistribución mutua.
2. **Multicast**: PIM, IGMP, MSDP, fallas RPF y estados huérfanos.
3. **Convergencia y radio de impacto BGP** (PIC, Add-Paths, path hiding).
4. **GIR**: aislar y reinsertar un nodo (gshut, max-metric, overload bit) con el modo asistido.

### Fase 24 — MPLS, Segment Routing y VPN
1. **Continuidad de etiquetas LDP/SR (SR-MPLS/SRv6)** por FIB/LFIB.
2. **L2VPN/L3VPN**: simetría de RT/RD, VPLS y MP-BGP.
3. **EVPN-VXLAN y SD-Access**: rutas tipo 2, 3 y 5 y vínculos MAC-IP.
4. **Túneles IPsec/GRE/VXLAN** en una vista (ikedec + calculadora MTU + estado).

### Fase 25 — Diseño y resiliencia (modo CCDE)
1. **Simulador de dominios de falla**: RP primario, keepalive de StackWise/VSS/vPC, split-brain.
2. **What-if** antes de un mantenimiento.

### Fase 26 — Reportes y colaboración
1. **Empaquetador para TAC** con enmascarado de contraseñas, IPs públicas y datos del cliente, cifrado.
2. **Reporte forense de incidente** desde la línea de tiempo.
3. **Informe ejecutivo** en Markdown/PDF.
4. **Notas por equipo y por caso**, ligadas a la evidencia.
Se define junto con la **vista de líder** del [backlog](backlog.md).

### Fase 27 — Extensibilidad y telemetría
1. **Plugins en Starlark** (starlark-go, BSD-3) en sandbox. Python embebido descartado.
2. **Telemetría por modelos YANG** con tableros de alta resolución sobre gNMI.
3. **EEM temporal**: inyecta un applet de captura con retiro automático, por el modo asistido.

## Paquetes de contenido por tecnología

Los playbooks y scripts de cada tecnología se publican como paquetes `.mpack` firmados ([ADR 0010](adr/0010-paquetes-de-contenido.md)), y cada quien instala solo los que usa. Todos están publicados; van adjuntos a cada release de la app y a las releases `packs-*`:

| Paquete | Playbooks | Validación en laboratorio |
|---|---:|---|
| `oom/ios` (IOS clásico) | 52 | Validado (3560CX) |
| `oom/ios-xe` (switches y routers IOS-XE) | 69 | Comandos revisados en Catalyst 9000v (DevNet) y Catalyst 8000v (CML) |
| `oom/cat9k` (Catalyst 9000) | 55 | Comandos revisados en Catalyst 9000v (DevNet); stack, StackWise Virtual y PoE piden hardware físico |
| `oom/sda` (SD-Access) | 26 | Comandos revisados en Catalyst 9000v (DevNet) sin fabric; falta un fabric real |
| `oom/wlc-9800` (Catalyst 9800 y EWC) | 47 | Comandos revisados en un 9120 EWC (17.12.6a); falta un 9800 de chasis o 9800-CL |
| `oom/wlc-aireos` (AireOS) | 64 | Pendiente |
| `oom/nx-os` (Nexus) | 68 | Pendiente (DevNet NX-OS) |
| `oom/aci` (leaf y spine ACI) | 45 | Pendiente |
| `oom/asa` | 68 | Comandos revisados en ASAv (contexto único y failover A/S, CML); multicontexto y cluster pendientes |
| `oom/ftd` (Firepower Threat Defense) | 64 | Pendiente |
| `oom/ise` | 36 | Pendiente |

## Después de 1.0.0: Windows y macOS

Empieza después de 1.0.0 (decisión del dueño: primero Linux sin bugs ni vulnerabilidades). Hoy MACUAHUITL es solo para Linux. El núcleo y `mctl` (Go) y la app (Wails + React) son portables en su mayor parte; hay que adaptar lo propio de Linux. Primero Windows y después macOS.

1. **ADR de multiplataforma, antes de tocar código**: qué funciones pueden faltar al principio, cómo se instala y se firma en cada sistema y qué código queda por plataforma (como `internal/sys`).
2. **Piezas de Linux que se adaptan**:
   - el canal local entre núcleo y clientes (hoy socket Unix con `SO_PEERCRED`);
   - el endurecimiento de memoria de `internal/sys` (`mlock`, sin core dumps);
   - inhibir la suspensión (systemd-logind → `SetThreadExecutionState` / `IOPMAssertion`);
   - consola serie (`/dev/ttyUSB*` → `COMx` / `/dev/cu.*`);
   - redirección de los puertos 21/69 (hoy `nft`): el servidor sigue en puerto alto y se explica el equivalente de cada sistema (ADR 0004);
   - herramientas externas (`dumpcap`, `nmap`, `iperf3`, `tracepath`) y sus equivalentes;
   - arranque del núcleo (servicio de usuario systemd → tarea de inicio de sesión / LaunchAgent).
3. **Instaladores y firma**: en Windows, un instalador firmado con certificado de firma de código (SmartScreen depende además de la reputación del certificado); en macOS, un `.dmg` firmado con Developer ID y notarizado (Gatekeeper, cuenta de Apple Developer).
4. **CI y release** con runners de Windows y macOS: pruebas y artefactos de las tres plataformas en cada tag.

## Qué cambia la red y dónde

Todo pasa por el modo de cambio asistido (ADR 0007), construido en la fase 16.

| Función | Fase |
|---|---|
| Snippets en uno o varios equipos, aprovisionamiento de puertos, restauración, rotación de credenciales | 16 |
| Generador de tramas | 18 |
| Prueba de cable TDR | 20 |
| MOP ejecutado y rollback | 21 |
| Upgrade ejecutado | 22 |
| GIR | 23 |
| EEM temporal | 27 |
