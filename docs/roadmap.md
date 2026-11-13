# Roadmap de MACUAHUITL

Misión: poner un TAC en la laptop de cada ingeniero, útil para **todo** el trabajo diario y no solo para leer. Flujo: **recolectar → buscar → analizar → correlacionar → cambiar con seguridad → reportar**.

Principios: local primero y auditado, secretos en la bóveda, sin falsos "todo bien", licencias permisivas y sin código privilegiado. Leer y analizar es libre. **Cambiar la red** se hace con el [modo de cambio asistido](adr/0007-modo-cambio-asistido.md): comando visible, confirmación, pre/post-check, reversa y auditoría.

## Ya construido (fases 0–14)

| Área | Qué hay |
|---|---|
| Base | Núcleo, bóveda, auditoría encadenada, Patrol IOS/IOS-XE, CLI y app (0–6) |
| Herramientas | Analizador PCAP, DNS ligero y profundo, inspector TLS, receptor syslog (7) |
| Análisis | 27 reglas, diff entre rondas, línea de tiempo correlacionada (9) |
| Campo | Consola serie, servidor TFTP/HTTP temporal, MD5/SHA-512 (10) |
| Cambios | Pre/post con semáforo, asistente de upgrade (verificación), plantillas doradas y hardening (11) |
| Visibilidad | Topología CDP/LLDP (SVG), SNMP y traps, NetFlow/IPFIX/sFlow, gNMI (12) |
| Calculadoras | Subredes/VLSM, MTU/MSS, TCP, QoS, óptica, selección de ruta BGP (13) |
| Seguridad | Probadores RADIUS/TACACS+, PKI de laboratorio, decodificador IKE/IPsec (14) |
| ACL | Importación, análisis (sombreadas, redundantes) y traducción IOS-XE/NX-OS/ASA (5) |

Las fases de abajo extienden esto; no lo rehacen.

## Prerrequisito transversal: evidencia real

Todo lo que lee salidas de equipos necesita transcripciones reales para validarse. Fuente: la [batería de laboratorio](plans/laboratorio-bateria-de-pruebas.md). Las **fases 2 y 3** (NX-OS, ASA y más plataformas) se desbloquean con lo mismo y son requisito de todo ítem que diga NX-OS o ASA.

## Fases

Cada fase es una rama y un PR, con su plan en `docs/plans/`, TDD, revisión independiente y como máximo 2–3 agentes a la vez. Primero va el día a día, porque se usa todos los días y se apoya en lo que Patrol ya recolecta.

### Fase 15 — Día a día: buscar y ver la flota
1. **Buscador global de IP, MAC o hostname**: cruza ARP, CAM, CDP/LLDP y DHCP snooping de toda la flota. Responde, por ejemplo: «Switch B, Gi0/1, VLAN 100, MAC tal, visto por última vez a tal hora».
2. **Rastreo de equipos por ARP y capa 2**: sigue la MAC salto a salto por las tablas CAM y los uplinks CDP/LLDP hasta el puerto de acceso real (descarta trunks y port-channels).
3. **Camino entre dos equipos**: dibuja el path L3 (rutas/CEF de cada salto) y L2 (VLAN, trunks, STP) entre origen y destino. Marca enlaces, interfaces y dónde se rompe si se rompe.
4. **Salud de interfaces**: solo las que tienen problema (CRC, input drops, runts, giants, err-disabled, duplex), ordenadas por gravedad.
5. **Tablero matutino de la flota**: CPU arriba de 80 %, NTP desincronizado, reinicios recientes, memoria y flash al límite, en 5 segundos al abrir la app.
6. **Espacio en flash y DRAM de toda la flota**: quién tiene lugar para una imagen o un respaldo y quién está al límite.
7. **Inventario exportable**: modelos, números de serie, versiones, módulos y SFP a CSV o Markdown.

### Fase 16 — Operación: ejecutar y configurar
1. **Modo de cambio asistido** (ADR 0007): primer entregable y base de todo lo que cambia la red.
2. **Ejecutor ad-hoc en lote**: elige N equipos y un comando; los resultados salen por equipo o en una tabla consolidada exportable. Los comandos de solo lectura corren directo; la configuración va por el modo asistido.
3. **Generador de snippets**: formularios para VLAN, trunk con excepciones, puerto de acceso, SVI/BVI, subinterfaz, port-channel y otros bloques frecuentes. Los aplica con el modo asistido en uno o varios equipos.
4. **Aprovisionamiento de puertos**: cambiar VLAN, descripción, shut/no shut o voz en puertos de acceso, con pre/post y reversa.
5. **Respaldo y restauración de configuraciones**: respaldo programado o bajo demanda; restaurar con diff previo y modo asistido.
6. **Drift diario de configuración**: cada ronda de Patrol se compara con la anterior y el diff sale resaltado (extiende el diff de la fase 9).
7. **Limpiador de configuraciones**: líneas vacías, orden, líneas huérfanas y comandos obsoletos antes de archivar o reusar.
8. **Rotación de credenciales en lote**: cambia contraseñas o llaves locales en la flota, verifica el acceso nuevo antes de cerrar y actualiza la bóveda.
9. **Terminal SSH multipestaña** con grabación de sesión (lo que devuelve el equipo) y auditoría, junto a la consola serie.

### Fase 17 — Forense de logs y fallas
1. **Analizador de crashinfo y core dumps** (IOS, IOS-XE; NX-OS tras la fase 2): motivo, tracebacks, proceso culpable y CPU.
2. **Base de conocimiento de mensajes Cisco**: traduce mnemónicos crípticos (`%PLATFORM-3-ELEMENT_WARNING`, `%SYS-2-MALLOCFAIL`) a causa y acción.
3. **Detector de flapping silencioso**: flaps de milisegundos que un SNMP de 5 minutos no ve.
4. **Syslog inteligente**: indexa en vivo, agrupa por patrón y resalta inestabilidad; alimenta la línea de tiempo.
5. **Filtro de debugs en vivo**: agrupa repetidos, oculta ruido y marca anomalías (desde consola, SSH o texto pegado).
6. **Fugas de memoria por proceso** entre rondas (BGP, OSPF, IS-IS).

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

## Paquetes de contenido por tecnología (en curso)

Los playbooks y scripts de cada tecnología se publican como paquetes `.mpack` firmados ([ADR 0010](adr/0010-paquetes-de-contenido.md)), y cada quien instala solo los que usa.

| Paquete | Estado |
|---|---|
| `oom/ios-xe` (switches y routers IOS-XE) | Publicado (v0.3.0; routers en 1.1.0, v0.3.1) |
| `oom/ios` (IOS clásico) | Publicado (v0.3.1), validado en 3560CX |
| `oom/wlc-9800` (Catalyst 9800 y EWC) | En main, sin release todavía (pide núcleo 0.4.0), validado en 9120 EWC |
| NX-OS, firewall (ASA/FTD), ACI, wireless AireOS, ISE, SD-Access | Pendientes |

También pendiente: selección por elemento, copia a «Mis scripts» y paquete personal de respaldo (fase 32b).

## Después de los paquetes: Windows y macOS

Empieza cuando estén todos los paquetes por tecnología. Hoy MACUAHUITL es solo para Linux. El núcleo y `mctl` (Go) y la app (Wails + React) son portables en su mayor parte; hay que adaptar lo propio de Linux. Primero Windows y después macOS.

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

Todo pasa por el modo de cambio asistido (ADR 0007), que se construye primero, en la fase 16.

| Función | Fase |
|---|---|
| Ejecutor en lote (configuración), snippets, aprovisionamiento, restauración, rotación de credenciales | 16 |
| Generador de tramas | 18 |
| Prueba de cable TDR | 20 |
| MOP ejecutado y rollback | 21 |
| Upgrade ejecutado | 22 |
| GIR | 23 |
| EEM temporal | 27 |
