# Fase 12 — Visibilidad de la red durante un caso

**Goal:** Ver la red mientras se trabaja un caso: topología CDP/LLDP, SNMP (consultas, sondeo y traps), flujos (NetFlow/IPFIX/sFlow) y telemetría gNMI. Todo de solo lectura, expuesto por gRPC, `mctl` y la pestaña Visibilidad.

**Licencias:** gosnmp v1.47.0 (BSD-2-Clause), openconfig/gnmi v0.14.1 (Apache-2.0; solo `proto/gnmi` y `proto/gnmi_ext`, cuyos imports son grpc y protobuf, ya presentes). gopacket (BSD-3) ya estaba. goflow2 no se usa: decodificadores propios.

**Architecture:**
- `internal/topo`: lógica pura. Parsers de `show cdp neighbors detail`, `show lldp neighbors detail` (IOS-XE y NX-OS), `show spanning-tree`, `show etherchannel summary` / `show port-channel summary` y `show version`; arma el grafo, detecta problemas, calcula el dibujo (Fruchterman-Reingold determinista) y genera SVG sin scripts.
- `internal/diag/snmp`: Get, walk (GetNext) y bulkwalk (GetBulk), sondeo por perfiles con tasas, receptor de traps/informs. Nunca Set.
- `internal/diag/flows`: decodificadores NetFlow v5/v9, IPFIX y sFlow v5, agregador en memoria y escucha UDP.
- `internal/diag/gnmic`: Get y Subscribe (STREAM con SAMPLE u ON_CHANGE). Nunca Set.
- `internal/diag/listen`: reglas comunes de escucha (IP explícita, puerto ≥ 1024, 0.0.0.0 solo pedido).
- `internal/transport.Guard.Control(runID)`: filtro para `net.Dialer.Control`; gosnmp marca por su cuenta y el socket se corta antes de conectar si el destino no está autorizado (auditado como `egress.denied`).
- `VisibilityService` (`api/proto/macuahuitl/v1/visibility.proto`), `internal/core/services_visibility.go`, `cmd/mctl/visibility.go`, `ui/bridge/visibility.go`, `ui/frontend/src/modules/visibility`.

## Lo que hace cada herramienta

| Herramienta | CLI | UI (Visibilidad) |
|---|---|---|
| Topología | `mctl topo build TRABAJO\|CARPETA [--pcap ARCHIVO] [--svg ARCHIVO] [--json]` | Topología: dibujo, hallazgos, exportar SVG y JSON |
| SNMP | `mctl snmp get HOST OID... \| walk HOST OID [--bulk] \| poll HOST [--profile P]... --cred ID [-v 3 --auth SHA --priv AES]` | SNMP: Get, Walk y sondeo en vivo con tabla de interfaces |
| Traps | `mctl snmp traps listen [--addr IP:PUERTO] [--any] [--for S] [--save] [--v3-cred ID]` | Traps: escucha en vivo |
| Flujos | `mctl flows listen [--addr IP:PUERTO] [--any] [--for S] [--save] [--top N] [--every S]` | Flujos: top talkers, conversaciones, puertos, protocolos y exportadores en vivo |
| gNMI | `mctl gnmi get\|subscribe HOST RUTA... --cred ID [--ca CA.pem] [--mode sample\|on_change]` | gNMI: Get y suscripción en vivo |

**Topología.** Nodos: nombre, plataforma, IP de gestión, versión, VLAN donde es root STP. Aristas: interfaz local y remota (normalizadas a la abreviatura de IOS), fuente (cdp, lldp, pcap) y quién las reportó. Hallazgos: enlace visto de un solo lado (solo si ambos extremos se recolectaron), VLAN nativa distinta, duplex distinto (lo que anuncia cada lado), port-channel con miembros hacia vecinos distintos (aviso: legítimo con vPC/StackWise Virtual/MLAG). Fuentes: carpeta de salida de Patrol o un trabajo de la sesión, y/o un PCAP (reusa `pcapan`; el punto de captura es un nodo). Playbook nuevo `ios-xe/topologia`.

**SNMP.** v2c y v3 solo authPriv (SHA/SHA-2 + AES; MD5 y DES rechazados). Perfiles: `sistema` (system MIB), `interfaces` (IF-MIB ifXTable con contadores HC; ifTable de 32 bits si el agente no tiene ifXTable, con manejo de vuelta del contador), `cpu` (CISCO-PROCESS-MIB cpmCPUTotal5secRev/1minRev/5minRev), `memoria` (CISCO-MEMORY-POOL-MIB). Las tasas (b/s y % de uso) se calculan entre muestras; un contador de 64 bits que baja se toma como reinicio y no da tasa. Walk acotado a 50 000 valores.

**Traps.** v1, v2c y v3 (si se indica la credencial USM). Se nombran coldStart, warmStart, linkDown, linkUp, authenticationFailure; linkDown/linkUp con interfaz, estado y el motivo que agrega IOS (locIfReason). Los demás quedan con su OID y variables. Los inform v1/v2c se responden; los v3 no (exigiría que la app fuera motor autoritativo). Un paquete que no decodifica se reporta con error y hasta 512 bytes en hex; `recover` evita que gosnmp tumbe el receptor. La comunidad nunca se guarda ni se muestra.

**Flujos.** Un solo socket reconoce el formato por la versión. Plantillas v9/IPFIX por (exportador, source ID/dominio, ID), con límites de 1024 exportadores, 128 plantillas por exportador, 16 384 en total y 64 campos por plantilla (lo que excede se reporta como error del exportador); retiro de plantillas IPFIX; campos de enterprise y de largo variable se saltan. sFlow: muestras de flujo (normal y expandida) con cabecera cruda Ethernet/IPv4/IPv6, escaladas por la tasa de muestreo; contadores se saltan. Agregación con 100 000 claves por tabla (lo demás va a "(otros)"); archivo de flujos acotado a 512 MiB.

**gNMI.** TLS siempre verificado (CAs del sistema o CA propia en PEM); sin opción insegura. Usuario y contraseña como metadatos por RPC. gRPC con `passthrough:///` y el Dialer del EgressGuard. Rutas con claves (`/interfaces/interface[name=Gi1/0/1]/state/counters`). Puerto 9339 por defecto (IOS-XE); NX-OS suele usar 50051.

## Credenciales (bóveda)

Sin cambiar el formato de la bóveda: SNMP v2c → contraseña = comunidad; SNMP v3 → usuario, contraseña = llave de autenticación, enable = llave de privacidad; gNMI → usuario y contraseña. Los mensajes gRPC solo llevan `credential_id`; la auditoría nunca los secretos (pruebas lo verifican).

## Escuchas y redirección nftables

Los receptores escuchan en 127.0.0.1 por defecto (traps 1162, flujos 2055), con duración de 1 h por defecto y 24 h máximo, auditados al abrir y cerrar (`visibility.traps[.done]`, `visibility.flows[.done]`). Puertos < 1024 se rechazan (ADR 0004). Si un equipo no permite cambiar el puerto de traps (162), redirige en el host:

```sh
sudo nft add table ip macuahuitl
sudo nft 'add chain ip macuahuitl pre { type nat hook prerouting priority dstnat; }'
sudo nft add rule ip macuahuitl pre udp dport 162 redirect to :1162
# al terminar
sudo nft delete table ip macuahuitl
```

y escucha en la IP de la interfaz que recibe los traps (`--addr 10.0.0.5:1162`).

## Decisiones

1. Decodificadores de flujos propios en vez de goflow2: límites de plantillas a la vista, sin dependencias nuevas. Probados con paquetes armados a mano y 20 s de fuzzing sin pánicos.
2. gosnmp abre su socket; el gate es `Guard.Control`. Una prueba del núcleo quita el `Allow` y confirma que la consulta no sale.
3. El SVG lo genera el núcleo (un solo dibujo para CLI y UI); la UI lo muestra como `<img>` para que un nombre CDP manipulado no ejecute nada.
4. El agente SNMP falso vive en `internal/diag/snmp/snmptest` para que el núcleo y `mctl` lo usen sin importar `net`.
5. Errores de parámetros (`snmp.ErrInvalid`, `gnmic.ErrInvalid`) → InvalidArgument; los de red → Unavailable.

## Pendiente / sin validar

- Parsers de topología con salidas fieles a la documentación pública de Cisco, **sin validar en laboratorio** (fixtures en `internal/topo/testdata`). NX-OS solo con fixtures sueltos; no hay playbook NX-OS.
- Topología desde trabajos con `ZIP_POLICY_PER_ROUND`/`AT_END` y archivos sueltos borrados: solo lee `.txt`.
- gosnmp y los metadatos gRPC exigen `string`: la copia de la comunidad/llave vive en el heap lo que dura la ejecución.
- Inform v3 sin respuesta; traps v3 con engine ID arbitrario probados solo contra gosnmp.
- Exportar desde la UI usa enlaces `download` con `data:`; sin probar dentro de la ventana Wails real.
- NetFlow/IPFIX no se escalan por muestreo.
