# Fase 7 — Herramientas de red: Plan de implementación

**Goal:** Analizador PCAP, DNS ligero y profundo, inspector TLS y receptor syslog, todos en Go con librerías de licencia permisiva, expuestos por gRPC, `mctl` y la UI.

**Licencias:** gopacket (BSD-3), miekg/dns (BSD-3), librería estándar de Go (BSD-3). Nada GPL enlazado; herramientas externas solo por ejecución.

**Architecture:**
- `internal/pcapan`: lógica pura sobre archivos pcap/pcapng (`pcapgo`, sin libpcap ni cgo). Sin red.
- `internal/diag/dnsq`: consultas y diagnóstico DNS. Toda conexión sale por un `Dialer` que el núcleo arma sobre `EgressGuard`.
- `internal/diag/tlsinspect`: handshake TLS de solo lectura contra un host:puerto escrito por el ingeniero.
- `internal/diag/syslogd`: receptor UDP/TCP temporal que guarda lo recibido con hora exacta.
- `internal/transport.Guard` gana `DialNetwork` (tcp, udp) y una política por ejecución `AllowAnyOnPorts(runID, puertos)` para el DNS profundo.

**Spec:** `docs/architecture/2026-11-02-macuahuitl-architecture-design.md` §6.1 (destinos), §9 (diagnóstico), §11 (auditoría).

## Global Constraints

- Ningún secreto en estas herramientas; SNMP queda para otra fase.
- DNS ligero: solo los resolvedores escritos (o el del sistema). DNS profundo: se activa por ejecución, lista los servidores que contactará, y cada uno queda en auditoría (`dns.contact`).
- El receptor syslog escucha en un puerto alto (>1024) por defecto y en la interfaz que se elija; nunca en 0.0.0.0 sin pedirlo; tiene duración máxima.
- El inspector TLS nunca envía datos de aplicación: solo handshake.
- Toda salida se guarda bajo la carpeta de outputs con 0600 y nombre único.

## Review Focus

1. **PCAP truncado o corrupto** debe dar un reporte parcial con aviso, no panic. Test en Task 1.
2. **Respuesta DNS falsificada** (ID distinto, pregunta distinta, desde otra IP) se descarta. Test en Task 3.
3. **Delegación en bucle o profundidad excesiva** en la traza termina con error claro. Test en Task 4.
4. **Certificado vencido, autofirmado o con nombre que no coincide** se reporta, no aborta la inspección. Test en Task 5.
5. **Mensaje syslog gigante o binario** no tumba el receptor. Test en Task 6.

---

### Task 1: `internal/pcapan`
`func Analyze(path string, opts Options) (Report, error)`. Report: resumen (paquetes, bytes, duración, enlaces), protocolos, conversaciones y top talkers, TCP (handshakes fallidos, RST, retransmisiones, ventana cero, RTT de handshake), DNS (consultas, respuestas, tiempos, RCODE, sin respuesta), TLS (SNI), ICMP (inalcanzables, TTL excedido), CDP/LLDP (vecino, puerto, plataforma, VLAN nativa, IP de gestión), ARP (IP con varias MAC), fragmentos. Pruebas con pcaps generados en la prueba.

### Task 2: `Guard.DialNetwork` y política por puertos
`DialNetwork(ctx, runID, network, host, port)` para tcp y udp; `AllowAnyOnPorts(runID, []uint16)`; `onDeny` sigue auditando.

### Task 3: DNS ligero
`Query(ctx, d Dialer, server, name, qtype, opts) (Answer, error)` con UDP, reintento por TCP si viene truncado, DoT y DoH; `Compare(ctx, servers, name, qtype)`. Validación de ID, pregunta y origen de la respuesta.

### Task 4: DNS profundo
`Trace` iterativo desde raíz con glue y tiempos; `CheckZone` (SOA serial por NS, padre contra hijo, lame, glue, AXFR abierto); `CheckDNSSEC` (cadena DS/DNSKEY/RRSIG hasta raíz, vencimientos, NSEC/NSEC3); `CheckTransport` (UDP/TCP, truncamiento, búfer EDNS, fragmentación); `CheckHygiene` (PTR↔A, CNAME, TTL, CAA, SPF, DMARC, DKIM con selector); `Propagation` (resolvedores públicos elegidos). Pruebas con servidores DNS locales (`miekg/dns.Server`) que forman raíz, TLD y zona.

### Task 5: Inspector TLS
`Inspect(ctx, d Dialer, host, port, sni) (Report, error)`: versiones aceptadas, cifrado negociado, ALPN, cadena completa, vencimientos, SAN, verificación contra el sistema y contra el nombre. Pruebas con servidores TLS locales (válido, vencido, autofirmado, nombre equivocado).

### Task 6: Receptor syslog
`Listen(ctx, addr, proto, dur, out io.Writer, onMsg)`: RFC 3164 y 5424, límite de tamaño por mensaje, archivo con hora de recepción y origen.

### Task 7: Servicio, CLI y UI
`ToolsService` en el contrato gRPC (proto nuevo), auditoría de cada ejecución, `mctl pcap|dns|tls|syslog`, pestañas en la UI.
