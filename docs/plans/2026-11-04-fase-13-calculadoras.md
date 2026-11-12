# Fase 13 — Calculadoras de bolsillo: Plan e implementación

**Goal:** Calculadoras de direccionamiento, MTU/MSS, rendimiento TCP, QoS, óptica y selección de ruta BGP, con la lógica en Go y un solo camino (gRPC) para `mctl` y la UI.

**Licencias:** solo la librería estándar de Go (BSD-3). Ninguna dependencia nueva.

**Architecture:**
- `internal/calc`: cálculo puro, sin red, archivos ni estado. Usa `net/netip` (noegress lo considera inocuo). Cada resultado implementa `Report()` → tablas (`Table{Title, Head, Rows}`) y notas; así la presentación se define una vez y la UI y `mctl` la muestran igual.
- `api/proto/macuahuitl/v1/calc.proto`: `CalcService` con un RPC por calculadora; cada respuesta lleva `CalcResult{json, text, tables, notes}`. El JSON es el resultado tipado (para `--json` y scripts).
- `internal/core/services_calc.go`: `calcSvc{}` sin estado, como `aclSvc`. Errores de entrada → `InvalidArgument`.
- `cmd/mctl/calc.go`: `mctl calc subnet|vlsm|summarize|wildcard|ipv6|mtu|tcp|dscp|optics|bgp`, todos con `--json`.
- `ui/bridge/calc.go`: un solo método `Calc(kind, reqJSON)`; la UI manda la solicitud en protojson (camelCase), igual que `CreateJob`.
- `ui/frontend/src/modules/calc/CalcView.tsx`: pestaña "Calculadoras" con una subnavegación por calculadora, formularios con etiqueta, tablas con `caption` y `th scope`, región desplazable con nombre, resultados en `aria-live`.

## Qué hace cada calculadora

1. **Subred** — red, broadcast, rango usable, hosts, máscara, wildcard, clase y tipo (RFC 1918, CGNAT, documentación, multicast…). /31 (RFC 3021), /32, /127 (RFC 6164), /128 y /0 con su caso.
2. **VLSM** — de mayor a menor necesidad, alineado y sin traslapes; lo que no cabe se reporta y lo más chico sigue acomodándose; el espacio libre sale como prefijos exactos. IPv4 e IPv6.
3. **Sumarización** — la exacta (mínimo conjunto de prefijos sin direcciones ajenas) y la de una sola ruta, con cuántas direcciones ajenas arrastra.
4. **Wildcard** — conversión prefijo ↔ máscara ↔ wildcard; con dirección, qué cubre la entrada de ACL aunque la wildcard no sea contigua (por octeto, cuántas direcciones, primeros 16 prefijos equivalentes, bits de host que IOS descarta).
5. **IPv6** — abreviada (RFC 5952) y expandida, tipo, multicast de nodo solicitado, PTR, EUI-64 desde una MAC (cualquier notación) y la MAC escondida en una EUI-64.
6. **MTU/MSS** — pila de afuera hacia adentro: GRE, GRE+clave, ESP túnel/transporte, GETVPN (con TBAR opcional), NAT-T, VXLAN, MPLS×N, 802.1Q/QinQ, PPPoE, LISP. ESP exacto: lo cifrado (carga + 2) se alinea al bloque (16 en CBC, 8 en 3DES, 4 en GCM) y la alineación desperdiciada aparece en el desglose. En transporte la IP del paquete protegido queda fuera del cifrado. Da `ip mtu`, `ip tcp adjust-mss` (IPv4 o IPv6 interno) y la MTU física necesaria para 1500.
7. **TCP** — BDP, escala de ventana mínima, límite por ventana, techo de Mathis por pérdida y quién limita; notas que explican por qué un iperf3 de un flujo no llena el enlace (ventana, pérdida, hash por flujo en port-channel/ECMP, un núcleo).
8. **DSCP** — nombre, decimal, binario, ToS, precedencia, CoS y EXP (mapeo Cisco por defecto = 3 bits altos), clase RFC 4594 y descarte AF; búsqueda por cualquier campo.
9. **Óptica** — presupuesto (Tx − sensibilidad), pérdidas de fibra, conectores y empalmes, margen, Rx esperada, veredicto y atenuador si satura el receptor; conversión dBm ↔ mW.
10. **BGP** — algoritmo de IOS/IOS-XE paso a paso por pares (weight, local-pref, local, AS_PATH, origin, MED, eBGP/iBGP, IGP, la eBGP más antigua, router-ID/ORIGINATOR_ID, CLUSTER_LIST, vecino). `always-compare-med`, `deterministic-med` (agrupa por AS vecino) y multipath con `maximum-paths` y `as-path multipath-relax`.

## Decisiones

- **Sin auditoría** en `CalcService`: es cálculo sobre lo que escribe el ingeniero, igual que `aclSvc` (spec §13).
- **VLSM clásico en IPv4**: el bloque mínimo es /30 (resta red y broadcast); /31 se documenta en la info de subred pero VLSM no lo asigna solo.
- **802.1Q/QinQ en el enlace exterior no restan MTU IP** (la trama crece); solo restan dentro de un encapsulado L2 (después de VXLAN). Se explica en una nota.
- **Orden de llegada BGP**: la lista se toma como la muestra `show ip bgp` (la más nueva primero) y se compara por pares; por eso sin `deterministic-med` el ganador puede depender del orden, y la prueba lo demuestra.
- **Pérdidas ópticas típicas** (SMF 1310 0.35 dB/km, 1550 0.25, MMF 850 3.0, 1300 1.0; conector 0.5, empalme 0.1, margen 3 por defecto en CLI y UI). Se pueden reemplazar.
- El puente no importa `grpc` (noegress): el tipo de opción de llamada se infiere con un parámetro genérico.

## Sin validar en laboratorio

- Sobrecarga de GETVPN con TBAR (12 bytes de metadatos Cisco) tomada de la documentación pública.
- Selección BGP con confederaciones, AIGP, `bestpath med missing-as-worst`, `compare-routerid` y `med confed`: no se modelan.
- IPv6 como encapsulado exterior (GRE sobre IPv6, VXLAN sobre IPv6): no se modela; todas las cabeceras externas son IPv4.

## Pendientes

- Importar rutas BGP pegando la salida de `show ip bgp x.x.x.x`.
- VLSM con /31 opcional para enlaces punto a punto.
