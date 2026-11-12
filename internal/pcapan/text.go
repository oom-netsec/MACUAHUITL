package pcapan

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// parseSNI extrae server_name de un ClientHello TLS. Devuelve "" si el registro
// no es un ClientHello completo o no trae la extensión; nunca lee fuera de rango.
func parseSNI(b []byte) string {
	if len(b) < 9 || b[0] != 0x16 || b[5] != 1 {
		return ""
	}
	p := b[9:] // tras cabecera de registro (5) y de handshake (4)
	need := func(n int) bool { return len(p) >= n }
	if !need(34) {
		return ""
	}
	p = p[34:] // versión + random
	if !need(1) {
		return ""
	}
	sid := int(p[0])
	if !need(1 + sid + 2) {
		return ""
	}
	p = p[1+sid:]
	cs := int(binary.BigEndian.Uint16(p))
	if !need(2 + cs + 1) {
		return ""
	}
	p = p[2+cs:]
	cm := int(p[0])
	if !need(1 + cm + 2) {
		return ""
	}
	p = p[1+cm:]
	extLen := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) > extLen {
		p = p[:extLen]
	}
	for len(p) >= 4 {
		typ, l := binary.BigEndian.Uint16(p), int(binary.BigEndian.Uint16(p[2:]))
		p = p[4:]
		if l > len(p) {
			return ""
		}
		if typ == 0 && l >= 5 {
			e := p[:l]
			nl := int(binary.BigEndian.Uint16(e[3:]))
			if e[2] == 0 && 5+nl <= len(e) {
				return string(e[5 : 5+nl])
			}
		}
		p = p[l:]
	}
	return ""
}

// Text es el resumen para leer en la terminal o guardar junto a la captura.
func (r Report) Text() string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("Captura: %s", r.File)
	w("Paquetes: %d · Bytes: %d · Duración: %s · Desde %s", r.Packets, r.Bytes, r.Duration.Round(time.Millisecond), r.Start.UTC().Format(time.RFC3339))
	for _, x := range r.Warnings {
		w("AVISO: %s", x)
	}
	if len(r.Neighbors) > 0 {
		w("\n== Vecinos (¿a dónde estoy conectado?)")
		for _, n := range r.Neighbors {
			w("  %s  %s  puerto %s  %s  gestión %s  vlan nativa %d", strings.ToUpper(n.Protocol), n.DeviceID, n.Port, n.Platform, n.MgmtIP, n.NativeVLAN)
		}
	}
	w("\n== TCP")
	w("  Handshakes completos: %d · RTT de handshake min/prom/máx: %s / %s / %s", r.TCP.Handshakes, r.TCP.HandshakeRTT.Min, r.TCP.HandshakeRTT.Avg, r.TCP.HandshakeRTT.Max)
	w("  Retransmisiones: %d · Ventana cero: %d", r.TCP.Retransmissions, r.TCP.ZeroWindow)
	if r.TCP.FailedHandshakesTotal > 0 {
		w("  SYN sin respuesta (%d):", r.TCP.FailedHandshakesTotal)
		for _, f := range r.TCP.FailedHandshakes {
			w("    %s → %s  (%d intentos)", f.Client, f.Server, f.Attempts)
		}
	}
	for _, f := range r.TCP.Resets {
		w("  RST: %s ↔ %s  (%d)", f.Client, f.Server, f.Count)
	}
	w("\n== DNS")
	w("  Consultas: %d · Respuestas: %d", r.DNS.Queries, r.DNS.Responses)
	for _, q := range r.DNS.Errors {
		w("  %s  %s %s  servidor %s", q.RCode, q.Name, q.Type, q.Server)
	}
	for _, q := range r.DNS.Slow {
		w("  LENTA %s  %s %s  servidor %s", q.Latency.Round(time.Millisecond), q.Name, q.Type, q.Server)
	}
	for _, q := range r.DNS.Unanswered {
		w("  SIN RESPUESTA  %s %s  servidor %s", q.Name, q.Type, q.Server)
	}
	if len(r.TLS) > 0 {
		w("\n== TLS (SNI)")
		for _, t := range r.TLS {
			w("  %s → %s  %s", t.Client, t.Server, t.SNI)
		}
	}
	if len(r.ICMP.Unreachable)+len(r.ICMP.TTLExceeded) > 0 {
		w("\n== ICMP")
		for _, e := range r.ICMP.Unreachable {
			w("  Inalcanzable (código %d): %s avisa que %s no se alcanza", e.Code, e.From, e.Target)
		}
		for _, e := range r.ICMP.TTLExceeded {
			w("  TTL excedido: %s hacia %s", e.From, e.Target)
		}
	}
	for _, c := range r.ARPConflicts {
		w("\n== CONFLICTO ARP: %s anunciada por %s", c.IP, strings.Join(c.MACs, ", "))
	}
	if r.Fragments > 0 {
		w("\nFragmentos IP: %d (revisa MTU o túneles)", r.Fragments)
	}
	w("\n== Conversaciones con más bytes")
	for _, c := range r.Conversations {
		w("  %-4s %s ↔ %s  %d paquetes  %d bytes", c.Proto, c.A, c.B, c.Packets, c.Bytes)
	}
	w("\n== Equipos con más tráfico")
	for _, t := range r.Talkers {
		w("  %s  %d paquetes  %d bytes", t.IP, t.Packets, t.Bytes)
	}
	return b.String()
}
