package pcapan

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
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

// Section es un encabezado de sección del resumen, con su clave del catálogo (pcap.section.*) y sus argumentos.
type Section struct {
	Key  string
	Args i18n.Args
}

// Sections son los encabezados del resumen en el orden en que se imprimen (los de las secciones que aparecen).
func (r Report) Sections() []Section {
	var out []Section
	if len(r.Neighbors) > 0 {
		out = append(out, Section{Key: "pcap.section.neighbors"})
	}
	out = append(out, Section{Key: "pcap.section.tcp"}, Section{Key: "pcap.section.dns"})
	if len(r.TLS) > 0 {
		out = append(out, Section{Key: "pcap.section.tls"})
	}
	if len(r.ICMP.Unreachable)+len(r.ICMP.TTLExceeded) > 0 {
		out = append(out, Section{Key: "pcap.section.icmp"})
	}
	for _, c := range r.ARPConflicts {
		out = append(out, Section{Key: "pcap.section.arp_conflict", Args: i18n.A("ip", c.IP, "macs", strings.Join(c.MACs, ", "))})
	}
	return append(out, Section{Key: "pcap.section.conversations"}, Section{Key: "pcap.section.top_talkers"})
}

// Text es el resumen para leer en la terminal o guardar junto a la captura, en español.
func (r Report) Text() string { return r.TextIn(i18n.Es) }

// TextIn es el resumen en el idioma pedido; los valores (IPs, nombres, cifras) salen tal cual y con es es el
// texto de siempre.
func (r Report) TextIn(loc string) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	m := func(key string, kv ...any) string { return i18n.Msg(loc, key, i18n.A(kv...)) }
	head := func(key string, kv ...any) { w("\n== %s", m(key, kv...)) }
	w("%s", m("pcap.text.file", "file", r.File))
	w("%s", m("pcap.text.summary", "packets", r.Packets, "bytes", r.Bytes, "duration", r.Duration.Round(time.Millisecond), "start", r.Start.UTC().Format(time.RFC3339)))
	for i, x := range r.Warnings {
		if i < len(r.WarnItems) {
			x = r.WarnItems[i].In(loc)
		}
		w("%s", m("pcap.text.warning", "message", x))
	}
	if len(r.Neighbors) > 0 {
		head("pcap.section.neighbors")
		for _, n := range r.Neighbors {
			w("  %s", m("pcap.text.neighbor", "protocol", strings.ToUpper(n.Protocol), "device", n.DeviceID, "port", n.Port, "platform", n.Platform, "mgmt", n.MgmtIP, "vlan", n.NativeVLAN))
		}
	}
	head("pcap.section.tcp")
	w("  %s", m("pcap.text.handshakes", "n", r.TCP.Handshakes, "min", r.TCP.HandshakeRTT.Min, "avg", r.TCP.HandshakeRTT.Avg, "max", r.TCP.HandshakeRTT.Max))
	w("  %s", m("pcap.text.retransmits", "retransmissions", r.TCP.Retransmissions, "zero_window", r.TCP.ZeroWindow))
	if r.TCP.FailedHandshakesTotal > 0 {
		w("  %s", m("pcap.text.failed_syn", "n", r.TCP.FailedHandshakesTotal))
		for _, f := range r.TCP.FailedHandshakes {
			w("    %s", m("pcap.text.failed_flow", "client", f.Client, "server", f.Server, "attempts", f.Attempts))
		}
	}
	for _, f := range r.TCP.Resets {
		w("  %s", m("pcap.text.reset", "client", f.Client, "server", f.Server, "count", f.Count))
	}
	head("pcap.section.dns")
	w("  %s", m("pcap.text.dns_counts", "queries", r.DNS.Queries, "responses", r.DNS.Responses))
	for _, q := range r.DNS.Errors {
		w("  %s", m("pcap.text.dns_error", "rcode", q.RCode, "name", q.Name, "type", q.Type, "server", q.Server))
	}
	for _, q := range r.DNS.Slow {
		w("  %s", m("pcap.text.dns_slow", "latency", q.Latency.Round(time.Millisecond), "name", q.Name, "type", q.Type, "server", q.Server))
	}
	for _, q := range r.DNS.Unanswered {
		w("  %s", m("pcap.text.dns_unanswered", "name", q.Name, "type", q.Type, "server", q.Server))
	}
	if len(r.TLS) > 0 {
		head("pcap.section.tls")
		for _, t := range r.TLS {
			w("  %s → %s  %s", t.Client, t.Server, t.SNI)
		}
	}
	if len(r.ICMP.Unreachable)+len(r.ICMP.TTLExceeded) > 0 {
		head("pcap.section.icmp")
		for _, e := range r.ICMP.Unreachable {
			w("  %s", m("pcap.text.icmp_unreach", "code", e.Code, "from", e.From, "target", e.Target))
		}
		for _, e := range r.ICMP.TTLExceeded {
			w("  %s", m("pcap.text.icmp_ttl", "from", e.From, "target", e.Target))
		}
	}
	for _, c := range r.ARPConflicts {
		head("pcap.section.arp_conflict", "ip", c.IP, "macs", strings.Join(c.MACs, ", "))
	}
	if r.Fragments > 0 {
		w("\n%s", m("pcap.text.fragments", "n", r.Fragments))
	}
	head("pcap.section.conversations")
	for _, c := range r.Conversations {
		w("  %-4s %s ↔ %s  %s", c.Proto, c.A, c.B, m("pcap.text.counts", "packets", c.Packets, "bytes", c.Bytes))
	}
	head("pcap.section.top_talkers")
	for _, t := range r.Talkers {
		w("  %s  %s", t.IP, m("pcap.text.counts", "packets", t.Packets, "bytes", t.Bytes))
	}
	return b.String()
}
