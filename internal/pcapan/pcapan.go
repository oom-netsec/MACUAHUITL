// Package pcapan analiza capturas pcap/pcapng sin red ni privilegios: lee el
// archivo con pcapgo (Go puro, sin libpcap) y resume lo que un ingeniero TAC
// busca primero: conversaciones, problemas de TCP, DNS lento o fallido, SNI de
// TLS, ICMP, vecinos CDP/LLDP, conflictos ARP y fragmentación.
package pcapan

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

type Options struct {
	Top     int           // cuántos elementos por lista; 20 por defecto
	SlowDNS time.Duration // umbral de respuesta DNS lenta; 200 ms por defecto
	// MaxFlows acota cada tabla (conversaciones, hosts, TCP, DNS, ARP) para que una
	// captura de un escaneo no agote la memoria del núcleo; 200000 por defecto.
	MaxFlows int
}

type Report struct {
	File          string
	Packets       int
	Bytes         int
	Start, End    time.Time
	Duration      time.Duration
	Protocols     map[string]int
	Conversations []Conversation
	Talkers       []Talker
	TCP           TCPStats
	DNS           DNSStats
	TLS           []TLSHello
	ICMP          ICMPStats
	Neighbors     []Neighbor
	ARPConflicts  []ARPConflict
	Fragments     int
	Warnings      []string
}

type Conversation struct {
	Proto, A, B    string
	Packets, Bytes int
	First, Last    time.Time
}

type Talker struct {
	IP             string
	Packets, Bytes int
}

type FlowCount struct {
	Client, Server string
	Count          int
}

type FailedHandshake struct {
	Client, Server string
	Attempts       int
}

type RTTStats struct {
	Count         int
	Min, Max, Avg time.Duration
}

type TCPStats struct {
	Handshakes            int
	FailedHandshakes      []FailedHandshake
	FailedHandshakesTotal int
	Resets                []FlowCount
	Retransmissions       int
	ZeroWindow            int
	HandshakeRTT          RTTStats
	// Events son los RST y retransmisiones con su hora, para la línea de tiempo; hasta maxTCPEvents.
	Events []TCPEvent
}

type TCPEvent struct {
	At             time.Time
	Kind           string // rst, retransmision
	Client, Server string
}

// shortcut: solo los primeros 1000 eventos TCP con hora; los contadores siguen completos.
const maxTCPEvents = 1000

func (a *analyzer) event(at time.Time, kind string, k flowKey) {
	if len(a.r.TCP.Events) < maxTCPEvents {
		a.r.TCP.Events = append(a.r.TCP.Events, TCPEvent{At: at, Kind: kind, Client: k.src, Server: k.dst})
	}
}

type DNSQuery struct {
	Client, Server, Name, Type, RCode string
	Latency                           time.Duration
	At                                time.Time
}

type DNSStats struct {
	Queries, Responses int
	Unanswered         []DNSQuery
	Errors             []DNSQuery
	Slow               []DNSQuery
}

type TLSHello struct {
	Client, Server, SNI string
}

type ICMPEvent struct {
	From, Target string
	Code         int
	At           time.Time
}

type ICMPStats struct {
	Unreachable []ICMPEvent
	TTLExceeded []ICMPEvent
}

type Neighbor struct {
	Protocol, DeviceID, Port, Platform, MgmtIP, SrcMAC string
	NativeVLAN                                         uint16
}

type ARPConflict struct {
	IP   string
	MACs []string
}

// Analyze lee path (pcap o pcapng) y devuelve el reporte. Un archivo truncado
// devuelve lo que alcanzó a leer y un aviso; un archivo que no es captura es error.
func Analyze(ctx context.Context, path string, o Options) (Report, error) {
	if o.Top <= 0 {
		o.Top = 20
	}
	if o.MaxFlows <= 0 {
		o.MaxFlows = 200000
	}
	if o.SlowDNS <= 0 {
		o.SlowDNS = 200 * time.Millisecond
	}
	f, err := sys.OpenRegular(path)
	if err != nil {
		return Report{}, fmt.Errorf("pcapan: %w", err)
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 1<<20)
	magic, err := br.Peek(4)
	if err != nil {
		return Report{}, fmt.Errorf("pcapan: archivo vacío o ilegible: %w", err)
	}
	var next func() ([]byte, gopacket.CaptureInfo, error)
	var link layers.LinkType
	if magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a {
		r, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return Report{}, fmt.Errorf("pcapan: pcapng inválido: %w", err)
		}
		next, link = r.ReadPacketData, r.LinkType()
	} else {
		r, err := pcapgo.NewReader(br)
		if err != nil {
			return Report{}, fmt.Errorf("pcapan: no es un pcap/pcapng: %w", err)
		}
		next, link = r.ReadPacketData, r.LinkType()
	}
	a := newAnalyzer(o)
	a.r.File = path
	for {
		if a.r.Packets%1024 == 0 && ctx.Err() != nil {
			return a.finish(), ctx.Err()
		}
		data, ci, err := next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				a.r.Warnings = append(a.r.Warnings, fmt.Sprintf("archivo truncado tras %d paquetes; el reporte es parcial", a.r.Packets))
			} else {
				a.r.Warnings = append(a.r.Warnings, fmt.Sprintf("lectura interrumpida tras %d paquetes: %v", a.r.Packets, err))
			}
			break
		}
		a.packet(gopacket.NewPacket(data, link, gopacket.DecodeOptions{Lazy: true, NoCopy: true}), ci)
	}
	return a.finish(), nil
}

type flowKey struct{ src, dst string }

type tcpConn struct {
	client, server string
	synAt          time.Time
	synAcked       bool
	synCount       int
	seen           map[[2]uint32]bool // (seq, len) por dirección, para retransmisiones
}

type pendingDNS struct {
	q  DNSQuery
	at time.Time
}

type analyzer struct {
	o       Options
	r       Report
	convs   map[string]*Conversation
	talkers map[string]*Talker
	conns   map[flowKey]*tcpConn
	resets  map[flowKey]int
	rtts    []time.Duration
	dnsQ    map[string]*pendingDNS
	arp     map[string]map[string]bool
	neigh   map[string]bool
	seenAll int  // entradas de seen sumando todas las conexiones
	limited bool // alguna tabla llegó a MaxFlows
}

// room dice si una tabla con n entradas admite una llave nueva.
func (a *analyzer) room(n int) bool {
	if n < a.o.MaxFlows {
		return true
	}
	a.limited = true
	return false
}

func newAnalyzer(o Options) *analyzer {
	return &analyzer{o: o, r: Report{Protocols: map[string]int{}}, convs: map[string]*Conversation{}, talkers: map[string]*Talker{},
		conns: map[flowKey]*tcpConn{}, resets: map[flowKey]int{}, dnsQ: map[string]*pendingDNS{}, arp: map[string]map[string]bool{}, neigh: map[string]bool{}}
}

func ipString(b []byte) string {
	a, ok := netip.AddrFromSlice(b)
	if !ok {
		return "?"
	}
	return a.Unmap().String()
}

func hp(ip string, port uint16) string {
	return netip.AddrPortFrom(netip.MustParseAddr(ip), port).String()
}

func (a *analyzer) packet(p gopacket.Packet, ci gopacket.CaptureInfo) {
	r := &a.r
	r.Packets++
	r.Bytes += ci.Length
	if r.Start.IsZero() || ci.Timestamp.Before(r.Start) {
		r.Start = ci.Timestamp
	}
	if ci.Timestamp.After(r.End) {
		r.End = ci.Timestamp
	}
	now := ci.Timestamp

	if l := p.Layer(layers.LayerTypeCiscoDiscoveryInfo); l != nil {
		a.cdp(l.(*layers.CiscoDiscoveryInfo), p)
		r.Protocols["cdp"]++
		return
	}
	if l := p.Layer(layers.LayerTypeLinkLayerDiscovery); l != nil {
		a.lldp(l.(*layers.LinkLayerDiscovery), p.Layer(layers.LayerTypeLinkLayerDiscoveryInfo), p)
		r.Protocols["lldp"]++
		return
	}
	if l := p.Layer(layers.LayerTypeARP); l != nil {
		arp := l.(*layers.ARP)
		r.Protocols["arp"]++
		ip := ipString(arp.SourceProtAddress)
		if ip != "0.0.0.0" && ip != "?" {
			if a.arp[ip] == nil && a.room(len(a.arp)) {
				a.arp[ip] = map[string]bool{}
			}
			if m := a.arp[ip]; m != nil && len(m) < 16 {
				m[macString(arp.SourceHwAddress)] = true
			}
		}
		return
	}
	var src, dst string
	if l := p.Layer(layers.LayerTypeIPv4); l != nil {
		ip := l.(*layers.IPv4)
		src, dst = ipString(ip.SrcIP), ipString(ip.DstIP)
		if ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset > 0 {
			r.Fragments++
		}
		r.Protocols["ipv4"]++
	} else if l := p.Layer(layers.LayerTypeIPv6); l != nil {
		ip := l.(*layers.IPv6)
		src, dst = ipString(ip.SrcIP), ipString(ip.DstIP)
		r.Protocols["ipv6"]++
	} else {
		r.Protocols["otro"]++
		return
	}
	a.talker(src, ci.Length)
	a.talker(dst, ci.Length)

	if l := p.Layer(layers.LayerTypeICMPv4); l != nil {
		ic := l.(*layers.ICMPv4)
		r.Protocols["icmp"]++
		a.conv("icmp", src, dst, ci.Length, now)
		typ := ic.TypeCode.Type()
		if typ == layers.ICMPv4TypeDestinationUnreachable || typ == layers.ICMPv4TypeTimeExceeded {
			target := "?"
			if inner := gopacket.NewPacket(ic.Payload, layers.LayerTypeIPv4, gopacket.Lazy); inner != nil {
				if il := inner.Layer(layers.LayerTypeIPv4); il != nil {
					target = ipString(il.(*layers.IPv4).DstIP)
				}
			}
			ev := ICMPEvent{From: src, Target: target, Code: int(ic.TypeCode.Code()), At: now}
			if typ == layers.ICMPv4TypeDestinationUnreachable {
				r.ICMP.Unreachable = append(r.ICMP.Unreachable, ev)
			} else {
				r.ICMP.TTLExceeded = append(r.ICMP.TTLExceeded, ev)
			}
		}
		return
	}
	if l := p.Layer(layers.LayerTypeTCP); l != nil {
		a.tcp(l.(*layers.TCP), src, dst, ci.Length, now)
		return
	}
	if l := p.Layer(layers.LayerTypeUDP); l != nil {
		u := l.(*layers.UDP)
		r.Protocols["udp"]++
		s, d := hp(src, uint16(u.SrcPort)), hp(dst, uint16(u.DstPort))
		a.conv("udp", s, d, ci.Length, now)
		if dl := p.Layer(layers.LayerTypeDNS); dl != nil {
			a.dns(dl.(*layers.DNS), s, d, now)
		}
	}
}

func macString(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":")
}

func (a *analyzer) talker(ip string, n int) {
	t := a.talkers[ip]
	if t == nil {
		if !a.room(len(a.talkers)) {
			return
		}
		t = &Talker{IP: ip}
		a.talkers[ip] = t
	}
	t.Packets++
	t.Bytes += n
}

func (a *analyzer) conv(proto, x, y string, n int, at time.Time) {
	if y < x {
		x, y = y, x
	}
	k := proto + " " + x + " " + y
	c := a.convs[k]
	if c == nil {
		if !a.room(len(a.convs)) {
			return
		}
		c = &Conversation{Proto: proto, A: x, B: y, First: at}
		a.convs[k] = c
	}
	c.Packets++
	c.Bytes += n
	c.Last = at
}

// shortcut: hasta 100 000 segmentos recordados por conexión para detectar retransmisiones; subir si hay falsos negativos en capturas enormes.
const maxSeen = 100000

func (a *analyzer) tcp(t *layers.TCP, src, dst string, n int, now time.Time) {
	a.r.Protocols["tcp"]++
	s, d := hp(src, uint16(t.SrcPort)), hp(dst, uint16(t.DstPort))
	a.conv("tcp", s, d, n, now)
	if p := t.LayerPayload(); len(p) > 5 && p[0] == 0x16 && p[5] == 1 {
		if sni := parseSNI(p); sni != "" {
			a.r.Protocols["tls"]++
			a.r.TLS = append(a.r.TLS, TLSHello{Client: s, Server: d, SNI: sni})
		}
	}
	fwd, rev := flowKey{s, d}, flowKey{d, s}
	switch {
	case t.SYN && !t.ACK:
		c := a.conns[fwd]
		if c == nil {
			if !a.room(len(a.conns)) {
				return
			}
			c = &tcpConn{client: s, server: d, synAt: now, seen: map[[2]uint32]bool{}}
			a.conns[fwd] = c
		}
		c.synCount++
		return
	case t.SYN && t.ACK:
		if c := a.conns[rev]; c != nil && !c.synAcked {
			c.synAcked = true
			a.r.TCP.Handshakes++
			a.rtts = append(a.rtts, now.Sub(c.synAt))
		}
		return
	}
	if t.RST {
		k := a.orient(fwd)
		if a.resets[k] > 0 || a.room(len(a.resets)) {
			a.resets[k]++
		}
		a.event(now, "rst", k)
		return
	}
	if t.Window == 0 {
		a.r.TCP.ZeroWindow++
	}
	if pl := len(t.LayerPayload()); pl > 0 {
		c := a.conns[fwd]
		if c == nil {
			c = a.conns[rev]
		}
		if c == nil {
			if !a.room(len(a.conns)) {
				return
			}
			c = &tcpConn{client: s, server: d, synAcked: true, seen: map[[2]uint32]bool{}}
			a.conns[fwd] = c
		}
		k := [2]uint32{t.Seq, uint32(pl)}
		if s != c.client {
			k[1] |= 1 << 31 // dirección servidor→cliente en el mismo mapa
		}
		if c.seen[k] {
			a.r.TCP.Retransmissions++
			a.event(now, "retransmision", flowKey{c.client, c.server})
		} else if len(c.seen) < maxSeen && a.seenAll < 20*maxSeen {
			c.seen[k] = true
			a.seenAll++
		}
	}
}

// orient devuelve el flujo como (cliente, servidor) si se conoce la conexión.
func (a *analyzer) orient(k flowKey) flowKey {
	if c := a.conns[k]; c != nil {
		return flowKey{c.client, c.server}
	}
	if c := a.conns[flowKey{k.dst, k.src}]; c != nil {
		return flowKey{c.client, c.server}
	}
	return k
}

func (a *analyzer) dns(d *layers.DNS, s, dst string, now time.Time) {
	if len(d.Questions) == 0 {
		return
	}
	q := d.Questions[0]
	name, typ := string(q.Name), q.Type.String()
	if !d.QR {
		a.r.DNS.Queries++
		if !a.room(len(a.dnsQ)) {
			return
		}
		a.dnsQ[fmt.Sprintf("%s|%s|%d|%s|%s", s, dst, d.ID, name, typ)] = &pendingDNS{q: DNSQuery{Client: s, Server: dst, Name: name, Type: typ, At: now}, at: now}
		return
	}
	// La respuesta solo cuenta si coincide en origen, destino, ID y pregunta.
	k := fmt.Sprintf("%s|%s|%d|%s|%s", dst, s, d.ID, name, typ)
	p := a.dnsQ[k]
	if p == nil {
		return
	}
	delete(a.dnsQ, k)
	a.r.DNS.Responses++
	q2 := p.q
	q2.Latency = now.Sub(p.at)
	q2.RCode = rcodeName(d.ResponseCode)
	if d.ResponseCode != layers.DNSResponseCodeNoErr {
		a.r.DNS.Errors = append(a.r.DNS.Errors, q2)
	}
	if q2.Latency >= a.o.SlowDNS {
		a.r.DNS.Slow = append(a.r.DNS.Slow, q2)
	}
}

func rcodeName(c layers.DNSResponseCode) string {
	switch c {
	case layers.DNSResponseCodeNoErr:
		return "NOERROR"
	case layers.DNSResponseCodeNXDomain:
		return "NXDOMAIN"
	case layers.DNSResponseCodeServFail:
		return "SERVFAIL"
	case layers.DNSResponseCodeRefused:
		return "REFUSED"
	case layers.DNSResponseCodeFormErr:
		return "FORMERR"
	}
	return c.String()
}

func (a *analyzer) cdp(c *layers.CiscoDiscoveryInfo, p gopacket.Packet) {
	n := Neighbor{Protocol: "cdp", DeviceID: c.DeviceID, Port: c.PortID, Platform: c.Platform, NativeVLAN: c.NativeVLAN, SrcMAC: srcMAC(p)}
	if len(c.MgmtAddresses) > 0 {
		n.MgmtIP = c.MgmtAddresses[0].String()
	} else if len(c.Addresses) > 0 {
		n.MgmtIP = c.Addresses[0].String()
	}
	a.addNeighbor(n)
}

func (a *analyzer) lldp(l *layers.LinkLayerDiscovery, info gopacket.Layer, p gopacket.Packet) {
	n := Neighbor{Protocol: "lldp", Port: string(l.PortID.ID), SrcMAC: srcMAC(p)}
	if l.PortID.Subtype == layers.LLDPPortIDSubtypeMACAddr {
		n.Port = macString(l.PortID.ID)
	}
	if in, ok := info.(*layers.LinkLayerDiscoveryInfo); ok && in != nil {
		n.DeviceID, n.Platform = in.SysName, in.SysDescription
		if len(in.MgmtAddress.Address) > 0 {
			n.MgmtIP = ipString(in.MgmtAddress.Address)
		}
	}
	if n.DeviceID == "" {
		n.DeviceID = macString(l.ChassisID.ID)
	}
	a.addNeighbor(n)
}

func srcMAC(p gopacket.Packet) string {
	if l := p.Layer(layers.LayerTypeEthernet); l != nil {
		return macString(l.(*layers.Ethernet).SrcMAC)
	}
	return ""
}

func (a *analyzer) addNeighbor(n Neighbor) {
	k := n.Protocol + "|" + n.DeviceID + "|" + n.Port
	if a.neigh[k] {
		return
	}
	a.neigh[k] = true
	a.r.Neighbors = append(a.r.Neighbors, n)
}

func (a *analyzer) finish() Report {
	r := a.r
	if a.limited {
		r.Warnings = append(r.Warnings, fmt.Sprintf("la captura superó el límite de %d flujos por tabla; los conteos por flujo son parciales", a.o.MaxFlows))
	}
	r.Duration = r.End.Sub(r.Start)
	for _, c := range a.convs {
		r.Conversations = append(r.Conversations, *c)
	}
	sort.Slice(r.Conversations, func(i, j int) bool {
		if r.Conversations[i].Bytes != r.Conversations[j].Bytes {
			return r.Conversations[i].Bytes > r.Conversations[j].Bytes
		}
		return r.Conversations[i].A+r.Conversations[i].B < r.Conversations[j].A+r.Conversations[j].B
	})
	r.Conversations = top(r.Conversations, a.o.Top)
	for _, t := range a.talkers {
		r.Talkers = append(r.Talkers, *t)
	}
	sort.Slice(r.Talkers, func(i, j int) bool {
		if r.Talkers[i].Bytes != r.Talkers[j].Bytes {
			return r.Talkers[i].Bytes > r.Talkers[j].Bytes
		}
		return r.Talkers[i].IP < r.Talkers[j].IP
	})
	r.Talkers = top(r.Talkers, a.o.Top)
	for _, c := range a.conns {
		if c.synCount > 0 && !c.synAcked {
			r.TCP.FailedHandshakes = append(r.TCP.FailedHandshakes, FailedHandshake{Client: c.client, Server: c.server, Attempts: c.synCount})
		}
	}
	r.TCP.FailedHandshakesTotal = len(r.TCP.FailedHandshakes)
	sort.Slice(r.TCP.FailedHandshakes, func(i, j int) bool {
		x, y := r.TCP.FailedHandshakes[i], r.TCP.FailedHandshakes[j]
		if x.Attempts != y.Attempts {
			return x.Attempts > y.Attempts
		}
		return x.Client+x.Server < y.Client+y.Server
	})
	r.TCP.FailedHandshakes = top(r.TCP.FailedHandshakes, a.o.Top)
	for k, n := range a.resets {
		r.TCP.Resets = append(r.TCP.Resets, FlowCount{Client: k.src, Server: k.dst, Count: n})
	}
	sort.Slice(r.TCP.Resets, func(i, j int) bool { return r.TCP.Resets[i].Count > r.TCP.Resets[j].Count })
	r.TCP.Resets = top(r.TCP.Resets, a.o.Top)
	if len(a.rtts) > 0 {
		st := RTTStats{Count: len(a.rtts), Min: a.rtts[0], Max: a.rtts[0]}
		var sum time.Duration
		for _, d := range a.rtts {
			sum += d
			st.Min, st.Max = min(st.Min, d), max(st.Max, d)
		}
		st.Avg = sum / time.Duration(len(a.rtts))
		r.TCP.HandshakeRTT = st
	}
	for _, p := range a.dnsQ {
		r.DNS.Unanswered = append(r.DNS.Unanswered, p.q)
	}
	sort.Slice(r.DNS.Unanswered, func(i, j int) bool { return r.DNS.Unanswered[i].At.Before(r.DNS.Unanswered[j].At) })
	r.DNS.Unanswered = top(r.DNS.Unanswered, a.o.Top)
	sort.Slice(r.DNS.Slow, func(i, j int) bool { return r.DNS.Slow[i].Latency > r.DNS.Slow[j].Latency })
	r.DNS.Slow = top(r.DNS.Slow, a.o.Top)
	r.DNS.Errors = top(r.DNS.Errors, a.o.Top)
	for ip, macs := range a.arp {
		if len(macs) > 1 {
			c := ARPConflict{IP: ip}
			for m := range macs {
				c.MACs = append(c.MACs, m)
			}
			sort.Strings(c.MACs)
			r.ARPConflicts = append(r.ARPConflicts, c)
		}
	}
	sort.Slice(r.ARPConflicts, func(i, j int) bool { return r.ARPConflicts[i].IP < r.ARPConflicts[j].IP })
	return r
}

func top[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}
