package flows

import (
	"fmt"
	"sort"
	"sync"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Other agrupa lo que ya no cabe en una tabla llena.
const Other = "(otros)"

type Counter struct {
	Key                   string
	Bytes, Packets, Flows uint64
}

type ExporterStat struct {
	Exporter              string
	Bytes, Packets, Flows uint64
	Errors                uint64
}

type Snapshot struct {
	Flows, Bytes, Packets uint64
	Errors                uint64
	Talkers               []Counter // por IP, origen y destino
	Conversations         []Counter // par de IPs y protocolo, sin dirección
	Ports                 []Counter // protocolo/puerto de servicio (el menor de los dos)
	Protocols             []Counter
	Exporters             []ExporterStat
	LastError             string    `json:",omitempty"`
	LastErrorText         i18n.Text `json:"-"` // LastError como texto, para darlo en otro idioma
}

// Aggregator acumula en memoria; cada tabla guarda a lo más max claves.
type Aggregator struct {
	max                           int
	mu                            sync.Mutex
	flows, bytes, packets, errors uint64
	lastErr                       i18n.Text
	talkers, convs, ports, protos map[string]*Counter
	exporters                     map[string]*ExporterStat
}

func NewAggregator(max int) *Aggregator {
	return &Aggregator{max: max, talkers: map[string]*Counter{}, convs: map[string]*Counter{}, ports: map[string]*Counter{},
		protos: map[string]*Counter{}, exporters: map[string]*ExporterStat{}}
}

var protoNames = map[uint8]string{1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 51: "ah", 58: "icmpv6", 89: "ospf", 112: "vrrp", 132: "sctp"}

func protoName(p uint8) string {
	if n, ok := protoNames[p]; ok {
		return n
	}
	return fmt.Sprint(p)
}

func (a *Aggregator) bump(m map[string]*Counter, key string, f Flow) {
	c, ok := m[key]
	if !ok {
		if len(m) >= a.max {
			key = Other
		}
		if c, ok = m[key]; !ok {
			c = &Counter{Key: key}
			m[key] = c
		}
	}
	c.Bytes += f.Bytes
	c.Packets += f.Packets
	c.Flows++
}

func (a *Aggregator) Add(f Flow) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.flows++
	a.bytes += f.Bytes
	a.packets += f.Packets
	a.bump(a.talkers, f.Src, f)
	if f.Dst != f.Src {
		a.bump(a.talkers, f.Dst, f)
	}
	x, y := f.Src, f.Dst
	if y < x {
		x, y = y, x
	}
	pn := protoName(f.Proto)
	a.bump(a.convs, x+" ↔ "+y+" "+pn, f)
	if f.SrcPort != 0 || f.DstPort != 0 {
		port := f.DstPort
		if f.SrcPort != 0 && (f.DstPort == 0 || f.SrcPort < f.DstPort) {
			port = f.SrcPort
		}
		a.bump(a.ports, fmt.Sprintf("%s/%d", pn, port), f)
	}
	a.bump(a.protos, pn, f)
	e := a.exporter(f.Exporter)
	if e != nil {
		e.Bytes += f.Bytes
		e.Packets += f.Packets
		e.Flows++
	}
}

func (a *Aggregator) exporter(name string) *ExporterStat {
	e, ok := a.exporters[name]
	if !ok {
		if len(a.exporters) >= a.max {
			name = Other
		}
		if e, ok = a.exporters[name]; !ok {
			e = &ExporterStat{Exporter: name}
			a.exporters[name] = e
		}
	}
	return e
}

// Error cuenta un paquete que no se pudo decodificar.
func (a *Aggregator) Error(exporter string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.errors++
	a.lastErr = i18n.Join(": ", i18n.Lit(exporter, exporter), i18n.FromErr(err))
	a.exporter(exporter).Errors++
}

func top(m map[string]*Counter, n int) []Counter {
	out := make([]Counter, 0, len(m))
	for _, c := range m {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Key < out[j].Key
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// Localize da el último error en el idioma pedido (el resto del resumen son cifras y direcciones).
func (s Snapshot) Localize(loc string) Snapshot {
	if !s.LastErrorText.Empty() {
		s.LastError = s.LastErrorText.In(loc)
	}
	return s
}

func (a *Aggregator) Snapshot(n int) Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Snapshot{Flows: a.flows, Bytes: a.bytes, Packets: a.packets, Errors: a.errors, LastError: a.lastErr.In(i18n.Es), LastErrorText: a.lastErr,
		Talkers: top(a.talkers, n), Conversations: top(a.convs, n), Ports: top(a.ports, n), Protocols: top(a.protos, n)}
	for _, e := range a.exporters {
		s.Exporters = append(s.Exporters, *e)
	}
	sort.Slice(s.Exporters, func(i, j int) bool { return s.Exporters[i].Bytes > s.Exporters[j].Bytes })
	return s
}
