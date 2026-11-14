// Package flows es un colector temporal de NetFlow v5/v9, IPFIX y sFlow v5:
// decodifica, agrega en memoria con límites (top talkers, conversaciones,
// puertos, protocolos, exportadores) y opcionalmente guarda cada flujo.
//
// Decodificadores propios sobre la biblioteca estándar (y gopacket para la
// cabecera de paquete que trae sFlow) en vez de goflow2: así los límites de
// plantillas por exportador quedan a la vista y no se arrastran dependencias.
// NetFlow/IPFIX se reportan tal como los exporta el equipo (sin escalar por
// muestreo); sFlow se escala por su tasa de muestreo, como manda el estándar.
package flows

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Flow es un registro normalizado; Exporter es la IP del equipo que lo envió.
type Flow struct {
	Exporter         string
	Src, Dst         string
	SrcPort, DstPort uint16
	Proto            uint8
	Bytes, Packets   uint64
}

type tmplKey struct {
	exporter string
	version  uint16
	domain   uint32 // source ID (v9) u observation domain (IPFIX)
	id       uint16
}

type field struct{ ie, length uint16 }

type template struct {
	fields  []field
	options bool // plantillas de opciones: sus datos se saltan
}

// Decoder guarda las plantillas v9/IPFIX por exportador. Es seguro para uso concurrente.
type Decoder struct {
	MaxExporters int // 1024 por defecto
	MaxTemplates int // por exportador; 128 por defecto
	MaxTotal     int // entre todos los exportadores; 16384 por defecto
	total        int
	mu           sync.Mutex
	tmpl         map[tmplKey]template
	perExp       map[string]int
}

func NewDecoder() *Decoder {
	return &Decoder{MaxExporters: 1024, MaxTemplates: 128, MaxTotal: 16384, tmpl: map[tmplKey]template{}, perExp: map[string]int{}}
}

// Templates cuenta las plantillas guardadas de un exportador.
func (d *Decoder) Templates(exporter string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.perExp[exporter]
}

var errShort error = i18n.New("flows.err.short", nil)

func host(addr string) string {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap.Addr().Unmap().String()
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// Decode reconoce el formato por la versión. from es host:puerto del remitente.
func (d *Decoder) Decode(from string, b []byte) ([]Flow, error) {
	if len(b) < 4 {
		return nil, errShort
	}
	exp := host(from)
	switch v := binary.BigEndian.Uint16(b); {
	case v == 5:
		return decodeV5(exp, b)
	case v == 9 || v == 10:
		return d.decodeTemplated(exp, v, b)
	case v == 0 && binary.BigEndian.Uint32(b) == 5:
		return decodeSFlow(b)
	default:
		return nil, i18n.New("flows.err.version", i18n.A("version", v))
	}
}

func decodeV5(exp string, b []byte) ([]Flow, error) {
	if len(b) < 24 {
		return nil, errShort
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	if n > 30 || len(b) < 24+48*n {
		return nil, i18n.New("flows.err.v5", i18n.A("n", n, "bytes", len(b)))
	}
	out := make([]Flow, 0, n)
	for i := 0; i < n; i++ {
		r := b[24+48*i:]
		out = append(out, Flow{Exporter: exp, Src: netip.AddrFrom4([4]byte(r[0:4])).String(), Dst: netip.AddrFrom4([4]byte(r[4:8])).String(),
			Packets: uint64(binary.BigEndian.Uint32(r[16:])), Bytes: uint64(binary.BigEndian.Uint32(r[20:])),
			SrcPort: binary.BigEndian.Uint16(r[32:]), DstPort: binary.BigEndian.Uint16(r[34:]), Proto: r[38]})
	}
	return out, nil
}

func (d *Decoder) decodeTemplated(exp string, version uint16, b []byte) ([]Flow, error) {
	hdr := 20
	if version == 10 {
		hdr = 16
		if l := int(binary.BigEndian.Uint16(b[2:])); l < len(b) {
			b = b[:l] // IPFIX trae el largo total; lo que sobra no es del mensaje
		}
	}
	if len(b) < hdr {
		return nil, errShort
	}
	domain := binary.BigEndian.Uint32(b[hdr-4:])
	var out []Flow
	var missing int
	for rest := b[hdr:]; len(rest) >= 4; {
		id, l := binary.BigEndian.Uint16(rest), int(binary.BigEndian.Uint16(rest[2:]))
		if l < 4 || l > len(rest) {
			return out, i18n.New("flows.err.set", i18n.A("id", id, "length", l))
		}
		body := rest[4:l]
		rest = rest[l:]
		switch {
		case (version == 9 && id == 0) || (version == 10 && id == 2):
			if err := d.templates(exp, version, domain, body, false); err != nil {
				return out, err
			}
		case (version == 9 && id == 1) || (version == 10 && id == 3):
			if err := d.templates(exp, version, domain, body, true); err != nil {
				return out, err
			}
		case id >= 256:
			d.mu.Lock()
			t, ok := d.tmpl[tmplKey{exp, version, domain, id}]
			d.mu.Unlock()
			if !ok {
				missing++
				continue
			}
			if !t.options {
				out = append(out, records(exp, t, body)...)
			}
		}
	}
	if missing > 0 && len(out) == 0 {
		return out, i18n.New("flows.err.no_template", i18n.A("n", missing))
	}
	return out, nil
}

// maxFields acota cada plantilla; las de Cisco reales rondan 20-40 campos.
const maxFields = 64

func (d *Decoder) templates(exp string, version uint16, domain uint32, b []byte, options bool) error {
	for len(b) >= 4 {
		id, count := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		b = b[4:]
		if options {
			// v9: largo de alcance y de opciones en bytes; IPFIX: total de campos y cuántos son de alcance.
			if len(b) < 2 {
				return errShort
			}
			if version == 9 {
				count = (count + int(binary.BigEndian.Uint16(b))) / 4
			}
			b = b[2:]
		}
		if count == 0 {
			if version == 10 { // retiro de plantilla
				d.mu.Lock()
				if _, ok := d.tmpl[tmplKey{exp, version, domain, id}]; ok {
					delete(d.tmpl, tmplKey{exp, version, domain, id})
					d.perExp[exp]--
					d.total--
				}
				d.mu.Unlock()
			}
			return nil
		}
		if count > maxFields || id < 256 {
			return i18n.New("flows.err.template", i18n.A("id", id, "fields", count))
		}
		t := template{options: options}
		for i := 0; i < count; i++ {
			if len(b) < 4 {
				return errShort
			}
			f := field{binary.BigEndian.Uint16(b), binary.BigEndian.Uint16(b[2:])}
			b = b[4:]
			if version == 10 && f.ie&0x8000 != 0 {
				if len(b) < 4 {
					return errShort
				}
				b = b[4:] // número de enterprise: el campo se salta
				f.ie = 0
			}
			t.fields = append(t.fields, f)
		}
		if err := d.store(tmplKey{exp, version, domain, id}, t); err != nil {
			return err
		}
	}
	return nil
}

func (d *Decoder) store(k tmplKey, t template) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.tmpl[k]; ok {
		d.tmpl[k] = t
		return nil
	}
	if _, known := d.perExp[k.exporter]; !known && len(d.perExp) >= d.MaxExporters {
		return i18n.New("flows.err.max_exporters", i18n.A("max", d.MaxExporters, "exporter", k.exporter))
	}
	if d.total >= d.MaxTotal {
		return i18n.New("flows.err.max_total", i18n.A("max", d.MaxTotal, "exporter", k.exporter))
	}
	if d.perExp[k.exporter] >= d.MaxTemplates {
		return i18n.New("flows.err.max_templates", i18n.A("max", d.MaxTemplates, "exporter", k.exporter))
	}
	d.tmpl[k] = t
	d.perExp[k.exporter]++
	d.total++
	return nil
}

func uintBE(b []byte) uint64 {
	var v uint64
	for _, c := range b[:min(len(b), 8)] {
		v = v<<8 | uint64(c)
	}
	return v
}

// records recorre los registros de un set de datos; el relleno final se ignora.
func records(exp string, t template, b []byte) []Flow {
	var out []Flow
	for len(b) > 0 {
		f := Flow{Exporter: exp}
		rest, ok := b, true
		for _, fd := range t.fields {
			l := int(fd.length)
			if l == 65535 { // largo variable (IPFIX)
				if len(rest) < 1 {
					ok = false
					break
				}
				l, rest = int(rest[0]), rest[1:]
				if l == 255 {
					if len(rest) < 2 {
						ok = false
						break
					}
					l, rest = int(binary.BigEndian.Uint16(rest)), rest[2:]
				}
			}
			if l > len(rest) {
				ok = false
				break
			}
			v := rest[:l]
			rest = rest[l:]
			switch fd.ie {
			case 1:
				f.Bytes = uintBE(v)
			case 2:
				f.Packets = uintBE(v)
			case 4:
				f.Proto = uint8(uintBE(v))
			case 7:
				f.SrcPort = uint16(uintBE(v))
			case 11:
				f.DstPort = uint16(uintBE(v))
			case 8, 27:
				f.Src = ipString(v)
			case 12, 28:
				f.Dst = ipString(v)
			}
		}
		if !ok || len(rest) == len(b) {
			break // relleno o registro incompleto
		}
		b = rest
		if f.Src != "" || f.Dst != "" {
			out = append(out, f)
		}
	}
	return out
}

func ipString(b []byte) string {
	if a, ok := netip.AddrFromSlice(b); ok {
		return a.Unmap().String()
	}
	return ""
}

// decodeSFlow toma las muestras de flujo con cabecera de paquete cruda; contadores y demás se saltan.
func decodeSFlow(b []byte) ([]Flow, error) {
	r := reader{b: b[4:]}
	var agent []byte
	switch r.u32() {
	case 1:
		agent = r.bytes(4)
	case 2:
		agent = r.bytes(16)
	default:
		return nil, i18n.New("flows.err.sflow_agent", nil)
	}
	r.skip(12) // sub-agente, secuencia, uptime
	n := r.u32()
	if r.err != nil {
		return nil, r.err
	}
	exp := ipString(agent)
	var out []Flow
	for i := uint32(0); i < n && r.err == nil; i++ {
		format, body := r.u32(), r.bytes(int(r.u32()))
		if r.err != nil {
			break
		}
		if format != 1 && format != 3 { // solo flow_sample y expanded_flow_sample (enterprise 0)
			continue
		}
		s := reader{b: body}
		s.skip(4)
		if format == 3 {
			s.skip(8)
		} else {
			s.skip(4)
		}
		rate := uint64(s.u32())
		s.skip(8)
		if format == 3 {
			s.skip(16)
		} else {
			s.skip(8)
		}
		nrec := s.u32()
		for j := uint32(0); j < nrec && s.err == nil; j++ {
			rf, rb := s.u32(), s.bytes(int(s.u32()))
			if s.err != nil || rf != 1 {
				continue
			}
			if f, ok := rawHeader(rb, rate); ok {
				f.Exporter = exp
				out = append(out, f)
			}
		}
	}
	if r.err != nil {
		return out, i18n.Wrap("flows.err.sflow", r.err, nil)
	}
	return out, nil
}

func rawHeader(b []byte, rate uint64) (Flow, bool) {
	r := reader{b: b}
	proto, frame := r.u32(), uint64(r.u32())
	r.skip(4)
	hdr := r.bytes(int(r.u32()))
	if r.err != nil {
		return Flow{}, false
	}
	first := map[uint32]gopacket.LayerType{1: layers.LayerTypeEthernet, 11: layers.LayerTypeIPv4, 12: layers.LayerTypeIPv6}[proto]
	if first == 0 {
		return Flow{}, false
	}
	if rate == 0 {
		rate = 1
	}
	p := gopacket.NewPacket(hdr, first, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	f := Flow{Bytes: frame * rate, Packets: rate}
	switch ip := p.NetworkLayer().(type) {
	case *layers.IPv4:
		f.Src, f.Dst, f.Proto = ip.SrcIP.String(), ip.DstIP.String(), uint8(ip.Protocol)
	case *layers.IPv6:
		f.Src, f.Dst, f.Proto = ip.SrcIP.String(), ip.DstIP.String(), uint8(ip.NextHeader)
	default:
		return Flow{}, false
	}
	switch t := p.TransportLayer().(type) {
	case *layers.TCP:
		f.SrcPort, f.DstPort = uint16(t.SrcPort), uint16(t.DstPort)
	case *layers.UDP:
		f.SrcPort, f.DstPort = uint16(t.SrcPort), uint16(t.DstPort)
	}
	return f, true
}

// reader lee XDR (sFlow) sin pasarse del búfer: el primer error se queda.
type reader struct {
	b   []byte
	err error
}

func (r *reader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = errShort
		return nil
	}
	out := r.b[:n]
	r.b = r.b[min(len(r.b), (n+3)&^3):] // XDR rellena a múltiplos de 4
	return out
}

func (r *reader) u32() uint32 {
	b := r.bytes(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func (r *reader) skip(n int) { r.bytes(n) }
