package dnsq

import (
	"context"
	"crypto"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// zone es un servidor autoritativo en memoria: responde lo que tiene, delega
// subzonas con glue y, si está firmada, agrega RRSIG cuando la consulta trae DO.
type zone struct {
	mu        sync.RWMutex // las pruebas cambian la zona con el servidor ya respondiendo
	origin    string
	rrsets    map[string][]dns.RR // "nombre|tipo"
	sigs      map[string][]dns.RR
	delegs    map[string]bool // nombres de subzonas delegadas
	allowAXFR bool
	refuse    bool // servidor "lame": rechaza todo
	recursive bool // contesta cualquier nombre con RA (resolvedor abierto)
	hijack    bool // contesta A para nombres inexistentes (secuestro de NXDOMAIN)
	mismatch  bool // contesta con otra pregunta (respuesta falsa)
	truncUDP  bool // por UDP siempre marca TC
	keys      []*dns.DNSKEY
	privs     []crypto.Signer
}

func newZone(origin string) *zone {
	return &zone{origin: dns.Fqdn(origin), rrsets: map[string][]dns.RR{}, sigs: map[string][]dns.RR{}, delegs: map[string]bool{}}
}

func key(name string, t uint16) string {
	return strings.ToLower(dns.Fqdn(name)) + "|" + dns.TypeToString[t]
}

func (z *zone) add(lines ...string) *zone {
	z.mu.Lock()
	defer z.mu.Unlock()
	for _, l := range lines {
		rr, err := dns.NewRR(l)
		if err != nil {
			panic(fmt.Sprintf("%s: %v", l, err))
		}
		k := key(rr.Header().Name, rr.Header().Rrtype)
		z.rrsets[k] = append(z.rrsets[k], rr)
		if rr.Header().Rrtype == dns.TypeNS && !strings.EqualFold(dns.Fqdn(rr.Header().Name), z.origin) {
			z.delegs[strings.ToLower(dns.Fqdn(rr.Header().Name))] = true
		}
	}
	return z
}

// sign genera KSK y ZSK, publica DNSKEY y firma todos los rrsets autoritativos.
func (z *zone) sign(t *testing.T, inception, expiration time.Time) *zone {
	t.Helper()
	for _, flags := range []uint16{257, 256} {
		k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: z.origin, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: flags, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
		priv, err := k.Generate(256)
		if err != nil {
			t.Fatal(err)
		}
		z.mu.Lock()
		z.keys = append(z.keys, k)
		z.privs = append(z.privs, priv.(crypto.Signer))
		kk := key(z.origin, dns.TypeDNSKEY)
		z.rrsets[kk] = append(z.rrsets[kk], k)
		z.mu.Unlock()
	}
	z.resign(t, inception, expiration)
	return z
}

func (z *zone) resign(t *testing.T, inception, expiration time.Time) {
	t.Helper()
	z.mu.Lock()
	defer z.mu.Unlock()
	z.sigs = map[string][]dns.RR{}
	for k, set := range z.rrsets {
		name := strings.SplitN(k, "|", 2)[0]
		typ := set[0].Header().Rrtype
		if z.delegs[name] && typ != dns.TypeDS || (typ == dns.TypeA || typ == dns.TypeAAAA) && z.isGlue(name) {
			continue // NS de delegación y glue no se firman
		}
		ki := 1 // ZSK
		if typ == dns.TypeDNSKEY {
			ki = 0 // KSK firma el DNSKEY
		}
		sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: set[0].Header().Ttl},
			TypeCovered: typ, Algorithm: z.keys[ki].Algorithm, Labels: uint8(dns.CountLabel(name)), OrigTtl: set[0].Header().Ttl,
			Expiration: uint32(expiration.Unix()), Inception: uint32(inception.Unix()), KeyTag: z.keys[ki].KeyTag(), SignerName: z.origin}
		if err := sig.Sign(z.privs[ki], set); err != nil {
			t.Fatal(err)
		}
		z.sigs[k] = []dns.RR{sig}
	}
}

func (z *zone) isGlue(name string) bool {
	for d := range z.delegs {
		if dns.IsSubDomain(d, name) {
			return true
		}
	}
	return false
}

// ds devuelve el DS que el padre debe publicar para esta zona.
func (z *zone) ds() string {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.keys[0].ToDS(dns.SHA256).String()
}

func (z *zone) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	m := new(dns.Msg)
	m.SetReply(r)
	if z.refuse {
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	do := r.IsEdns0() != nil && r.IsEdns0().Do()
	if opt := r.IsEdns0(); opt != nil {
		m.SetEdns0(4096, do)
	}
	if z.mismatch {
		m.Question[0].Name = "otro.nombre."
		w.WriteMsg(m)
		return
	}
	if _, udp := w.RemoteAddr().(*net.UDPAddr); udp && z.truncUDP {
		m.Truncated = true
		w.WriteMsg(m)
		return
	}
	if q.Qtype == dns.TypeAXFR {
		if !z.allowAXFR {
			m.Rcode = dns.RcodeRefused
		} else {
			soa := z.rrsets[key(z.origin, dns.TypeSOA)]
			m.Answer = append(m.Answer, soa...)
			for k, set := range z.rrsets {
				if !strings.HasSuffix(k, "|SOA") {
					m.Answer = append(m.Answer, set...)
				}
			}
			m.Answer = append(m.Answer, soa...)
		}
		w.WriteMsg(m)
		return
	}
	name := strings.ToLower(q.Name)
	add := func(dst *[]dns.RR, k string) {
		*dst = append(*dst, z.rrsets[k]...)
		if do {
			*dst = append(*dst, z.sigs[k]...)
		}
	}
	if !dns.IsSubDomain(z.origin, name) {
		if z.recursive || z.hijack {
			m.RecursionAvailable = true
			rr, _ := dns.NewRR(name + " 60 IN A 192.0.2.66")
			m.Answer = append(m.Answer, rr)
		} else {
			m.Rcode = dns.RcodeRefused
		}
		w.WriteMsg(m)
		return
	}
	// Delegación: el nombre cae bajo una subzona delegada.
	for d := range z.delegs {
		if dns.IsSubDomain(d, name) && !(name == d && q.Qtype == dns.TypeDS) {
			m.Ns = append(m.Ns, z.rrsets[key(d, dns.TypeNS)]...)
			if do {
				add(&m.Ns, key(d, dns.TypeDS))
			}
			for _, ns := range z.rrsets[key(d, dns.TypeNS)] {
				target := ns.(*dns.NS).Ns
				m.Extra = append(m.Extra, z.rrsets[key(target, dns.TypeA)]...)
			}
			w.WriteMsg(m)
			return
		}
	}
	m.Authoritative = true
	if z.recursive {
		m.RecursionAvailable = true
	}
	k := key(name, q.Qtype)
	if len(z.rrsets[k]) > 0 {
		add(&m.Answer, k)
	} else if c := z.rrsets[key(name, dns.TypeCNAME)]; len(c) > 0 {
		add(&m.Answer, key(name, dns.TypeCNAME))
	} else {
		exists := false
		for kk := range z.rrsets {
			if strings.HasPrefix(kk, name+"|") {
				exists = true
			}
		}
		if !exists {
			if z.hijack {
				rr, _ := dns.NewRR(name + " 60 IN A 192.0.2.66")
				m.Answer = append(m.Answer, rr)
				w.WriteMsg(m)
				return
			}
			m.Rcode = dns.RcodeNameError
		}
		add(&m.Ns, key(z.origin, dns.TypeSOA))
	}
	w.WriteMsg(m)
}

// lab es una red DNS de juguete en 127.0.0.x con un mapa IP→puerto real.
type lab struct {
	mu    sync.Mutex
	ports map[string]uint16
}

func (l *lab) serve(t *testing.T, ip string, h dns.Handler) {
	t.Helper()
	pc, err := net.ListenPacket("udp", ip+":0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []*dns.Server{{PacketConn: pc, Handler: h}, {Listener: ln, Handler: h}} {
		go s.ActivateAndServe()
		t.Cleanup(func() { s.Shutdown() })
	}
	l.mu.Lock()
	l.ports[ip] = uint16(port)
	l.mu.Unlock()
}

// dial lleva el puerto 53 de cada IP del laboratorio a su puerto real.
func (l *lab) dial(ctx context.Context, network, host string, port uint16) (net.Conn, error) {
	l.mu.Lock()
	p, ok := l.ports[host]
	l.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("lab: %s no existe", host)
	}
	if port == 53 {
		port = p
	}
	var d net.Dialer
	return d.DialContext(ctx, network, fmt.Sprintf("%s:%d", host, port))
}

// hierarchy arma raíz (127.0.0.2) → lab. (127.0.0.3) → ejemplo.lab. (127.0.0.4).
// Con signed=true firma las tres zonas y publica los DS en cada padre.
func hierarchy(t *testing.T, signed bool) (*lab, []Root, map[string]*zone) {
	t.Helper()
	l := &lab{ports: map[string]uint16{}}
	root := newZone(".").add(". 86400 IN SOA a.root.lab. admin.lab. 1 7200 3600 1209600 300", ". 86400 IN NS a.root.lab.",
		"a.root.lab. 86400 IN A 127.0.0.2", "lab. 86400 IN NS ns1.lab.", "ns1.lab. 86400 IN A 127.0.0.3")
	tld := newZone("lab.").add("lab. 3600 IN SOA ns1.lab. admin.lab. 1 7200 3600 1209600 300", "lab. 3600 IN NS ns1.lab.",
		"ns1.lab. 3600 IN A 127.0.0.3", "ejemplo.lab. 3600 IN NS ns1.ejemplo.lab.", "ns1.ejemplo.lab. 3600 IN A 127.0.0.4")
	ej := newZone("ejemplo.lab.").add("ejemplo.lab. 300 IN SOA ns1.ejemplo.lab. admin.ejemplo.lab. 2026110401 7200 3600 1209600 300",
		"ejemplo.lab. 300 IN NS ns1.ejemplo.lab.", "ns1.ejemplo.lab. 300 IN A 127.0.0.4",
		"www.ejemplo.lab. 300 IN A 192.0.2.10", "alias.ejemplo.lab. 300 IN CNAME www.ejemplo.lab.",
		`ejemplo.lab. 300 IN TXT "v=spf1 ip4:192.0.2.0/24 -all"`, "ejemplo.lab. 300 IN CAA 0 issue \"letsencrypt.org\"")
	if signed {
		now := time.Now()
		ej.sign(t, now.Add(-time.Hour), now.Add(30*24*time.Hour))
		tld.add(ej.ds())
		tld.sign(t, now.Add(-time.Hour), now.Add(30*24*time.Hour))
		root.add(tld.ds())
		root.sign(t, now.Add(-time.Hour), now.Add(30*24*time.Hour))
	}
	l.serve(t, "127.0.0.2", root)
	l.serve(t, "127.0.0.3", tld)
	l.serve(t, "127.0.0.4", ej)
	return l, []Root{{Name: "a.root.lab.", IP: "127.0.0.2"}}, map[string]*zone{".": root, "lab.": tld, "ejemplo.lab.": ej}
}

func opts() Options { return Options{Timeout: 2 * time.Second} }
