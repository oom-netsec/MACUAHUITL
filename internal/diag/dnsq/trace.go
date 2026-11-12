package dnsq

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Root es un servidor raíz (o el punto de partida de una traza en pruebas).
type Root struct{ Name, IP string }

// RootServers son las direcciones IPv4 de los 13 servidores raíz (root hints de IANA).
var RootServers = []Root{
	{"a.root-servers.net.", "198.41.0.4"}, {"b.root-servers.net.", "170.247.170.2"}, {"c.root-servers.net.", "192.33.4.12"},
	{"d.root-servers.net.", "199.7.91.13"}, {"e.root-servers.net.", "192.203.230.10"}, {"f.root-servers.net.", "192.5.5.241"},
	{"g.root-servers.net.", "192.112.36.4"}, {"h.root-servers.net.", "198.97.190.53"}, {"i.root-servers.net.", "192.36.148.17"},
	{"j.root-servers.net.", "192.58.128.30"}, {"k.root-servers.net.", "193.0.14.129"}, {"l.root-servers.net.", "199.7.83.42"},
	{"m.root-servers.net.", "202.12.27.33"},
}

// RootAnchors son los DS de las KSK de la raíz vigentes según data.iana.org/root-anchors (verificado 2026-11-04).
var RootAnchors = []string{
	". 172800 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
	". 172800 IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
}

// Step es una consulta de la traza a un servidor de la zona Zone.
type Step struct {
	Zone         string
	Server       string
	ServerIP     string
	RTT          time.Duration
	RCode        string
	AA           bool
	ReferralZone string
	Referral     []string
	Glue         map[string][]string
	Answer       []string
	Error        string `json:",omitempty"`
}

type TraceResult struct {
	Name, Type string
	Steps      []Step
	CNAMEs     []string
	Final      []string
	RCode      string
	Warnings   []string
}

const (
	maxSteps  = 40
	maxCNAME  = 8
	maxNSHops = 3
)

type nsAddr struct{ name, ip string }

// Trace resuelve name/qtype de forma iterativa desde roots, como dig +trace, y
// registra cada delegación con su glue y su tiempo.
func Trace(ctx context.Context, d Dialer, name string, qtype uint16, roots []Root, o Options) (TraceResult, error) {
	t := &tracer{ctx: ctx, d: d, roots: roots, o: o}
	t.o.NoRecurse = true
	res := TraceResult{Name: dns.Fqdn(name), Type: dns.TypeToString[qtype]}
	err := t.run(&res, dns.Fqdn(name), qtype, 0)
	return res, err
}

type tracer struct {
	ctx   context.Context
	d     Dialer
	roots []Root
	o     Options
	steps int
}

func (t *tracer) start() []nsAddr {
	var out []nsAddr
	for _, r := range t.roots {
		out = append(out, nsAddr{r.Name, r.IP})
	}
	return out
}

func (t *tracer) run(res *TraceResult, qname string, qtype uint16, nsDepth int) error {
	servers, zone := t.start(), "."
	seen := map[string]bool{}
	for {
		t.steps++
		if t.steps > maxSteps {
			return errors.New("dnsq: traza abortada: profundidad máxima alcanzada")
		}
		r, step, err := t.ask(servers, zone, qname, qtype)
		res.Steps = append(res.Steps, step)
		if err != nil {
			return err
		}
		// ¿Respuesta? (puede incluir CNAME)
		if len(r.Answer) > 0 {
			var final []string
			var cname string
			for _, rr := range r.Answer {
				h := rr.Header()
				if strings.EqualFold(h.Name, qname) && h.Rrtype == qtype {
					final = append(final, rr.String())
				}
				if c, ok := rr.(*dns.CNAME); ok && strings.EqualFold(h.Name, qname) && qtype != dns.TypeCNAME {
					cname = c.Target
				}
			}
			if len(final) > 0 {
				res.Final, res.RCode = final, dns.RcodeToString[r.Rcode]
				return nil
			}
			if cname != "" {
				res.CNAMEs = append(res.CNAMEs, qname+" → "+cname)
				if len(res.CNAMEs) > maxCNAME {
					return errors.New("dnsq: demasiados CNAME encadenados")
				}
				qname, servers, zone, seen = dns.Fqdn(cname), t.start(), ".", map[string]bool{}
				continue
			}
		}
		if r.Rcode == dns.RcodeNameError || (r.Authoritative && r.Rcode == dns.RcodeSuccess) {
			res.RCode = dns.RcodeToString[r.Rcode] // NXDOMAIN o NODATA autoritativo
			return nil
		}
		if r.Rcode != dns.RcodeSuccess {
			return fmt.Errorf("dnsq: %s respondió %s para %s", step.Server, dns.RcodeToString[r.Rcode], qname)
		}
		child, names, glue := referral(r)
		if child == "" {
			return fmt.Errorf("dnsq: %s no respondió ni delegó %s", step.Server, qname)
		}
		if !dns.IsSubDomain(zone, child) || strings.EqualFold(child, zone) && zone != "." || seen[child] {
			return fmt.Errorf("dnsq: bucle de delegación: %s vuelve a delegar %s", step.Server, child)
		}
		seen[child] = true
		next := []nsAddr{}
		for _, n := range names {
			for _, ip := range glue[n] {
				next = append(next, nsAddr{n, ip})
			}
		}
		if len(next) == 0 { // sin glue: hay que resolver el nombre del NS aparte
			if nsDepth >= maxNSHops {
				return fmt.Errorf("dnsq: no hay glue para %s y se alcanzó el límite de resoluciones de NS", child)
			}
			for _, n := range names {
				sub := TraceResult{}
				if err := t.run(&sub, n, dns.TypeA, nsDepth+1); err == nil {
					for _, f := range sub.Final {
						if rr, err := dns.NewRR(f); err == nil {
							if a, ok := rr.(*dns.A); ok {
								next = append(next, nsAddr{n, a.A.String()})
							}
						}
					}
				}
				if len(next) > 0 {
					break
				}
			}
			if len(next) == 0 {
				return fmt.Errorf("dnsq: no se pudo obtener la dirección de ningún NS de %s", child)
			}
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s se delega sin glue; se resolvió el NS aparte", child))
		}
		servers, zone = next, child
	}
}

// ask prueba los servidores de la zona en orden hasta que uno conteste.
func (t *tracer) ask(servers []nsAddr, zone, qname string, qtype uint16) (*dns.Msg, Step, error) {
	var lastErr error
	step := Step{Zone: zone}
	for _, s := range servers {
		srv := Server{Transport: "udp", Host: s.ip, Port: 53}
		r, rtt, _, err := exchange(t.ctx, t.d, srv, newMsg(qname, qtype, t.o), t.o)
		if err == nil && r.Truncated {
			srv.Transport = "tcp"
			r, rtt, _, err = exchange(t.ctx, t.d, srv, newMsg(qname, qtype, t.o), t.o)
		}
		step.Server, step.ServerIP = s.name, s.ip
		if err != nil {
			lastErr = err
			continue
		}
		step.RTT, step.RCode, step.AA = rtt, dns.RcodeToString[r.Rcode], r.Authoritative
		for _, rr := range r.Answer {
			step.Answer = append(step.Answer, rr.String())
		}
		step.ReferralZone, step.Referral, step.Glue = referral(r)
		return r, step, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("dnsq: no hay servidores para %s", zone)
	}
	step.Error = lastErr.Error()
	return nil, step, lastErr
}

// referral extrae la delegación: zona hija, nombres de NS y glue.
func referral(r *dns.Msg) (string, []string, map[string][]string) {
	if r.Authoritative && len(r.Answer) > 0 {
		return "", nil, nil
	}
	child := ""
	var names []string
	for _, rr := range r.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			child = strings.ToLower(ns.Hdr.Name)
			names = append(names, strings.ToLower(ns.Ns))
		}
	}
	glue := map[string][]string{}
	for _, rr := range r.Extra {
		switch g := rr.(type) {
		case *dns.A:
			glue[strings.ToLower(g.Hdr.Name)] = append(glue[strings.ToLower(g.Hdr.Name)], g.A.String())
		case *dns.AAAA:
			// shortcut: solo IPv4 para seguir la traza; el glue IPv6 se muestra pero no se usa.
		}
	}
	sort.Strings(names)
	return child, names, glue
}

// Finding es un hallazgo de diagnóstico.
type Finding struct {
	Severity string // error, aviso, info
	Code     string
	Detail   string
}

type ZoneServer struct {
	Name, IP string
	Serial   uint32
	AA       bool
	RTT      time.Duration
	AXFR     bool
	Error    string `json:",omitempty"`
}

type ZoneReport struct {
	Zone     string
	ParentNS []string
	ChildNS  []string
	Servers  []ZoneServer
	Findings []Finding
}

// CheckZone revisa la consistencia de los autoritativos de una zona: serial SOA,
// NS del padre contra los del hijo, servidores lame, glue y transferencia abierta.
func CheckZone(ctx context.Context, d Dialer, zone string, roots []Root, o Options) (ZoneReport, error) {
	zone = strings.ToLower(dns.Fqdn(zone))
	rep := ZoneReport{Zone: zone}
	tr, err := Trace(ctx, d, zone, dns.TypeNS, roots, o)
	if err != nil {
		return rep, err
	}
	glue := map[string][]string{}
	for _, s := range tr.Steps {
		if s.ReferralZone == zone {
			rep.ParentNS, glue = s.Referral, s.Glue
		}
	}
	for _, f := range tr.Final {
		if rr, err := dns.NewRR(f); err == nil {
			if ns, ok := rr.(*dns.NS); ok {
				rep.ChildNS = append(rep.ChildNS, strings.ToLower(ns.Ns))
			}
		}
	}
	sort.Strings(rep.ChildNS)
	if len(rep.ParentNS) == 0 {
		rep.Findings = append(rep.Findings, Finding{"error", "sin-delegacion", "el padre no delega la zona"})
		return rep, nil
	}
	if strings.Join(rep.ParentNS, ",") != strings.Join(rep.ChildNS, ",") {
		rep.Findings = append(rep.Findings, Finding{"aviso", "ns-padre-hijo", fmt.Sprintf("el padre anuncia %v y la zona anuncia %v", rep.ParentNS, rep.ChildNS)})
	}
	all := append(append([]string{}, rep.ParentNS...), rep.ChildNS...)
	sort.Strings(all)
	o2 := o
	o2.NoRecurse = true
	serials := map[uint32]bool{}
	seen := map[string]bool{}
	for _, name := range all {
		if seen[name] {
			continue
		}
		seen[name] = true
		ips := glue[name]
		if len(ips) == 0 {
			if dns.IsSubDomain(zone, name) {
				rep.Findings = append(rep.Findings, Finding{"error", "glue-faltante", name + " está dentro de la zona y el padre no da su dirección"})
			}
			sub, err := Trace(ctx, d, name, dns.TypeA, roots, o)
			if err == nil {
				for _, f := range sub.Final {
					if rr, err := dns.NewRR(f); err == nil {
						if a, ok := rr.(*dns.A); ok {
							ips = append(ips, a.A.String())
						}
					}
				}
			}
		}
		if len(ips) == 0 {
			rep.Servers = append(rep.Servers, ZoneServer{Name: name, Error: "sin dirección"})
			rep.Findings = append(rep.Findings, Finding{"error", "ns-sin-direccion", name})
			continue
		}
		for _, ip := range ips {
			zs := ZoneServer{Name: name, IP: ip}
			srv := Server{Transport: "udp", Host: ip, Port: 53}
			r, rtt, _, err := exchange(ctx, d, srv, newMsg(zone, dns.TypeSOA, o2), o2)
			zs.RTT = rtt
			switch {
			case err != nil:
				zs.Error = err.Error()
				rep.Findings = append(rep.Findings, Finding{"error", "ns-lame", fmt.Sprintf("%s (%s) no responde: %v", name, ip, err)})
			case r.Rcode != dns.RcodeSuccess || !r.Authoritative:
				zs.Error = dns.RcodeToString[r.Rcode]
				rep.Findings = append(rep.Findings, Finding{"error", "ns-lame", fmt.Sprintf("%s (%s) no es autoritativo para la zona (%s, AA=%v)", name, ip, dns.RcodeToString[r.Rcode], r.Authoritative)})
			default:
				zs.AA = true
				for _, rr := range r.Answer {
					if soa, ok := rr.(*dns.SOA); ok {
						zs.Serial = soa.Serial
						serials[soa.Serial] = true
					}
				}
				zs.AXFR = axfrOpen(ctx, d, ip, zone, o2)
				if zs.AXFR {
					rep.Findings = append(rep.Findings, Finding{"aviso", "axfr-abierto", fmt.Sprintf("%s (%s) entrega la zona completa por AXFR a cualquiera", name, ip)})
				}
			}
			rep.Servers = append(rep.Servers, zs)
		}
	}
	if len(serials) > 1 {
		var parts []string
		for _, s := range rep.Servers {
			if s.AA {
				parts = append(parts, fmt.Sprintf("%s=%d", s.Name, s.Serial))
			}
		}
		rep.Findings = append(rep.Findings, Finding{"aviso", "serial-distinto", "los autoritativos no están sincronizados: " + strings.Join(parts, ", ")})
	}
	return rep, nil
}

func axfrOpen(ctx context.Context, d Dialer, ip, zone string, o Options) bool {
	m := new(dns.Msg)
	m.SetAxfr(zone)
	r, _, _, err := exchange(ctx, d, Server{Transport: "tcp", Host: ip, Port: 53}, m, o)
	if err != nil || r.Rcode != dns.RcodeSuccess {
		return false
	}
	for _, rr := range r.Answer {
		if rr.Header().Rrtype == dns.TypeSOA {
			return true
		}
	}
	return false
}
