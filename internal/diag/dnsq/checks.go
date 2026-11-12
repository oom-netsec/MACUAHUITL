package dnsq

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Probe struct {
	Transport string
	BufSize   uint16
	RCode     string
	Size      int
	Truncated bool
	RTT       time.Duration
	Error     string `json:",omitempty"`
}

type TransportReport struct {
	Server          string
	Probes          []Probe
	TCPWorks        bool
	EDNS            bool
	UDP512Truncated bool
	Findings        []Finding
}

// CheckTransport prueba UDP sin EDNS, UDP con 1232 y 4096 bytes, y TCP: la falla
// clásica detrás de un firewall que bloquea fragmentos o TCP/53.
func CheckTransport(ctx context.Context, d Dialer, s Server, name string, o Options) TransportReport {
	rep := TransportReport{Server: s.String()}
	type variant struct {
		tr     string
		size   uint16
		noEDNS bool
	}
	for _, v := range []variant{{"udp", 512, true}, {"udp", 1232, false}, {"udp", 4096, false}, {"tcp", 4096, false}} {
		oo := o
		oo.BufSize, oo.NoEDNS, oo.DNSSEC = v.size, v.noEDNS, !v.noEDNS
		srv := s
		srv.Transport = v.tr
		p := Probe{Transport: v.tr, BufSize: v.size}
		r, rtt, size, err := exchange(ctx, d, srv, newMsg(name, dns.TypeANY, oo), oo)
		if err != nil {
			r, rtt, size, err = exchange(ctx, d, srv, newMsg(name, dns.TypeDNSKEY, oo), oo)
		}
		p.RTT = rtt
		if err != nil {
			p.Error = err.Error()
		} else {
			p.RCode, p.Size, p.Truncated = dns.RcodeToString[r.Rcode], size, r.Truncated
			if v.tr == "tcp" {
				rep.TCPWorks = true
			}
			if !v.noEDNS && r.IsEdns0() != nil {
				rep.EDNS = true
			}
			if v.noEDNS && r.Truncated {
				rep.UDP512Truncated = true
			}
			if v.tr == "udp" && v.size == 4096 && size > 1232 && !r.Truncated {
				rep.Findings = append(rep.Findings, Finding{"aviso", "fragmentacion", fmt.Sprintf("respuesta UDP de %d bytes: se fragmenta y muchos firewalls la descartan", size)})
			}
		}
		rep.Probes = append(rep.Probes, p)
	}
	if !rep.TCPWorks {
		rep.Findings = append(rep.Findings, Finding{"error", "tcp-bloqueado", "TCP/53 no responde: las respuestas grandes y DNSSEC fallarán"})
	}
	if !rep.EDNS {
		rep.Findings = append(rep.Findings, Finding{"info", "sin-edns", "el servidor no anuncia EDNS(0)"})
	}
	return rep
}

type HygieneOptions struct {
	ReverseServer *Server // nil = el mismo resolvedor
	DKIMSelector  string
}

type HygieneReport struct {
	Name     string
	Addrs    []string
	PTR      map[string][]string
	CNAMEs   []string
	Findings []Finding
}

// CheckHygiene revisa coherencia y correo: PTR contra A/AAAA, CNAME largos, TTL bajos, CAA, SPF, DMARC y DKIM.
func CheckHygiene(ctx context.Context, d Dialer, res Server, name string, h HygieneOptions, o Options) HygieneReport {
	name = dns.Fqdn(name)
	rep := HygieneReport{Name: name, PTR: map[string][]string{}}
	add := func(sev, code, detail string) { rep.Findings = append(rep.Findings, Finding{sev, code, detail}) }
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		a, err := Query(ctx, d, res, name, qt, o)
		if err != nil || a.msg == nil {
			continue
		}
		for _, rr := range a.msg.Answer {
			switch x := rr.(type) {
			case *dns.A:
				rep.Addrs = append(rep.Addrs, x.A.String())
			case *dns.AAAA:
				rep.Addrs = append(rep.Addrs, x.AAAA.String())
			case *dns.CNAME:
				if qt == dns.TypeA {
					rep.CNAMEs = append(rep.CNAMEs, x.Hdr.Name+" → "+x.Target)
				}
			}
			if rr.Header().Ttl < 60 && rr.Header().Rrtype != dns.TypeCNAME {
				add("aviso", "ttl-bajo", fmt.Sprintf("%s con TTL %d s", rr.Header().Name, rr.Header().Ttl))
			}
		}
	}
	if len(rep.CNAMEs) > 3 {
		add("aviso", "cname-larga", fmt.Sprintf("cadena de %d CNAME", len(rep.CNAMEs)))
	}
	rev := res
	if h.ReverseServer != nil {
		rev = *h.ReverseServer
	}
	for _, ip := range rep.Addrs {
		arpa, err := dns.ReverseAddr(ip)
		if err != nil {
			continue
		}
		a, err := Query(ctx, d, rev, arpa, dns.TypePTR, o)
		if err != nil || a.msg == nil || len(a.msg.Answer) == 0 {
			add("aviso", "sin-ptr", ip+" no tiene PTR")
			continue
		}
		confirmed := false
		for _, rr := range a.msg.Answer {
			p, ok := rr.(*dns.PTR)
			if !ok {
				continue
			}
			rep.PTR[ip] = append(rep.PTR[ip], p.Ptr)
			for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
				f, err := Query(ctx, d, res, p.Ptr, qt, o)
				if err != nil || f.msg == nil {
					continue
				}
				for _, rr2 := range f.msg.Answer {
					if (rr2.Header().Rrtype == dns.TypeA && rr2.(*dns.A).A.String() == ip) || (rr2.Header().Rrtype == dns.TypeAAAA && rr2.(*dns.AAAA).AAAA.String() == ip) {
						confirmed = true
					}
				}
			}
		}
		if !confirmed {
			add("aviso", "ptr-no-coincide", fmt.Sprintf("%s → PTR %v, pero ese nombre no resuelve de vuelta a %s", ip, rep.PTR[ip], ip))
		}
	}
	txt := func(n string) []string {
		a, err := Query(ctx, d, res, n, dns.TypeTXT, o)
		if err != nil || a.msg == nil {
			return nil
		}
		var out []string
		for _, rr := range a.msg.Answer {
			if t, ok := rr.(*dns.TXT); ok {
				out = append(out, strings.Join(t.Txt, ""))
			}
		}
		return out
	}
	var spf []string
	for _, t := range txt(name) {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			spf = append(spf, t)
		}
	}
	switch len(spf) {
	case 0:
		add("info", "sin-spf", "no hay registro SPF")
	case 1:
		add("info", "spf", spf[0])
	default:
		add("error", "spf-multiple", "hay varios SPF; los receptores lo tratan como error permanente")
	}
	dmarc := ""
	for _, t := range txt("_dmarc." + name) {
		if strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
			dmarc = t
		}
	}
	if dmarc == "" {
		add("aviso", "sin-dmarc", "no hay registro DMARC en _dmarc."+name)
	} else {
		add("info", "dmarc", dmarc)
	}
	if h.DKIMSelector != "" {
		k := h.DKIMSelector + "._domainkey." + name
		if v := txt(k); len(v) == 0 {
			add("aviso", "sin-dkim", "no hay llave DKIM en "+k)
		} else {
			add("info", "dkim", k)
		}
	}
	if a, err := Query(ctx, d, res, name, dns.TypeCAA, o); err == nil && a.msg != nil && len(a.msg.Answer) > 0 {
		var v []string
		for _, rr := range a.msg.Answer {
			if c, ok := rr.(*dns.CAA); ok {
				v = append(v, c.Tag+" "+c.Value)
			}
		}
		add("info", "caa", strings.Join(v, "; "))
	} else {
		add("info", "sin-caa", "sin CAA: cualquier autoridad puede emitir certificados para este nombre")
	}
	return rep
}

type ExposureReport struct {
	Server         string
	OpenResolver   bool
	NXDomainHijack bool
	Details        []string
}

// CheckExposure revisa si un servidor resuelve para cualquiera y si inventa respuestas para nombres inexistentes.
func CheckExposure(ctx context.Context, d Dialer, s Server, o Options) ExposureReport {
	rep := ExposureReport{Server: s.String()}
	oo := o
	oo.NoRecurse = false
	if a, err := Query(ctx, d, s, "example.com.", dns.TypeA, oo); err == nil && a.Flags.RA && a.RCode == "NOERROR" && len(a.Answer) > 0 {
		rep.OpenResolver = true
		rep.Details = append(rep.Details, "resuelve nombres ajenos con recursión: resolvedor abierto (riesgo de amplificación)")
	}
	b := make([]byte, 6)
	rand.Read(b)
	nx := "mcu-" + hex.EncodeToString(b) + ".invalid." // .invalid nunca existe (RFC 6761)
	if a, err := Query(ctx, d, s, nx, dns.TypeA, oo); err == nil && a.RCode == "NOERROR" && len(a.Answer) > 0 {
		rep.NXDomainHijack = true
		rep.Details = append(rep.Details, "responde con direcciones para un nombre que no puede existir: secuestro de NXDOMAIN")
	}
	return rep
}
