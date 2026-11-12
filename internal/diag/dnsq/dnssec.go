package dnsq

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Link es un eslabón de la cadena DNSSEC: la zona, sus llaves y el DS que la ata a su padre.
type Link struct {
	Zone    string
	Server  string
	KeyTags []uint16
	DS      []string
	Valid   bool
	Expires time.Time // la firma verificada que vence primero
	Error   string    `json:",omitempty"`
}

type DNSSECReport struct {
	Zone     string
	Secure   bool // toda la cadena verificó hasta el ancla
	Unsigned bool // la zona o un padre no firma: resolución insegura, no inválida
	Chain    []Link
	Denial   string // NSEC, NSEC3 o ninguna
	Warnings []string
}

// CheckDNSSEC verifica la cadena de confianza desde la raíz hasta zone. anchors son
// DS en formato de zona; nil usa las anclas de IANA.
func CheckDNSSEC(ctx context.Context, d Dialer, zone string, roots []Root, anchors []string, o Options) (DNSSECReport, error) {
	zone = strings.ToLower(dns.Fqdn(zone))
	rep := DNSSECReport{Zone: zone}
	if anchors == nil {
		anchors = RootAnchors
	}
	var trust []*dns.DS
	for _, a := range anchors {
		rr, err := dns.NewRR(a)
		if err != nil {
			return rep, fmt.Errorf("dnsq: ancla inválida %q: %w", a, err)
		}
		if ds, ok := rr.(*dns.DS); ok {
			trust = append(trust, ds)
		}
	}
	tr, err := Trace(ctx, d, zone, dns.TypeSOA, roots, o)
	if err != nil {
		return rep, err
	}
	// Los cortes de zona reales entre la raíz y el nombre, en orden: www.ejemplo.lab
	// vive en ejemplo.lab, y un label sin delegación no es un eslabón de la cadena.
	server := map[string]string{} // zona → IP de un autoritativo
	var zones []string
	for _, s := range tr.Steps {
		if s.Error == "" && dns.IsSubDomain(s.Zone, zone) {
			if _, ok := server[s.Zone]; !ok {
				zones = append(zones, s.Zone)
			}
			server[s.Zone] = s.ServerIP
		}
	}
	sort.SliceStable(zones, func(i, j int) bool { return dns.CountLabel(zones[i]) < dns.CountLabel(zones[j]) })
	if len(zones) == 0 || zones[0] != "." {
		zones = append([]string{"."}, zones...)
	}
	last := zones[len(zones)-1]
	o2 := o
	o2.NoRecurse, o2.DNSSEC = true, true
	if o2.BufSize == 0 {
		o2.BufSize = 4096
	}
	now := o.now()
	var parentKeys []*dns.DNSKEY
	for i, z := range zones {
		link := Link{Zone: z, Server: server[z]}
		if link.Server == "" {
			link.Error = "no se encontró un servidor autoritativo en la traza"
			rep.Chain = append(rep.Chain, link)
			return rep, nil
		}
		keys, keySigs, err := fetch(ctx, d, link.Server, z, dns.TypeDNSKEY, o2)
		if err != nil {
			link.Error = err.Error()
			rep.Chain = append(rep.Chain, link)
			return rep, nil
		}
		var dnskeys []*dns.DNSKEY
		for _, rr := range keys {
			if k, ok := rr.(*dns.DNSKEY); ok {
				dnskeys = append(dnskeys, k)
				link.KeyTags = append(link.KeyTags, k.KeyTag())
			}
		}
		// DS: en la raíz son las anclas; en las demás, lo que publica el padre (firmado por el padre).
		var dsSet []*dns.DS
		if z == "." {
			dsSet = trust
		} else {
			parent := zones[i-1]
			ds, dsSigs, err := fetch(ctx, d, server[parent], z, dns.TypeDS, o2)
			if err != nil {
				link.Error = "DS del padre: " + err.Error()
				rep.Chain = append(rep.Chain, link)
				return rep, nil
			}
			if len(ds) == 0 {
				if len(dnskeys) == 0 {
					rep.Unsigned = true
					link.Error = "la zona no está firmada y el padre no publica DS (delegación insegura)"
				} else {
					link.Error = "la zona tiene llaves pero el padre no publica DS: la cadena se rompe aquí"
				}
				rep.Chain = append(rep.Chain, link)
				return rep, nil
			}
			if _, err := verify(ds, dsSigs, parentKeys, now); err != nil {
				link.Error = "firma del DS en el padre: " + err.Error()
				rep.Chain = append(rep.Chain, link)
				return rep, nil
			}
			for _, rr := range ds {
				if x, ok := rr.(*dns.DS); ok {
					dsSet = append(dsSet, x)
				}
			}
		}
		for _, x := range dsSet {
			link.DS = append(link.DS, fmt.Sprintf("%d %d %d", x.KeyTag, x.Algorithm, x.DigestType))
		}
		if len(dnskeys) == 0 {
			if z == "." {
				rep.Unsigned = true
				link.Error = "la raíz de esta traza no publica DNSKEY"
			} else {
				link.Error = "el padre publica DS pero la zona no tiene DNSKEY: la resolución validada falla"
			}
			rep.Chain = append(rep.Chain, link)
			return rep, nil
		}
		if !dsMatches(dsSet, dnskeys) {
			link.Error = "ninguna llave de la zona coincide con el DS (o con el ancla de confianza)"
			rep.Chain = append(rep.Chain, link)
			return rep, nil
		}
		// RFC 4035 §5.2: el RRset DNSKEY debe estar firmado por una llave que el DS ancla;
		// una firma de cualquier otra llave del propio RRset no prueba nada.
		var anchored []*dns.DNSKEY
		for _, k := range dnskeys {
			if dsMatches(dsSet, []*dns.DNSKEY{k}) {
				anchored = append(anchored, k)
			}
		}
		exp, err := verify(keys, keySigs, anchored, now)
		if err != nil {
			link.Error = "firma del DNSKEY: " + err.Error()
			rep.Chain = append(rep.Chain, link)
			return rep, nil
		}
		link.Valid, link.Expires = true, exp
		if exp.Sub(now) < 7*24*time.Hour {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("la firma del DNSKEY de %s vence el %s", z, exp.UTC().Format(time.RFC3339)))
		}
		// La firma de la SOA de la zona final dice si la ZSK firma de verdad.
		if z == last {
			soa, soaSigs, err := fetch(ctx, d, link.Server, z, dns.TypeSOA, o2)
			if err == nil {
				if e2, err := verify(soa, soaSigs, dnskeys, now); err != nil {
					link.Valid, link.Error = false, "firma de la SOA: "+err.Error()
				} else if e2.Before(link.Expires) {
					link.Expires = e2
				}
			}
			rep.Denial = denial(ctx, d, link.Server, z, o2)
		}
		rep.Chain = append(rep.Chain, link)
		parentKeys = dnskeys
		if !link.Valid {
			return rep, nil
		}
	}
	rep.Secure = true
	return rep, nil
}

// fetch pide name/qtype al servidor y separa el rrset de sus RRSIG.
func fetch(ctx context.Context, d Dialer, ip, name string, qtype uint16, o Options) ([]dns.RR, []*dns.RRSIG, error) {
	r, _, _, err := exchange(ctx, d, Server{Transport: "udp", Host: ip, Port: 53}, newMsg(name, qtype, o), o)
	if err == nil && r.Truncated {
		r, _, _, err = exchange(ctx, d, Server{Transport: "tcp", Host: ip, Port: 53}, newMsg(name, qtype, o), o)
	}
	if err != nil {
		return nil, nil, err
	}
	var set []dns.RR
	var sigs []*dns.RRSIG
	for _, rr := range append(r.Answer, r.Ns...) {
		if !strings.EqualFold(rr.Header().Name, name) {
			continue
		}
		if s, ok := rr.(*dns.RRSIG); ok {
			if s.TypeCovered == qtype {
				sigs = append(sigs, s)
			}
			continue
		}
		if rr.Header().Rrtype == qtype {
			set = append(set, rr)
		}
	}
	return set, sigs, nil
}

// verify comprueba que alguna firma vigente del rrset verifique con alguna llave.
func verify(set []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY, now time.Time) (time.Time, error) {
	if len(set) == 0 {
		return time.Time{}, fmt.Errorf("rrset vacío")
	}
	if len(sigs) == 0 {
		return time.Time{}, fmt.Errorf("sin RRSIG")
	}
	var last error = fmt.Errorf("ninguna llave verifica la firma")
	for _, s := range sigs {
		for _, k := range keys {
			if k.KeyTag() != s.KeyTag || k.Algorithm != s.Algorithm {
				continue
			}
			if err := s.Verify(k, set); err != nil {
				last = err
				continue
			}
			if !s.ValidityPeriod(now) {
				exp := time.Unix(int64(s.Expiration), 0)
				if now.After(exp) {
					last = fmt.Errorf("firma vencida el %s", exp.UTC().Format(time.RFC3339))
				} else {
					last = fmt.Errorf("firma aún no válida")
				}
				continue
			}
			return time.Unix(int64(s.Expiration), 0), nil
		}
	}
	return time.Time{}, last
}

func dsMatches(ds []*dns.DS, keys []*dns.DNSKEY) bool {
	for _, x := range ds {
		for _, k := range keys {
			if k.Flags&dns.SEP == 0 {
				continue
			}
			if c := k.ToDS(x.DigestType); c != nil && strings.EqualFold(c.Digest, x.Digest) && c.KeyTag == x.KeyTag {
				return true
			}
		}
	}
	return false
}

// denial pregunta un nombre inexistente y dice qué prueba de inexistencia usa la zona.
func denial(ctx context.Context, d Dialer, ip, zone string, o Options) string {
	r, _, _, err := exchange(ctx, d, Server{Transport: "udp", Host: ip, Port: 53}, newMsg("mcu-nx-7f3a."+zone, dns.TypeA, o), o)
	if err != nil {
		return "desconocido"
	}
	for _, rr := range r.Ns {
		switch rr.(type) {
		case *dns.NSEC3:
			return "NSEC3"
		case *dns.NSEC:
			return "NSEC"
		}
	}
	return "ninguna"
}
