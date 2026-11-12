package dnsq

import (
	"context"
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Hallazgos de la revisión final. La zona final publica KSK (coincide con el DS), ZSK y una llave intrusa; el
// RRset DNSKEY y la SOA están firmados SOLO por la llave intrusa (no anclada).
// Un validador real dice "bogus"; CheckDNSSEC no debería decir Secure.
func TestRogueKeySignsDNSKEY(t *testing.T) {
	l, roots, zones := hierarchy(t, true)
	ej := zones["ejemplo.lab."]
	rogue := &dns.DNSKEY{Hdr: dns.RR_Header{Name: ej.origin, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: 256, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	priv, err := rogue.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	ej.mu.Lock()
	kk := key(ej.origin, dns.TypeDNSKEY)
	ej.rrsets[kk] = append(ej.rrsets[kk], rogue)
	now := time.Now()
	ej.sigs = map[string][]dns.RR{}
	for k, set := range ej.rrsets {
		name := strings.SplitN(k, "|", 2)[0]
		typ := set[0].Header().Rrtype
		if ej.delegs[name] && typ != dns.TypeDS || (typ == dns.TypeA || typ == dns.TypeAAAA) && ej.isGlue(name) {
			continue
		}
		sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: set[0].Header().Ttl},
			TypeCovered: typ, Algorithm: rogue.Algorithm, Labels: uint8(dns.CountLabel(name)), OrigTtl: set[0].Header().Ttl,
			Expiration: uint32(now.Add(24 * time.Hour).Unix()), Inception: uint32(now.Add(-time.Hour).Unix()), KeyTag: rogue.KeyTag(), SignerName: ej.origin}
		if err := sig.Sign(priv.(crypto.Signer), set); err != nil {
			t.Fatal(err)
		}
		ej.sigs[k] = []dns.RR{sig}
	}
	ej.mu.Unlock()
	rep, err := CheckDNSSEC(context.Background(), l.dial, "ejemplo.lab", roots, []string{zones["."].ds()}, opts())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Secure=%v last link=%+v", rep.Secure, rep.Chain[len(rep.Chain)-1])
	if rep.Secure {
		t.Fatalf("BUG: cadena firmada por llave no anclada reportada como Secure")
	}
}

func TestCheckDNSSECHostnameNotApex(t *testing.T) {
	l, roots, zones := hierarchy(t, true)
	rep, err := CheckDNSSEC(context.Background(), l.dial, "www.ejemplo.lab", roots, []string{zones["."].ds()}, opts())
	if err != nil || !rep.Secure || len(rep.Chain) != 3 || rep.Chain[2].Zone != "ejemplo.lab." {
		t.Fatalf("err=%v rep=%+v", err, rep)
	}
}
