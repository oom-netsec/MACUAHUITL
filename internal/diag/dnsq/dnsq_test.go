package dnsq

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseServer(t *testing.T) {
	cases := map[string]Server{
		"192.0.2.1":                        {Transport: "udp", Host: "192.0.2.1", Port: 53},
		"tcp://192.0.2.1":                  {Transport: "tcp", Host: "192.0.2.1", Port: 53},
		"tls://1.1.1.1#cloudflare-dns.com": {Transport: "dot", Host: "1.1.1.1", Port: 853, TLSName: "cloudflare-dns.com"},
		"https://dns.google/dns-query":     {Transport: "doh", Host: "dns.google", Port: 443, TLSName: "dns.google", Path: "/dns-query"},
		"[2001:db8::53]:5353":              {Transport: "udp", Host: "2001:db8::53", Port: 5353},
	}
	for in, want := range cases {
		got, err := ParseServer(in)
		if err != nil || got != want {
			t.Errorf("ParseServer(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "-x", "ftp://a", "tls://1.1.1.1", "1.1.1.1:0", "a b"} {
		if _, err := ParseServer(bad); err == nil {
			t.Errorf("ParseServer(%q) accepted", bad)
		}
	}
}

func TestQueryAuthoritative(t *testing.T) {
	l, _, _ := hierarchy(t, false)
	a, err := Query(context.Background(), l.dial, Server{Transport: "udp", Host: "127.0.0.4", Port: 53}, "www.ejemplo.lab", dns.TypeA, opts())
	if err != nil || a.RCode != "NOERROR" || !a.Flags.AA || len(a.Answer) != 1 || !strings.Contains(a.Answer[0], "192.0.2.10") || a.RTT <= 0 {
		t.Fatalf("a=%+v err=%v", a, err)
	}
}

func TestQueryFallsBackToTCPWhenTruncated(t *testing.T) {
	l := &lab{ports: map[string]uint16{}}
	z := newZone("t.lab.").add("t.lab. 60 IN A 192.0.2.1")
	z.truncUDP = true
	l.serve(t, "127.0.0.20", z)
	a, err := Query(context.Background(), l.dial, Server{Transport: "udp", Host: "127.0.0.20", Port: 53}, "t.lab", dns.TypeA, opts())
	if err != nil || !a.Truncated || !a.RetriedTCP || len(a.Answer) != 1 {
		t.Fatalf("a=%+v err=%v", a, err)
	}
}

func TestQueryRejectsMismatchedQuestion(t *testing.T) {
	l := &lab{ports: map[string]uint16{}}
	z := newZone("m.lab.").add("m.lab. 60 IN A 192.0.2.1")
	z.mismatch = true
	l.serve(t, "127.0.0.21", z)
	if _, err := Query(context.Background(), l.dial, Server{Transport: "udp", Host: "127.0.0.21", Port: 53}, "m.lab", dns.TypeA, opts()); err == nil || !strings.Contains(err.Error(), "pregunta") {
		t.Fatalf("spoofed answer accepted: %v", err)
	}
}

func TestCompare(t *testing.T) {
	l, _, _ := hierarchy(t, false)
	other := newZone("ejemplo.lab.").add("www.ejemplo.lab. 300 IN A 192.0.2.99")
	l.serve(t, "127.0.0.22", other)
	c := Compare(context.Background(), l.dial, []Server{{Transport: "udp", Host: "127.0.0.4", Port: 53}, {Transport: "udp", Host: "127.0.0.22", Port: 53}}, "www.ejemplo.lab", dns.TypeA, opts())
	if len(c.Answers) != 2 || c.Consistent {
		t.Fatalf("compare = %+v", c)
	}
}

func TestTraceFromRoot(t *testing.T) {
	l, roots, _ := hierarchy(t, false)
	tr, err := Trace(context.Background(), l.dial, "www.ejemplo.lab", dns.TypeA, roots, opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Steps) != 3 || tr.Steps[0].Zone != "." || tr.Steps[1].Zone != "lab." || tr.Steps[2].Zone != "ejemplo.lab." {
		t.Fatalf("steps = %+v", tr.Steps)
	}
	if len(tr.Final) != 1 || !strings.Contains(tr.Final[0], "192.0.2.10") || !tr.Steps[2].AA {
		t.Fatalf("final = %+v", tr.Final)
	}
	if len(tr.Steps[0].Referral) != 1 || tr.Steps[0].Referral[0] != "ns1.lab." || tr.Steps[0].Glue["ns1.lab."][0] != "127.0.0.3" {
		t.Fatalf("referral = %+v", tr.Steps[0])
	}
}

func TestTraceFollowsCNAME(t *testing.T) {
	l, roots, _ := hierarchy(t, false)
	tr, err := Trace(context.Background(), l.dial, "alias.ejemplo.lab", dns.TypeA, roots, opts())
	if err != nil || len(tr.Final) == 0 || !strings.Contains(strings.Join(tr.Final, " "), "192.0.2.10") || len(tr.CNAMEs) != 1 {
		t.Fatalf("tr=%+v err=%v", tr, err)
	}
}

func TestTraceDetectsLoop(t *testing.T) {
	l := &lab{ports: map[string]uint16{}}
	root := newZone(".").add(". 60 IN SOA a.root.lab. x. 1 1 1 1 1", "lab. 60 IN NS ns1.lab.", "ns1.lab. 60 IN A 127.0.0.30")
	// lab. vuelve a delegar lab. a sí misma: bucle.
	tld := newZone(".").add("lab. 60 IN NS ns1.lab.", "ns1.lab. 60 IN A 127.0.0.30")
	l.serve(t, "127.0.0.29", root)
	l.serve(t, "127.0.0.30", tld)
	_, err := Trace(context.Background(), l.dial, "x.lab", dns.TypeA, []Root{{Name: "a.", IP: "127.0.0.29"}}, opts())
	if err == nil || !strings.Contains(err.Error(), "bucle") && !strings.Contains(err.Error(), "profundidad") {
		t.Fatalf("loop not detected: %v", err)
	}
}

func TestCheckZoneFindsInconsistencies(t *testing.T) {
	l, roots, zones := hierarchy(t, false)
	// El padre anuncia tres NS; el hijo solo dos. ns2 tiene otro serial y permite AXFR; ns3 es lame.
	zones["lab."].add("ejemplo.lab. 3600 IN NS ns2.ejemplo.lab.", "ns2.ejemplo.lab. 3600 IN A 127.0.0.5",
		"ejemplo.lab. 3600 IN NS ns3.ejemplo.lab.", "ns3.ejemplo.lab. 3600 IN A 127.0.0.6")
	zones["ejemplo.lab."].add("ejemplo.lab. 300 IN NS ns2.ejemplo.lab.", "ns2.ejemplo.lab. 300 IN A 127.0.0.5")
	ns2 := newZone("ejemplo.lab.").add("ejemplo.lab. 300 IN SOA ns1.ejemplo.lab. admin.ejemplo.lab. 2026110300 7200 3600 1209600 300",
		"ejemplo.lab. 300 IN NS ns1.ejemplo.lab.", "ejemplo.lab. 300 IN NS ns2.ejemplo.lab.")
	ns2.allowAXFR = true
	lame := newZone("ejemplo.lab.")
	lame.refuse = true
	l.serve(t, "127.0.0.5", ns2)
	l.serve(t, "127.0.0.6", lame)
	rep, err := CheckZone(context.Background(), l.dial, "ejemplo.lab", roots, opts())
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]bool{}
	for _, f := range rep.Findings {
		codes[f.Code] = true
	}
	for _, want := range []string{"serial-distinto", "ns-lame", "axfr-abierto", "ns-padre-hijo"} {
		if !codes[want] {
			t.Errorf("finding %s missing: %+v", want, rep.Findings)
		}
	}
	if len(rep.Servers) != 3 {
		t.Fatalf("servers = %+v", rep.Servers)
	}
}

func TestCheckDNSSECValidChain(t *testing.T) {
	l, roots, zones := hierarchy(t, true)
	rep, err := CheckDNSSEC(context.Background(), l.dial, "ejemplo.lab", roots, []string{zones["."].ds()}, opts())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Secure || len(rep.Chain) != 3 {
		t.Fatalf("rep = %+v", rep)
	}
	for _, link := range rep.Chain {
		if !link.Valid || link.Expires.IsZero() {
			t.Errorf("link %+v", link)
		}
	}
}

func TestCheckDNSSECExpiredSignature(t *testing.T) {
	l, roots, zones := hierarchy(t, true)
	zones["ejemplo.lab."].resign(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	rep, err := CheckDNSSEC(context.Background(), l.dial, "ejemplo.lab", roots, []string{zones["."].ds()}, opts())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Secure || rep.Chain[2].Valid || !strings.Contains(rep.Chain[2].Error, "venc") {
		t.Fatalf("expired signature accepted: %+v", rep.Chain[2])
	}
}

func TestCheckDNSSECWrongAnchor(t *testing.T) {
	l, roots, _ := hierarchy(t, true)
	other := hierarchyKey(t)
	rep, _ := CheckDNSSEC(context.Background(), l.dial, "ejemplo.lab", roots, []string{other}, opts())
	if rep.Secure || rep.Chain[0].Valid {
		t.Fatalf("wrong trust anchor accepted: %+v", rep.Chain[0])
	}
}

func TestCheckDNSSECUnsignedIsInsecure(t *testing.T) {
	l, roots, _ := hierarchy(t, false)
	rep, err := CheckDNSSEC(context.Background(), l.dial, "ejemplo.lab", roots, nil, opts())
	if err != nil || rep.Secure || !rep.Unsigned {
		t.Fatalf("rep=%+v err=%v", rep, err)
	}
}

func TestCheckTransport(t *testing.T) {
	l := &lab{ports: map[string]uint16{}}
	z := newZone("t.lab.").add("t.lab. 60 IN A 192.0.2.1")
	z.truncUDP = true
	l.serve(t, "127.0.0.40", z)
	rep := CheckTransport(context.Background(), l.dial, Server{Transport: "udp", Host: "127.0.0.40", Port: 53}, "t.lab", opts())
	if !rep.TCPWorks || rep.UDP512Truncated != true || len(rep.Probes) < 3 {
		t.Fatalf("rep = %+v", rep)
	}
}

func TestCheckHygiene(t *testing.T) {
	l, _, zones := hierarchy(t, false)
	rev := newZone("2.0.192.in-addr.arpa.").add("10.2.0.192.in-addr.arpa. 300 IN PTR otro.ejemplo.lab.")
	l.serve(t, "127.0.0.41", rev)
	_ = zones
	// El resolvedor de prueba responde ejemplo.lab y la zona inversa: un servidor por zona basta aquí.
	res := Server{Transport: "udp", Host: "127.0.0.4", Port: 53}
	revSrv := Server{Transport: "udp", Host: "127.0.0.41", Port: 53}
	rep := CheckHygiene(context.Background(), l.dial, res, "www.ejemplo.lab", HygieneOptions{ReverseServer: &revSrv, DKIMSelector: "s1"}, opts())
	codes := map[string]bool{}
	for _, f := range rep.Findings {
		codes[f.Code] = true
	}
	if !codes["ptr-no-coincide"] {
		t.Errorf("PTR mismatch not found: %+v", rep.Findings)
	}
	rep2 := CheckHygiene(context.Background(), l.dial, res, "ejemplo.lab", HygieneOptions{DKIMSelector: "s1"}, opts())
	codes = map[string]bool{}
	for _, f := range rep2.Findings {
		codes[f.Code] = true
	}
	if !codes["spf"] || !codes["sin-dmarc"] || !codes["caa"] || !codes["sin-dkim"] {
		t.Errorf("mail/CAA checks: %+v", rep2.Findings)
	}
}

func TestExposure(t *testing.T) {
	l := &lab{ports: map[string]uint16{}}
	open := newZone("x.lab.")
	open.recursive = true
	hij := newZone("y.lab.")
	hij.hijack = true
	closed := newZone("z.lab.").add("z.lab. 60 IN SOA a. b. 1 1 1 1 1")
	l.serve(t, "127.0.0.50", open)
	l.serve(t, "127.0.0.51", hij)
	l.serve(t, "127.0.0.52", closed)
	if r := CheckExposure(context.Background(), l.dial, Server{Transport: "udp", Host: "127.0.0.50", Port: 53}, opts()); !r.OpenResolver {
		t.Errorf("open resolver not detected: %+v", r)
	}
	if r := CheckExposure(context.Background(), l.dial, Server{Transport: "udp", Host: "127.0.0.51", Port: 53}, opts()); !r.NXDomainHijack {
		t.Errorf("hijack not detected: %+v", r)
	}
	if r := CheckExposure(context.Background(), l.dial, Server{Transport: "udp", Host: "127.0.0.52", Port: 53}, opts()); r.OpenResolver || r.NXDomainHijack {
		t.Errorf("false positive: %+v", r)
	}
}

// hierarchyKey genera un DS de una llave cualquiera, para probar un ancla equivocada.
func hierarchyKey(t *testing.T) string {
	z := newZone(".").sign(t, time.Now(), time.Now().Add(time.Hour))
	return z.ds()
}
