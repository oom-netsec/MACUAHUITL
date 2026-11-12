package dnsq

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

var volatileDNS = regexp.MustCompile(`"RTT":[0-9]+|127\.0\.0\.[0-9]+:[0-9]+`)

// udpOnly escucha solo por UDP: TCP/53 no responde.
func (l *lab) udpOnly(t *testing.T, ip string, h dns.Handler) {
	t.Helper()
	pc, err := net.ListenPacket("udp", ip+":0")
	if err != nil {
		t.Fatal(err)
	}
	s := &dns.Server{PacketConn: pc, Handler: h}
	go s.ActivateAndServe()
	t.Cleanup(func() { s.Shutdown() })
	l.mu.Lock()
	l.ports[ip] = uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	l.mu.Unlock()
}

// noEDNS quita el OPT de cada respuesta.
type noEDNS struct{ h dns.Handler }

func (n noEDNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	r2 := r.Copy()
	r2.Extra = nil
	n.h.ServeDNS(w, r2)
}

// chain responde a cualquier A con una cadena de 5 CNAME y una dirección.
type chain struct{}

func (chain) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	for i := 1; i <= 5; i++ {
		rr, _ := dns.NewRR(fmt.Sprintf("c%d.h.lab. 300 IN CNAME c%d.h.lab.", i, i+1))
		m.Answer = append(m.Answer, rr)
	}
	a, _ := dns.NewRR("c6.h.lab. 300 IN A 192.0.2.9")
	m.Answer = append(m.Answer, a)
	w.WriteMsg(m)
}

// bigAnswer responde a todo con 90 direcciones (más de 1232 bytes, sin truncar).
type bigAnswer struct{}

func (bigAnswer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	if opt := r.IsEdns0(); opt != nil {
		m.SetEdns0(4096, false)
	}
	for i := 0; i < 90; i++ {
		rr, _ := dns.NewRR(fmt.Sprintf("big.lab. 300 IN A 192.0.2.%d", i+1))
		m.Answer = append(m.Answer, rr)
	}
	w.WriteMsg(m)
}

// escenariosDNS corre cada revisión del diagnóstico DNS contra servidores de juguete y devuelve los informes.
func escenariosDNS(t *testing.T) map[string]any {
	t.Helper()
	out := map[string]any{}
	ctx := context.Background()
	srv := func(ip string) Server { return Server{Transport: "udp", Host: ip, Port: 53} }

	// zona: padre con tres NS, hijo con dos; ns2 con otro serial y AXFR abierto; ns3 lame; ns4 sin dirección.
	l, roots, zones := hierarchy(t, false)
	zones["lab."].add("ejemplo.lab. 3600 IN NS ns2.ejemplo.lab.", "ns2.ejemplo.lab. 3600 IN A 127.0.0.5",
		"ejemplo.lab. 3600 IN NS ns3.ejemplo.lab.", "ns3.ejemplo.lab. 3600 IN A 127.0.0.6",
		"ejemplo.lab. 3600 IN NS ns9.ejemplo.lab.")
	zones["ejemplo.lab."].add("ejemplo.lab. 300 IN NS ns2.ejemplo.lab.", "ns2.ejemplo.lab. 300 IN A 127.0.0.5")
	ns2 := newZone("ejemplo.lab.").add("ejemplo.lab. 300 IN SOA ns1.ejemplo.lab. admin.ejemplo.lab. 2026110300 7200 3600 1209600 300",
		"ejemplo.lab. 300 IN NS ns1.ejemplo.lab.", "ejemplo.lab. 300 IN NS ns2.ejemplo.lab.")
	ns2.allowAXFR = true
	lame := newZone("ejemplo.lab.")
	lame.refuse = true
	l.serve(t, "127.0.0.5", ns2)
	l.serve(t, "127.0.0.6", lame)
	rep, err := CheckZone(ctx, l.dial, "ejemplo.lab", roots, opts())
	if err != nil {
		t.Fatal(err)
	}
	out["zone"] = rep
	rep, err = CheckZone(ctx, l.dial, "noexiste.lab", roots, opts())
	if err != nil {
		t.Fatal(err)
	}
	out["zone-sin-delegacion"] = rep

	// transporte: fragmentación (respuesta grande), TCP bloqueado y sin EDNS.
	lt := &lab{ports: map[string]uint16{}}
	lt.serve(t, "127.0.0.30", bigAnswer{})
	out["transport-frag"] = CheckTransport(ctx, lt.dial, srv("127.0.0.30"), "big.lab", opts())
	lt.udpOnly(t, "127.0.0.31", noEDNS{newZone("t.lab.").add("t.lab. 60 IN A 192.0.2.1")})
	out["transport-sin-tcp-edns"] = CheckTransport(ctx, lt.dial, srv("127.0.0.31"), "t.lab", opts())

	// higiene
	lh, _, _ := hierarchy(t, false)
	rev := newZone("2.0.192.in-addr.arpa.").add("10.2.0.192.in-addr.arpa. 300 IN PTR otro.ejemplo.lab.")
	lh.serve(t, "127.0.0.41", rev)
	revS := srv("127.0.0.41")
	out["hygiene-ptr"] = CheckHygiene(ctx, lh.dial, srv("127.0.0.4"), "www.ejemplo.lab", HygieneOptions{ReverseServer: &revS, DKIMSelector: "s1"}, opts())
	out["hygiene-mail"] = CheckHygiene(ctx, lh.dial, srv("127.0.0.4"), "ejemplo.lab", HygieneOptions{DKIMSelector: "s1"}, opts())
	h := newZone("h.lab.").add("h.lab. 30 IN A 192.0.2.7", `h.lab. 300 IN TXT "v=spf1 -all"`, `h.lab. 300 IN TXT "v=spf1 +all"`,
		`_dmarc.h.lab. 300 IN TXT "v=DMARC1; p=none"`, `s1._domainkey.h.lab. 300 IN TXT "v=DKIM1; k=rsa"`)
	lh.serve(t, "127.0.0.60", h)
	out["hygiene-txt"] = CheckHygiene(ctx, lh.dial, srv("127.0.0.60"), "h.lab", HygieneOptions{DKIMSelector: "s1"}, opts())
	lh.serve(t, "127.0.0.61", chain{})
	out["hygiene-cname"] = CheckHygiene(ctx, lh.dial, srv("127.0.0.61"), "c1.h.lab", HygieneOptions{}, opts())

	// exposición
	le := &lab{ports: map[string]uint16{}}
	open := newZone("x.lab.")
	open.recursive = true
	hij := newZone("y.lab.")
	hij.hijack = true
	le.serve(t, "127.0.0.50", open)
	le.serve(t, "127.0.0.51", hij)
	out["exposure-open"] = CheckExposure(ctx, le.dial, srv("127.0.0.50"), opts())
	out["exposure-hijack"] = CheckExposure(ctx, le.dial, srv("127.0.0.51"), opts())
	return out
}

func viewDNS(r any) string {
	b, _ := json.Marshal(r)
	return volatileDNS.ReplaceAllString(string(b), "X")
}

// Regresión: el JSON en español de cada revisión es el de antes del catálogo (UPDATE_GOLDEN=1 lo reescribe).
func TestFindingsEspanolRegresion(t *testing.T) {
	got := map[string]string{}
	for n, r := range escenariosDNS(t) {
		got[n] = viewDNS(r)
	}
	const file = "testdata/findings_es.golden.json"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		b, _ := json.MarshalIndent(got, "", " ")
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	for n, g := range got {
		if g != want[n] {
			t.Errorf("%s cambió:\n got: %s\nwant: %s", n, g, want[n])
		}
	}
	_ = strings.TrimSpace
}

// Con en, cada hallazgo de catálogo sale en inglés (sin español en el detalle) y los de datos quedan tal cual.
func TestFindingsEnIngles(t *testing.T) {
	spanish := regexp.MustCompile(`(?i)\b(no hay|el servidor|respuesta|padre|autoritativ|cadena|sin |tiene|resuelve|responde|zona)\b`)
	nData, nText := 0, 0
	for n, r := range escenariosDNS(t) {
		es, en := Findings(r), Findings(Localize(r, "en"))
		for i, f := range en {
			switch {
			case es[i].Text.Empty():
				nData++
				if f.Detail != es[i].Detail {
					t.Errorf("%s: el dato %q cambió a %q", n, es[i].Detail, f.Detail)
				}
			default:
				nText++
				if f.Detail == es[i].Detail || f.Detail != es[i].Text.In("en") || spanish.MatchString(f.Detail) {
					t.Errorf("%s/%s: %q sin traducir", n, f.Code, f.Detail)
				}
			}
		}
		if x, ok := r.(ExposureReport); ok {
			for _, d := range Localize(x, "en").(ExposureReport).Details {
				if spanish.MatchString(d) {
					t.Errorf("%s: %q", n, d)
				}
			}
		}
	}
	if nData < 5 || nText < 20 {
		t.Errorf("pocos hallazgos: %d datos, %d de catálogo", nData, nText)
	}
}
