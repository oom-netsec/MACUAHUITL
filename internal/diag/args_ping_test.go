package diag

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func pingIfaces(t *testing.T) {
	localTest(t)
	localIfaceNames = func() []string { return []string{"eth0", "Wi-Fi", "-c", "eth\u00e9"} }
	// fe80::1 y la mapeada son locales a propósito: las rechaza la regla, no el que no existan.
	localIPs = func() []netip.Addr {
		return []netip.Addr{netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("2001:db8::9"), netip.MustParseAddr("fe80::1"), netip.MustParseAddr("::ffff:192.0.2.9")}
	}
	t.Cleanup(func() { localIfaceNames = realIfaceNames; localIPs = realLocalIPs })
}

func po(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func TestPingOptionsArgv(t *testing.T) {
	pingIfaces(t)
	const h = "192.0.2.1"
	cases := []struct {
		name         string
		opts         map[string]string
		target       string
		linux, winar string // argv completo; "ERR" = debe fallar
	}{
		{"continuous", po("continuous", "true"), h, "-n " + h, "-t -w 2000 " + h},
		{"continuous con count se ignora", po("continuous", "true", "count", "9"), h, "-n " + h, "-t -w 2000 " + h},
		{"source ip", po("source", "192.0.2.9"), h, "-n -c 4 -I 192.0.2.9 " + h, "-n 4 -S 192.0.2.9 -w 2000 " + h},
		{"source nombre", po("source", "eth0"), h, "-n -c 4 -I eth0 " + h, "ERR"},
		{"source nombre windows", po("source", "Wi-Fi"), h, "-n -c 4 -I Wi-Fi " + h, "ERR"},
		{"df", po("df", "true"), h, "-n -c 4 -M do " + h, "-n 4 -f -w 2000 " + h},
		{"df family 6", po("df", "true", "family", "6"), "2001:db8::1", "-n -c 4 -M do -6 2001:db8::1", "ERR"},
		{"ttl", po("ttl", "64"), h, "-n -c 4 -t 64 " + h, "-n 4 -i 64 -w 2000 " + h},
		{"ttl 255", po("ttl", "255"), h, "-n -c 4 -t 255 " + h, "-n 4 -i 255 -w 2000 " + h},
		{"timeout", po("timeout", "5"), h, "-n -c 4 -W 5 " + h, "-n 4 -w 5000 " + h},
		{"family 4", po("family", "4"), "sw1.example", "-n -c 4 -4 sw1.example", "-n 4 -4 -w 2000 sw1.example"},
		{"family 6", po("family", "6"), "sw1.example", "-n -c 4 -6 sw1.example", "-n 4 -6 -w 2000 sw1.example"},
		{"tos", po("tos", "184"), h, "-n -c 4 -Q 184 " + h, "ERR"},
		{"tos 0", po("tos", "0"), h, "-n -c 4 -Q 0 " + h, "ERR"},
		{"interval", po("interval", "0.5"), h, "-n -c 4 -i 0.5 " + h, "ERR"},
		{"duration no genera bandera", po("duration", "30"), h, "-n -c 4 " + h, "-n 4 -w 2000 " + h},
		{"barrido sin bandera de tamaño", po("sweep_start", "100", "sweep_end", "300", "sweep_step", "100"), h, "-n -c 1 " + h, "-n 1 -w 2000 " + h},
		{"barrido con count", po("sweep_start", "0", "sweep_end", "10", "sweep_step", "5", "count", "5"), h, "-n -c 5 " + h, "-n 5 -w 2000 " + h},
		{"barrido y duration", po("sweep_start", "0", "sweep_end", "10", "sweep_step", "5", "duration", "60"), h, "-n -c 1 " + h, "-n 1 -w 2000 " + h},
		{"timeout con ceros", po("timeout", "007"), h, "-n -c 4 -W 7 " + h, "-n 4 -w 7000 " + h},
		{"enteros con ceros", po("count", "007", "ttl", "010", "size", "0100"), h, "-n -c 7 -s 100 -t 10 " + h, "-n 7 -l 100 -i 10 -w 2000 " + h},
		{"tos con ceros", po("tos", "010"), h, "-n -c 4 -Q 10 " + h, "ERR"},
		{"source v6 a destino v6", po("source", "2001:db8::9"), "2001:db8::1", "-n -c 4 -I 2001:db8::9 2001:db8::1", "-n 4 -S 2001:db8::9 -w 2000 2001:db8::1"},
		{"df windows destino v6 sin family", po("df", "true"), "2001:db8::1", "-n -c 4 -M do 2001:db8::1", "ERR"},
		{"df windows origen v6 destino DNS", po("df", "true", "source", "2001:db8::9"), "sw1.example", "-n -c 4 -I 2001:db8::9 -M do sw1.example", "ERR"},
		{"100 tamaños", po("sweep_start", "0", "sweep_end", "99", "sweep_step", "1"), h, "-n -c 1 " + h, "-n 1 -w 2000 " + h},
		{"start igual a end", po("sweep_start", "64", "sweep_end", "64", "sweep_step", "1"), h, "-n -c 1 " + h, "-n 1 -w 2000 " + h},
		{"combinadas", po("source", "192.0.2.9", "family", "4", "df", "true", "ttl", "5", "timeout", "2", "size", "100"), h,
			"-n -c 4 -s 100 -I 192.0.2.9 -M do -t 5 -W 2 -4 " + h, "-n 4 -l 100 -S 192.0.2.9 -f -i 5 -4 -w 2000 " + h},
	}
	for _, c := range cases {
		for _, win := range []bool{false, true} {
			want := c.linux
			if win {
				want = c.winar
			}
			_, argv, err := build(req(Ping, c.target, c.opts, ""), win)
			got := strings.Join(argv, " ")
			if want == "ERR" {
				if err == nil {
					t.Errorf("%s win=%v: debió fallar, dio %q", c.name, win, got)
				}
				continue
			}
			if err != nil || got != want {
				t.Errorf("%s win=%v: %q %v, quiero %q", c.name, win, got, err, want)
			}
		}
	}
}

func TestPingOptionsRechaza(t *testing.T) {
	pingIfaces(t)
	const h = "192.0.2.1"
	bad := map[string]map[string]string{
		"ttl 0":                  po("ttl", "0"),
		"ttl 256":                po("ttl", "256"),
		"ttl negativo":           po("ttl", "-1"),
		"timeout 0":              po("timeout", "0"),
		"timeout 61":             po("timeout", "61"),
		"tos 256":                po("tos", "256"),
		"duration 0":             po("duration", "0"),
		"duration 3601":          po("duration", "3601"),
		"family 5":               po("family", "5"),
		"family vacío":           po("family", ""),
		"sweep incompleto":       po("sweep_start", "0", "sweep_end", "10"),
		"sweep solo step":        po("sweep_step", "1"),
		"sweep step 0":           po("sweep_start", "0", "sweep_end", "10", "sweep_step", "0"),
		"sweep end < start":      po("sweep_start", "10", "sweep_end", "5", "sweep_step", "1"),
		"sweep end 65501":        po("sweep_start", "0", "sweep_end", "65501", "sweep_step", "65501"),
		"sweep 101 tamaños":      po("sweep_start", "0", "sweep_end", "100", "sweep_step", "1"),
		"sweep con size":         po("sweep_start", "0", "sweep_end", "10", "sweep_step", "5", "size", "10"),
		"sweep count 6":          po("sweep_start", "0", "sweep_end", "10", "sweep_step", "5", "count", "6"),
		"sweep con continuous":   po("sweep_start", "0", "sweep_end", "10", "sweep_step", "5", "continuous", "true"),
		"source con family":      po("source", "2001:db8::9", "family", "4"),
		"source v6 a destino v4": po("source", "2001:db8::9"),
		"source con zona":        po("source", "fe80::1%eth0"),
		"source inexistente":     po("source", "eth9"),
		"source -oProxy":         po("source", "-oProxy=x"),
		"source ;":               po("source", "eth0;id"),
		"source espacios":        po("source", "eth0 -x"),
		"source vacío":           po("source", ""),
		"source 0.0.0.0":         po("source", "0.0.0.0"),
		"source multicast":       po("source", "224.0.0.1"),
		"source no local":        po("source", "8.8.8.8"),
		"source link-local":      po("source", "fe80::1"),
		"source mapeada":         po("source", "::ffff:192.0.2.9"),
		"source nombre -c":       po("source", "-c"),
		"source nombre ethé":     po("source", "eth\u00e9"),
		"family 6 a destino v4":  po("family", "6"),
	}
	for n, o := range bad {
		for _, win := range []bool{false, true} {
			if _, argv, err := build(req(Ping, h, o, ""), win); err == nil {
				t.Errorf("%s win=%v: aceptado %v", n, win, argv)
			}
		}
	}
	// el error de rango lleva la clave
	_, _, err := build(req(Ping, h, po("ttl", "300"), ""), false)
	if err == nil || !strings.Contains(i18n.In(i18n.En, err), "ttl") {
		t.Errorf("ttl: %v", err)
	}
	// family contra IP literal: el error marca el campo
	for _, c := range []struct{ host, fam string }{{h, "6"}, {"2001:db8::1", "4"}} {
		_, _, err := build(req(Ping, c.host, po("family", c.fam), ""), false)
		if got := errKey(err); got != "family" {
			t.Errorf("family %s con %s: key=%q err=%v", c.fam, c.host, got, err)
		}
	}
	// family distinta de la del origen con destino DNS
	if _, _, err := build(req(Ping, "sw1.example", po("source", "2001:db8::9", "family", "4"), ""), false); errKey(err) != "source" {
		t.Errorf("source/family con DNS: %v", err)
	}
	// link-local y mapeada locales contra destino DNS: solo la regla propia las rechaza (la familia coincidiría)
	for _, src := range []string{"fe80::1", "::ffff:192.0.2.9"} {
		if _, argv, err := build(req(Ping, "sw1.example", po("source", src), ""), false); err == nil {
			t.Errorf("source %s con destino DNS aceptado: %v", src, argv)
		}
	}
	// zona IPv6 contra un destino v6
	if _, _, err := build(req(Ping, "2001:db8::1", po("source", "fe80::1%eth0"), ""), false); err == nil {
		t.Error("source con zona y destino v6 debe fallar")
	}
	// source v4 con destino v6 literal
	if _, _, err := build(req(Ping, "2001:db8::1", po("source", "192.0.2.9"), ""), false); err == nil {
		t.Error("source v4 con destino v6 debe fallar")
	}
}

func errKey(err error) string {
	m, ok := err.(interface{ Metadata() map[string]string })
	if !ok {
		return ""
	}
	return m.Metadata()["key"]
}

// La UI marca el campo con la clave del error.
func TestPingErrorKey(t *testing.T) {
	pingIfaces(t)
	sw := []string{"sweep_start", "0", "sweep_end", "10", "sweep_step", "5"}
	for _, c := range []struct {
		name, want string
		o          map[string]string
	}{
		{"source_bad", "source", po("source", "8.8.8.8")},
		{"source_family", "source", po("source", "2001:db8::9")},
		{"sweep_all", "sweep_start", po("sweep_start", "0")},
		{"sweep_max", "sweep_start", po("sweep_start", "0", "sweep_end", "100", "sweep_step", "1")},
		{"combo continuous", "continuous", po(append(sw, "continuous", "true")...)},
		{"combo size", "size", po(append(sw, "size", "9")...)},
	} {
		_, _, err := build(req(Ping, "192.0.2.1", c.o, ""), false)
		if got := errKey(err); err == nil || got != c.want {
			t.Errorf("%s: key=%q quiero %q (%v)", c.name, got, c.want, err)
		}
	}
}

func TestPingWindowsOptWindows(t *testing.T) {
	pingIfaces(t)
	for key, o := range map[string]map[string]string{
		"interval": po("interval", "1"),
		"tos":      po("tos", "10"),
		"source":   po("source", "eth0"),
		"df":       po("df", "true", "family", "6"),
	} {
		_, _, err := buildWindows(req(Ping, "sw1.example", o, ""))
		if err == nil || !strings.Contains(i18n.In(i18n.En, err), "does not exist on Windows") || !strings.Contains(i18n.In(i18n.En, err), key) {
			t.Errorf("%s: %v", key, err)
		}
	}
}

func TestPingPlan(t *testing.T) {
	pingIfaces(t)
	p, err := Plan(req(Ping, "192.0.2.1", po("continuous", "true", "duration", "30"), ""))
	if err != nil || !p.Continuous || p.Duration != 30 || p.Sweep != nil || p.Count != 4 {
		t.Errorf("%+v %v", p, err)
	}
	p, err = Plan(req(Ping, "192.0.2.1", po("sweep_start", "100", "sweep_end", "350", "sweep_step", "100", "count", "2"), ""))
	if err != nil || p.Sweep == nil || p.Count != 2 || len(p.Sweep.Sizes()) != 3 || p.Sweep.Sizes()[2] != 300 {
		t.Errorf("%+v %v", p, err)
	}
	_, err = Plan(req(Traceroute, "192.0.2.1", nil, ""))
	if err == nil || !strings.Contains(i18n.In(i18n.En, err), "ping") || strings.Contains(i18n.In(i18n.En, err), "unknown tool") {
		t.Errorf("Plan solo es de ping: %v", err)
	}
}
