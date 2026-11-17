package diag

import (
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func pingIfaces(t *testing.T) {
	localTest(t)
	localIfaceNames = func() []string { return []string{"eth0", "Wi-Fi"} }
	t.Cleanup(func() { localIfaceNames = realIfaceNames })
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
	// source v4 con destino v6 literal
	if _, _, err := build(req(Ping, "2001:db8::1", po("source", "192.0.2.9"), ""), false); err == nil {
		t.Error("source v4 con destino v6 debe fallar")
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
		_, _, err := buildWindows(req(Ping, "192.0.2.1", o, ""))
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
	if _, err := Plan(req(Traceroute, "192.0.2.1", nil, "")); err == nil {
		t.Error("Plan solo es de ping")
	}
}
