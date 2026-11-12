package drift

import (
	"os"
	"strings"
	"testing"
)

func read(t *testing.T, n string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + n)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func lines(cs []Change) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Op+" "+c.Path+" | "+c.Line)
	}
	return out
}

func TestCompareDetectaSoloCambiosReales(t *testing.T) {
	cs, ign := Compare(read(t, "ronda1.txt"), read(t, "ronda2.txt"))
	got := strings.Join(lines(cs), "\n")
	want := strings.Join([]string{
		"- interface GigabitEthernet1/0/1 | description PC-01",
		"- interface GigabitEthernet1/0/2 | shutdown",
		"- line vty 0 4 | transport input ssh",
		"+ interface GigabitEthernet1/0/1 | description PC-01-NUEVA",
		"+ interface GigabitEthernet1/0/1 | switchport port-security",
		"+  | interface Loopback9",
		"+ interface Loopback9 | ip address 192.0.2.9 255.255.255.255",
		"+ line vty 0 4 | transport input ssh telnet",
	}, "\n")
	if got != want {
		t.Fatalf("cambios:\n%s\nquería:\n%s", got, want)
	}
	// Lo volátil no cuenta como cambio, pero se informa que se ignoró.
	for _, v := range []string{"ntp clock-period", "Last configuration change", "NVRAM config last updated", "Current configuration"} {
		found := false
		for _, i := range ign {
			found = found || strings.Contains(i, v)
		}
		if !found {
			t.Errorf("no se informó como ignorada: %s (%v)", v, ign)
		}
	}
}

func TestCompareIgualConRuidoVolatilNoHayDeriva(t *testing.T) {
	a := "Current configuration : 100 bytes\n! Last configuration change at 1\nntp clock-period 1\nhostname R1\n"
	b := "Current configuration : 200 bytes\n! Last configuration change at 2\nntp clock-period 2\nhostname R1\n"
	if cs, _ := Compare(a, b); len(cs) != 0 {
		t.Fatalf("cambios = %v", lines(cs))
	}
}

func TestCompareBannerYLineaMovida(t *testing.T) {
	a := "banner motd ^C\nuno\n^C\nhostname R1\n"
	b := "banner motd ^C\ndos\n^C\nhostname R1\n"
	cs := lines(first(Compare(a, b)))
	if len(cs) != 2 || !strings.Contains(cs[0], "uno") || !strings.Contains(cs[1], "dos") {
		t.Fatalf("banner: %v", cs)
	}
}

func first(cs []Change, _ []string) []Change { return cs }

func TestReporteTexto(t *testing.T) {
	cs, ign := Compare(read(t, "ronda1.txt"), read(t, "ronda2.txt"))
	r := Report{Dir: "/x", From: 1, To: 2, Devices: []DeviceDrift{
		NewDevice("SW1", 1, 2, cs, ign), NewDevice("SW2", 1, 2, nil, nil)}}
	txt := r.Text()
	for _, w := range []string{"SW1: 8 cambios (5 agregadas, 3 quitadas)", "interface GigabitEthernet1/0/1", "- description PC-01", "+ description PC-01-NUEVA", "SW2: sin deriva", "1 de 2 equipos con deriva"} {
		if !strings.Contains(txt, w) {
			t.Errorf("falta %q en:\n%s", w, txt)
		}
	}
}

func TestCompareLineaRepetida(t *testing.T) {
	a := "ip route 0.0.0.0 0.0.0.0 192.0.2.1\nip route 0.0.0.0 0.0.0.0 192.0.2.1\n"
	b := "ip route 0.0.0.0 0.0.0.0 192.0.2.1\n"
	if cs, _ := Compare(a, b); len(cs) != 1 || cs[0].Op != "-" {
		t.Fatalf("cambios = %v", lines(cs))
	}
}

func TestPair(t *testing.T) {
	for _, c := range []struct {
		have     []int
		to       int
		from, tr int
		ok       bool
	}{
		{[]int{1, 2, 3}, 0, 2, 3, true},
		{[]int{1, 2, 3}, 2, 1, 2, true},
		{[]int{1, 3}, 3, 1, 3, true}, // ronda 2 sin configuración: se compara con la anterior que sí la tiene
		{[]int{1, 2}, 1, 0, 0, false},
		{[]int{1, 2}, 9, 0, 0, false},
		{nil, 0, 0, 0, false},
		{[]int{4}, 0, 0, 0, false},
	} {
		from, to, ok := Pair(c.have, c.to)
		if ok != c.ok || (ok && (from != c.from || to != c.tr)) {
			t.Errorf("Pair(%v,%d) = %d,%d,%v", c.have, c.to, from, to, ok)
		}
	}
	for cmd, want := range map[string]bool{"show running-config": true, "SHOW  run": true, "show running-config | include boot": false, "show startup-config": false,
		"sh run": true, "show running": true, "sh running-config": true, "sh ru": true, "SH RUNNING-CONFIG": true, "s run": false,
		"show running-config all": false, "show run full": false, "show run | section x": false, "show runn-x": false, "show ru x": false, "show r": false, "show": false, "": false} {
		if IsRunningConfig(cmd) != want {
			t.Errorf("IsRunningConfig(%q) != %v", cmd, want)
		}
	}
}
