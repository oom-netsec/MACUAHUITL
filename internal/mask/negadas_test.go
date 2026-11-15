package mask

import (
	"strings"
	"testing"
)

// Una línea negada («no …») lleva el mismo secreto que la afirmada: sale en reversas, planes y diffs.
func TestLineasNegadasNoFiltranSecretos(t *testing.T) {
	ios := []string{
		"no snmp-server community Cl4veX RO",
		"no snmp-server host 192.0.2.9 version 2c Cl4veX udp-port 162",
		"no snmp-server host 192.0.2.9 Cl4veX",
		"no username U secret 0 Cl4veX",
		"no username U privilege 15 password 0 Cl4veX",
		"no enable secret 0 Cl4veX",
		"no tacacs-server key Cl4veX",
		"no radius-server key Cl4veX",
		"no crypto isakmp key Cl4veX address 192.0.2.1",
		"no ntp authentication-key 1 md5 Cl4veX",
		"no snmp-server user U G v3 auth sha Cl4veX priv aes 128 Cl4veY",
		"  no   snmp-server community Cl4veX RO",
	}
	for _, in := range ios {
		got, _ := Apply("ios", in)
		checkNeg(t, "ios", in, got)
	}
	bgp := "router bgp 65000\n no neighbor 192.0.2.1 password Cl4veX\n"
	got, _ := Apply("ios", bgp)
	checkNeg(t, "ios", bgp, got)
	for plat, ins := range map[string][]string{
		"nxos": {"no snmp-server community Cl4veX group network-admin", "no username U password 0 Cl4veX role network-admin"},
		"asa":  {"no snmp-server host inside 192.0.2.9 community Cl4veX", "no username U password Cl4veX", "no failover key Cl4veX"},
	} {
		for _, in := range ins {
			got, _ := Apply(plat, in)
			checkNeg(t, plat, in, got)
		}
	}
	for _, in := range []string{
		"- no snmp-server community Cl4veX RO",
		"R1(config)#no snmp-server community Cl4veX RO",
		`*** Output from config line 5, "no snmp-server community Cl4veX"`,
	} {
		got, _ := Apply("ios", in)
		if strings.Contains(got, "Cl4ve") || !strings.Contains(got, "no snmp-server community") {
			t.Errorf("%q -> %q", in, got)
		}
	}
}

func checkNeg(t *testing.T, plat, in, got string) {
	t.Helper()
	if strings.Contains(got, "Cl4ve") {
		t.Errorf("%s %q filtra: %q", plat, in, got)
	}
	for i, l := range strings.Split(strings.TrimRight(in, "\n"), "\n") {
		g := strings.Split(strings.TrimRight(got, "\n"), "\n")[i]
		if !strings.HasPrefix(strings.TrimLeft(l, " "), "no") {
			continue
		}
		if ind := len(l) - len(strings.TrimLeft(l, " ")); !strings.HasPrefix(g, l[:ind]) || !strings.HasPrefix(strings.TrimLeft(g, " "), "no") {
			t.Errorf("%s %q pierde sangría o no: %q", plat, l, g)
		}
	}
}

func TestLineasNegadasSinSecretoQuedanIguales(t *testing.T) {
	for _, in := range []string{"no shutdown", " no ip address", "no route to host", "no such file or directory"} {
		if got, _ := Apply("ios", in); got != in {
			t.Errorf("%q cambió: %q", in, got)
		}
	}
}
