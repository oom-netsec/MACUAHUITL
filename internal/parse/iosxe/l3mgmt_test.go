package iosxe

import (
	"net/netip"
	"reflect"
	"testing"
)

// Formatos de la documentación de Cisco (IOS 15.2E e IOS-XE 17.x). Sin validar en laboratorio.

func TestParseStaticRoutes(t *testing.T) {
	const out = `ip route 10.1.0.0 255.255.0.0 10.0.0.1
ip route 10.2.0.0 255.255.0.0 10.0.0.1 5 name LAB
ip route 10.3.0.0 255.255.255.0 GigabitEthernet1/0/1 10.0.0.9 200 tag 7
ip route 10.4.0.0 255.255.255.0 Null0
ip route vrf MGMT 10.5.0.0 255.255.0.0 10.9.9.1
`
	got, ok := ParseStaticRoutes(out)
	if !ok || len(got) != 4 {
		t.Fatalf("%v %+v", ok, got)
	}
	if r := got[0]; r.Net != "10.1.0.0" || r.Mask != "255.255.0.0" || r.NextHop != "10.0.0.1" || r.Iface != "" || r.Distance != "" || r.Name != "" {
		t.Errorf("simple = %+v", r)
	}
	if r := got[1]; r.Distance != "5" || r.Name != "LAB" || r.NextHop != "10.0.0.1" {
		t.Errorf("con distancia y nombre = %+v", r)
	}
	if r := got[2]; r.Iface != "GigabitEthernet1/0/1" || r.NextHop != "10.0.0.9" || r.Distance != "200" || !reflect.DeepEqual(r.Other, []string{"tag", "7"}) {
		t.Errorf("con interfaz = %+v", r)
	}
	if r := got[3]; r.Iface != "Null0" || r.NextHop != "" {
		t.Errorf("solo interfaz = %+v", r)
	}
	if _, ok := ParseStaticRoutes(""); !ok {
		t.Error("sin rutas es una salida válida")
	}
	for _, bad := range []string{"% Invalid input detected at '^' marker.\n", "ip route profile\n", "ip route static bfd Gi1/0/1 10.0.0.1\n", "ip route 10.1.0.0\n"} {
		if _, ok := ParseStaticRoutes(bad); ok {
			t.Errorf("%q se tomó por válida", bad)
		}
	}
}

func TestParseNTPServers(t *testing.T) {
	const out = "ntp server 10.0.0.1\nntp server 10.0.0.2 prefer\nntp server vrf Mgmt 10.0.0.3\nntp server 10.0.0.4 key 3 version 3\nntp authentication-key 1 md5 0822455D0A16 7\nntp peer 10.0.0.9\nntp server ip 10.0.0.5\n"
	got, ok := ParseNTPServers(out)
	if !ok || len(got) != 5 {
		t.Fatalf("%v %+v", ok, got)
	}
	if got[0].Addr != "10.0.0.1" || len(got[0].Options) != 0 || got[0].Vrf != "" {
		t.Errorf("%+v", got[0])
	}
	if got[1].Addr != "10.0.0.2" || !reflect.DeepEqual(got[1].Options, []string{"prefer"}) {
		t.Errorf("%+v", got[1])
	}
	if got[2].Vrf != "Mgmt" || got[2].Addr != "10.0.0.3" {
		t.Errorf("%+v", got[2])
	}
	if !reflect.DeepEqual(got[3].Options, []string{"key", "3", "version", "3"}) || got[4].Addr != "10.0.0.5" {
		t.Errorf("%+v %+v", got[3], got[4])
	}
	if _, ok := ParseNTPServers("% Invalid input detected at '^' marker.\n"); ok {
		t.Error("error de IOS tomado por válido")
	}
}

func TestParseLoggingCfg(t *testing.T) {
	const out = "logging buffered 8192\nlogging host 10.0.0.1\nlogging 10.0.0.2\nlogging host 10.0.0.3 transport tcp port 601\nlogging trap warnings\nlogging source-interface Vlan10\n"
	got, ok := ParseLoggingCfg(out)
	if !ok || got.Trap != "warnings" || len(got.Hosts) != 3 {
		t.Fatalf("%v %+v", ok, got)
	}
	if got.Hosts[0].Addr != "10.0.0.1" || got.Hosts[1].Addr != "10.0.0.2" || len(got.Hosts[1].Options) != 0 {
		t.Errorf("%+v", got.Hosts)
	}
	if got.Hosts[2].Addr != "10.0.0.3" || !reflect.DeepEqual(got.Hosts[2].Options, []string{"transport", "tcp", "port", "601"}) {
		t.Errorf("%+v", got.Hosts[2])
	}
	if c, ok := ParseLoggingCfg("no logging trap\nlogging host 10.0.0.1\n"); !ok || !c.NoTrap || c.Trap != "" || len(c.Hosts) != 1 {
		t.Errorf("no logging trap: %v %+v", ok, c)
	}
	if c, ok := ParseLoggingCfg(""); !ok || c.Trap != "" || len(c.Hosts) != 0 {
		t.Errorf("vacío: %v %+v", ok, c)
	}
	if _, ok := ParseLoggingCfg("% Invalid input detected at '^' marker.\n"); ok {
		t.Error("error de IOS tomado por válido")
	}
}

// El transporte y el puerto efectivos de un destino: IOS puede omitir `port 514` (o todo el sufijo) en el running. Supuesto sin validar
// en laboratorio: udp = 514 y tcp = 601 son los puertos de fábrica.
func TestLogHostTransport(t *testing.T) {
	for _, c := range []struct {
		opts []string
		tr   string
		port int
		ok   bool
	}{
		{nil, "udp", 514, true},
		{[]string{"transport", "udp"}, "udp", 514, true},
		{[]string{"transport", "udp", "port", "514"}, "udp", 514, true},
		{[]string{"transport", "udp", "port", "5514"}, "udp", 5514, true},
		{[]string{"transport", "tcp"}, "tcp", 601, true},
		{[]string{"transport", "tcp", "port", "601"}, "tcp", 601, true},
		{[]string{"transport", "tcp", "port", "1514"}, "tcp", 1514, true},
		{[]string{"transport", "beep"}, "", 0, false},
		{[]string{"transport", "udp", "port", "0"}, "", 0, false},
		{[]string{"transport", "udp", "port", "70000"}, "", 0, false},
		{[]string{"transport", "udp", "port", "x"}, "", 0, false},
		{[]string{"transport", "udp", "port", "05514"}, "", 0, false},
		{[]string{"transport", "udp", "port", "5514", "xml"}, "", 0, false},
		{[]string{"filtered"}, "", 0, false},
		{[]string{"vrf", "Mgmt"}, "", 0, false},
	} {
		tr, port, ok := LogHost{Addr: "10.0.0.1", Options: c.opts}.Transport()
		if tr != c.tr || port != c.port || ok != c.ok {
			t.Errorf("%v: %q %d %v, quería %q %d %v", c.opts, tr, port, ok, c.tr, c.port, c.ok)
		}
	}
}

func TestParseSNMP(t *testing.T) {
	cm, ok := ParseSNMPCommunities("snmp-server community pub RO\nsnmp-server community priv RW 10\nsnmp-server community vista view V1 RO MGMT\nsnmp-server community rara\n")
	if !ok || len(cm) != 4 {
		t.Fatalf("%v %+v", ok, cm)
	}
	if cm[0].Name != "pub" || cm[0].Perm != "RO" || cm[0].ACL != "" || cm[1].Perm != "RW" || cm[1].ACL != "10" {
		t.Errorf("%+v %+v", cm[0], cm[1])
	}
	if cm[2].Perm != "RO" || cm[2].ACL != "MGMT" || len(cm[2].Other) == 0 || cm[3].Perm != "" {
		t.Errorf("%+v %+v", cm[2], cm[3])
	}
	gs, ok := ParseSNMPGroups("snmp-server group ADMINS v3 priv\nsnmp-server group LECT v3 auth read VISTA\nsnmp-server group V2G v2c\n")
	if !ok || len(gs) != 3 || gs[0].Name != "ADMINS" || gs[0].Version != "v3" || gs[0].Level != "priv" || gs[1].Level != "auth" || !reflect.DeepEqual(gs[1].Other, []string{"read", "VISTA"}) || gs[2].Version != "v2c" || gs[2].Level != "" {
		t.Errorf("%v %+v", ok, gs)
	}
	const users = `User name: tech
Engine ID: 800000090300AABBCCDDEEFF
storage-type: nonvolatile        active
Authentication Protocol: SHA
Privacy Protocol: AES128
Group-name: ADMINS

User name: viejo
Engine ID: 800000090300AABBCCDDEEFF
storage-type: nonvolatile        active
Authentication Protocol: MD5
Privacy Protocol: None
Group-name: LECT
`
	us, ok := ParseSNMPUsers(users)
	if !ok || len(us) != 2 || us[0].Name != "tech" || us[0].Group != "ADMINS" || us[0].Auth != "SHA" || us[0].Priv != "AES128" || us[0].EngineID != "800000090300AABBCCDDEEFF" || us[1].Name != "viejo" {
		t.Fatalf("%v %+v", ok, us)
	}
	if us, ok := ParseSNMPUsers(""); !ok || len(us) != 0 {
		t.Errorf("sin usuarios: %v %v", ok, us)
	}
	for _, bad := range []string{"%SNMP agent not enabled\n", "% Invalid input detected at '^' marker.\n"} {
		if _, ok := ParseSNMPUsers(bad); ok {
			t.Errorf("%q tomado por válido", bad)
		}
		if _, ok := ParseSNMPCommunities(bad); ok {
			t.Errorf("%q tomado por válido (communities)", bad)
		}
	}
}

func TestParseBannerMOTD(t *testing.T) {
	cases := []struct {
		name, text string
		want       Banner
		ok         bool
	}{
		{"sin banner", "", Banner{}, true},
		{"una línea", "banner motd ^CSolo personal autorizado^C\n", Banner{Present: true, Text: "Solo personal autorizado"}, true},
		{"varias líneas", "banner motd ^C\nAcceso restringido\nSolo personal autorizado\n^C\n", Banner{Present: true, Multi: true}, true},
		{"varias líneas con texto en la primera", "banner motd ^CAcceso\nrestringido^C\n", Banner{Present: true, Multi: true}, true},
		{"error", "% Invalid input detected at '^' marker.\n", Banner{}, false},
	}
	for _, c := range cases {
		got, ok := ParseBannerMOTD(c.text)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: %v %+v, quería %v %+v", c.name, ok, got, c.ok, c.want)
		}
	}
}

func TestParseVtyBlocks(t *testing.T) {
	const out = `line vty 0 4
 access-class MGMT in
 exec-timeout 5 0
 login local
 transport input ssh
line vty 5 15
 access-class 10 in vrf-also
 access-class OTRA out
 login local
line vty 16
 login local
`
	got, ok := ParseVtyBlocks(out)
	if !ok || len(got) != 3 {
		t.Fatalf("%v %+v", ok, got)
	}
	if b := got[0]; b.Lo != 0 || b.Hi != 4 || !b.HasAccessIn || b.AccessIn != "MGMT" || len(b.Lines) != 4 {
		t.Errorf("%+v", b)
	}
	if b := got[1]; b.Lo != 5 || b.Hi != 15 || b.AccessIn != "10" || !b.HasAccessIn {
		t.Errorf("%+v", b)
	}
	if b := got[2]; b.Lo != 16 || b.Hi != 16 || b.HasAccessIn {
		t.Errorf("%+v", b)
	}
	if _, ok := ParseVtyBlocks("% Invalid input detected at '^' marker.\n"); ok {
		t.Error("error de IOS tomado por válido")
	}
	if bs, ok := ParseVtyBlocks(""); !ok || len(bs) != 0 {
		t.Errorf("vacío: %v %v", ok, bs)
	}
}

func TestParseAccessLists(t *testing.T) {
	const out = `Standard IP access list MGMT
    10 permit 10.1.1.0, wildcard bits 0.0.0.255 (12 matches)
    20 permit 192.168.5.7
    30 remark red de laboratorio
    40 permit host 172.16.0.9 log
    50 deny   any
Extended IP access list 101
    10 permit tcp any any eq 22
`
	got, ok := ParseAccessLists(out)
	if !ok || len(got) != 2 {
		t.Fatalf("%v %+v", ok, got)
	}
	std := got[0]
	if std.Name != "MGMT" || !std.Standard || len(std.Entries) != 4 {
		t.Fatalf("%+v", std)
	}
	if got[1].Name != "101" || got[1].Standard {
		t.Errorf("%+v", got[1])
	}
	in := func(ip string) (string, bool) {
		a := netip.MustParseAddr(ip)
		for _, e := range std.Entries {
			if e.Matches(a) {
				return e.Action, true
			}
		}
		return "", false
	}
	for ip, want := range map[string]string{"10.1.1.77": "permit", "192.168.5.7": "permit", "172.16.0.9": "permit", "10.1.2.1": "deny", "8.8.8.8": "deny"} {
		if a, found := in(ip); !found || a != want {
			t.Errorf("%s: %q %v, quería %s", ip, a, found, want)
		}
	}
	// Forma de configuración («A W») y wildcard no contigua.
	got, ok = ParseAccessLists("Standard IP access list N\n    10 permit 10.0.0.0 0.0.255.255\n    20 permit 10.1.0.1 0.0.254.0\n")
	if !ok || len(got[0].Entries) != 2 || !got[0].Entries[0].Matches(netip.MustParseAddr("10.0.9.9")) || got[0].Entries[0].Matches(netip.MustParseAddr("10.1.9.9")) ||
		!got[0].Entries[1].Matches(netip.MustParseAddr("10.1.2.1")) || got[0].Entries[1].Matches(netip.MustParseAddr("10.1.1.1")) {
		t.Errorf("%v %+v", ok, got)
	}
	if got, ok := ParseAccessLists(""); !ok || len(got) != 0 {
		t.Errorf("sin ACL: %v %v", ok, got)
	}
	for _, bad := range []string{"% Invalid input detected at '^' marker.\n", "Standard IP access list X\n    10 permit algo raro aqui\n"} {
		if _, ok := ParseAccessLists(bad); ok {
			t.Errorf("%q tomado por válido", bad)
		}
	}
}

func TestParseHelpers(t *testing.T) {
	c, _ := ParseInterfaceConfig("interface Vlan10\n ip address 10.0.10.1 255.255.255.0\n ip helper-address 10.9.9.1\n ip helper-address vrf RED 10.9.9.2\n ip helper-address global 10.9.9.3\nend\n")
	got := ParseHelpers(c)
	want := []Helper{{Addr: "10.9.9.1"}, {Addr: "10.9.9.2", Options: []string{"vrf", "RED"}}, {Addr: "10.9.9.3", Options: []string{"global"}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
}
