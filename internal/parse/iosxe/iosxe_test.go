package iosxe

import (
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func fx(t *testing.T, n string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + n + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestNormMAC(t *testing.T) {
	for _, s := range []string{"AABB.CC00.0A01", "aa:bb:cc:00:0a:01", "AA-BB-CC-00-0A-01", "aabbcc000a01"} {
		if m, ok := NormMAC(s); !ok || m != "aabb.cc00.0a01" {
			t.Errorf("%q → %q %v", s, m, ok)
		}
	}
	if _, ok := NormMAC("10.1.1.1"); ok {
		t.Error("una IP no es MAC")
	}
}

func TestTables(t *testing.T) {
	arp, ok := ParseARP(fx(t, "core1_show-ip-arp"))
	if !ok || len(arp) != 4 || arp[1] != (ARP{"10.1.10.20", "aabb.cc00.0a01", "Vlan10"}) {
		t.Fatalf("arp %v %v", arp, ok)
	}
	mac, ok := ParseMACTable(fx(t, "core1_show-mac-address-table"))
	if !ok || len(mac) != 4 || mac[0] != (MACEntry{"10", "aabb.cc00.0a01", "DYNAMIC", "Po1"}) {
		t.Fatalf("mac %v", mac)
	}
	d, ok := ParseDHCPSnooping(fx(t, "acc1_show-ip-dhcp-snooping-binding"))
	if !ok || len(d) != 1 || d[0] != (DHCPBinding{"aabb.cc00.0a01", "10.1.10.20", "10", "Gi1/0/5"}) {
		t.Fatalf("dhcp %v", d)
	}
	st, ok := ParseIfStatus(fx(t, "acc1_show-interfaces-status"))
	if !ok || len(st) != 4 || st[1].Status != "err-disabled" || st[1].Name != "sala-juntas" || st[0].Duplex != "a-half" || st[3].VLAN != "trunk" {
		t.Fatalf("status %+v", st)
	}
}

func TestRoutes(t *testing.T) {
	rs, ok := ParseRoute(fx(t, "core1_show-ip-route"))
	if !ok || len(rs) != 9 {
		t.Fatalf("rutas %d %v", len(rs), ok)
	}
	if r := rs[0]; r.Code != "S*" || r.Hops[0].IP != "10.255.0.254" || r.Hops[0].Iface != "" {
		t.Errorf("default %+v", r)
	}
	ecmp, _ := LongestMatch(rs, netip.MustParseAddr("10.9.1.1"))
	if len(ecmp.Hops) != 2 || ecmp.Hops[1].IP != "10.255.100.6" || ecmp.Hops[1].Iface != "Vlan100" {
		t.Errorf("ecmp %+v", ecmp)
	}
	if r, _ := LongestMatch(rs, netip.MustParseAddr("10.1.10.1")); r.Prefix.Bits() != 32 || !r.Connected {
		t.Errorf("local %+v", r)
	}
	if r, _ := LongestMatch(rs, netip.MustParseAddr("8.8.8.8")); r.Prefix.Bits() != 0 {
		t.Errorf("default %+v", r)
	}
	cef, ok := ParseCEF(fx(t, "core1_show-ip-cef"))
	if !ok || len(cef) != 3 || cef[2].Hops[0] != (NextHop{"10.255.100.2", "Vlan100"}) {
		t.Fatalf("cef %+v", cef)
	}
}

func TestRest(t *testing.T) {
	if n, ok := ParseNTP(fx(t, "core1_show-ntp-status")); !ok || !n.Synced || n.Stratum != 3 {
		t.Errorf("ntp %+v", n)
	}
	if n, ok := ParseNTP("Clock is unsynchronized, stratum 16, no reference clock"); !ok || n.Synced {
		t.Errorf("ntp unsync %+v", n)
	}
	inv, ok := ParseInventory(fx(t, "core1_show-inventory"))
	if !ok || len(inv) != 3 || inv[2].PID != "SFP-10G-SR" || inv[0].SN != "FCW2301A0AA" {
		t.Fatalf("inv %+v", inv)
	}
	v, ok := ParseVersion(fx(t, "core1_show-version"))
	if !ok || v.Host != "CORE1" || v.Model != "C9500-24Y4C" || v.Version != "17.09.04a" || v.Serial != "FCW2301A0AA" || v.DRAMKB != 2907628+6147 || v.Uptime.Hours() < 6*7*24 {
		t.Fatalf("version %+v", v)
	}
	d, ok := ParseDir(fx(t, "core1_dir-flash-"))
	if !ok || d.FS != "flash:" || d.Total != 11353194496 || d.Free != 8000000000 {
		t.Fatalf("dir %+v", d)
	}
	if c, ok := ParseCPU(fx(t, "core1_show-processes-cpu")); !ok || c.FiveSec != 92 {
		t.Errorf("cpu %+v", c)
	}
	if m, ok := ParseMem(fx(t, "core1_show-processes-memory")); !ok || m.Free != 2000000000 {
		t.Errorf("mem %+v", m)
	}
	ifs, ok := ParseInterfaces(fx(t, "acc1_show-interfaces"))
	if !ok || len(ifs) != 2 || ifs[0].CRC != 15234 || ifs[0].Runts != 12 || ifs[0].Duplex != "Half" || ifs[0].MAC != "aabb.cc00.0005" {
		t.Fatalf("ifs %+v", ifs)
	}
	svi, _ := ParseInterfaces(fx(t, "core1_show-interfaces"))
	if len(svi) != 1 || svi[0].IPs[0] != "10.1.10.1/24" {
		t.Errorf("svi %+v", svi)
	}
	br, ok := ParseIPBrief(fx(t, "core1_show-ip-interface-brief"))
	if !ok || len(br) != 3 || br[2].Iface != "Gi1/0/24" {
		t.Errorf("brief %+v", br)
	}
	nb, _ := ParseCDP(fx(t, "core1_show-cdp-neighbors-detail"))
	if len(nb) != 3 || nb[0].LocalIf != "Gi1/0/1" || nb[0].RemoteIf != "Gi1/0/1" || nb[0].MgmtIP != "10.255.0.2" {
		t.Errorf("cdp %+v", nb)
	}
	pc := ParsePortChannels(fx(t, "core1_show-etherchannel-summary"))
	if len(pc["Po1"]) != 2 || pc["Po1"][1] != "Gi1/0/2" {
		t.Errorf("pc %v", pc)
	}
}

func TestLLDP(t *testing.T) {
	nb, ok := ParseLLDP("Local Intf: Gi1/0/7\nChassis id: aabb.cc00.0001\nPort id: Gi0/1\nSystem Name: AP-1\nManagement Addresses:\n    IP: 10.9.9.9\n\nLocal Intf: Gi1/0/8\nPort id: Gi0/2\nSystem Name: AP-2\n")
	if !ok || len(nb) != 2 || nb[0].Device != "AP-1" || nb[0].MgmtIP != "10.9.9.9" || nb[1].LocalIf != "Gi1/0/8" {
		t.Fatalf("%+v", nb)
	}
}

// Formato inesperado: ok=false, nunca "cero filas" silencioso.
func TestFormatoInesperado(t *testing.T) {
	junk := "algo completamente distinto\n% Invalid input detected at '^' marker.\n"
	if _, ok := ParseARP(junk); ok {
		t.Error("arp")
	}
	if _, ok := ParseMACTable(junk); ok {
		t.Error("mac")
	}
	if _, ok := ParseRoute(junk); ok {
		t.Error("route")
	}
	if _, ok := ParseNTP(junk); ok {
		t.Error("ntp")
	}
	if _, ok := ParseDir(junk); ok {
		t.Error("dir")
	}
	if _, ok := ParseIfStatus(junk); ok {
		t.Error("status")
	}
	if _, ok := ParseVersion(junk); ok {
		t.Error("version")
	}
	if _, ok := ParseDir("100 bytes total (500 bytes free)"); ok {
		t.Error("libre > total")
	}
}

// Hijas sin máscara bajo "is subnetted" y códigos en minúscula (i L1, i ia).
func TestRoutesSubnettedYMinusculas(t *testing.T) {
	txt := fx(t, "core2_show-ip-route")
	rs, ok := ParseRoute(txt)
	if !ok || len(rs) != 7 {
		t.Fatalf("rutas %d %v", len(rs), ok)
	}
	if r, _ := LongestMatch(rs, netip.MustParseAddr("172.16.1.5")); r.Code != "O" || r.Prefix.String() != "172.16.1.0/24" || r.Hops[0].IP != "10.0.0.2" {
		t.Errorf("debe ganar la OSPF, no la default: %+v", r)
	}
	if r, _ := LongestMatch(rs, netip.MustParseAddr("172.16.2.9")); !r.Connected || r.Hops[0].Iface != "Vlan20" {
		t.Errorf("conectada %+v", r)
	}
	if r, _ := LongestMatch(rs, netip.MustParseAddr("192.168.2.7")); r.Code != "i L2" || r.Prefix.String() != "192.168.2.0/25" {
		t.Errorf("L2 %+v", r)
	}
	if r, _ := LongestMatch(rs, netip.MustParseAddr("192.168.3.7")); r.Code != "i ia" {
		t.Errorf("ia %+v", r)
	}
	if u := RouteUnread(txt); len(u) != 0 {
		t.Errorf("todo se leyó: %v", u)
	}
	// una hija sin máscara y sin encabezado "is subnetted" no se adivina: se reporta
	if u := RouteUnread("O  172.16.9.0 [110/20] via 10.0.0.2, 00:40:12, Vlan100\n"); len(u) != 1 {
		t.Errorf("sin leer: %v", u)
	}
}

func TestVecinosCapacidades(t *testing.T) {
	nb, _ := ParseCDP(fx(t, "core1_show-cdp-neighbors-detail"))
	if !nb[0].Infra() || len(nb[0].Capabilities) != 2 || nb[0].Capabilities[0] != "Switch" {
		t.Errorf("switch %+v", nb[0])
	}
	cdp := "Device ID: SEP1\n  IP address: 10.1.1.9\nPlatform: Cisco IP Phone 7960,  Capabilities: Host Phone\nInterface: GigabitEthernet1/0/7,  Port ID (outgoing port): Port 1\n\n" +
		"Device ID: AP1\nPlatform: cisco AIR-AP,  Capabilities: Trans-Bridge\nInterface: GigabitEthernet1/0/8,  Port ID (outgoing port): Gi0\n"
	nb, _ = ParseCDP(cdp)
	if len(nb) != 2 || nb[0].Infra() || nb[1].Infra() {
		t.Errorf("teléfono y AP no son infraestructura: %+v", nb)
	}
	ll := "Local Intf: Gi1/0/7\nPort id: P1\nSystem Name: PH\nSystem Capabilities: B,T\nEnabled Capabilities: B,T\n\n" +
		"Local Intf: Gi1/0/8\nPort id: Gi0/2\nSystem Name: SW9\nSystem Capabilities: B,R\nEnabled Capabilities: B,R\n\nLocal Intf: Gi1/0/9\nPort id: x\nSystem Name: SIN\n"
	nb, _ = ParseLLDP(ll)
	if len(nb) != 3 || nb[0].Infra() || !nb[1].Infra() || !nb[2].Infra() {
		t.Errorf("lldp: %+v", nb)
	}
}

func TestRutasDescarte(t *testing.T) {
	rs, _ := ParseRoute("O        10.9.0.0/16 is a summary, 00:10:00, Null0\n")
	if len(rs) != 1 || len(rs[0].Hops) != 1 || rs[0].Hops[0].Iface != "Null0" {
		t.Errorf("resumen %+v", rs)
	}
	cef, _ := ParseCEF("Prefix               Next Hop             Interface\n0.0.0.0/0            10.0.0.2             Vlan1\n10.9.0.0/16          drop                 Null0\n")
	if r, _ := LongestMatch(cef, netip.MustParseAddr("10.9.1.1")); r.Prefix.Bits() != 16 || r.Hops[0].Iface != "Null0" {
		t.Errorf("drop %+v", r)
	}
}

// Vecinos CDP/LLDP de IOS-XE y NX-OS (fixtures de topología) con sus campos de remoto.
func TestVecinosIOSyNXOS(t *testing.T) {
	ns, ok := ParseCDP(fx(t, "sw1_show-cdp-neighbors-detail"))
	if !ok || len(ns) != 3 {
		t.Fatalf("cdp = %+v", ns)
	}
	n := ns[2]
	if n.Device != "N9K-2(FDO12345678)" || n.LocalRaw != "GigabitEthernet1/0/3" || n.LocalIf != "Gi1/0/3" || n.RemoteRaw != "Ethernet1/49" || n.RemoteIf != "Eth1/49" || n.Platform != "N9K-C93180YC-EX" ||
		n.MgmtIP != "192.168.1.12" || n.Version != "9.3(8)" || n.NativeVLAN != "1" || n.Duplex != "full" || n.Protocol != "cdp" {
		t.Fatalf("vecino = %+v", n)
	}
	ll, _ := ParseLLDP(fx(t, "sw1_show-lldp-neighbors-detail"))
	if len(ll) != 1 || ll[0].Device != "SW3" || ll[0].LocalIf != "Gi1/0/4" || ll[0].RemoteIf != "Gi1/0/24" || ll[0].MgmtIP != "10.0.0.3" || ll[0].Version != "17.6.5" {
		t.Fatalf("lldp = %+v", ll)
	}
	cdp, _ := ParseCDP(fx(t, "n9k1_show-cdp-neighbors-detail"))
	if len(cdp) != 1 || cdp[0].Device != "N9K-1" || cdp[0].LocalRaw != "Ethernet1/49" || cdp[0].MgmtIP != "192.168.1.11" || cdp[0].Version != "9.3(8)" {
		t.Fatalf("cdp nx-os = %+v", cdp)
	}
	lldp, _ := ParseLLDP(fx(t, "n9k1_show-lldp-neighbors-detail"))
	if len(lldp) != 2 || lldp[1].Device != "N9K-4" || lldp[1].LocalRaw != "Eth1/51" || lldp[1].RemoteRaw != "Ethernet1/2" || lldp[1].MgmtIP != "10.0.0.14" || lldp[1].NativeVLAN != "1" {
		t.Fatalf("lldp nx-os = %+v", lldp)
	}
	pc := ParsePortChannels(fx(t, "n9k1_show-port-channel-summary"))
	if got := strings.Join(pc["Po10"], ","); got != "Eth1/1,Eth1/2,Eth1/3,Eth1/4" {
		t.Fatalf("port-channel = %q", got)
	}
}

func TestSTPRoots(t *testing.T) {
	if got := ParseSTPRoots(fx(t, "sw1_show-spanning-tree")); len(got) != 1 || got[0] != 1 {
		t.Fatalf("root = %v", got)
	}
}

func TestShortIf(t *testing.T) {
	for in, want := range map[string]string{"GigabitEthernet1/0/1": "Gi1/0/1", "Gi1/0/1": "Gi1/0/1", "Ethernet1/49": "Eth1/49", "Eth1/49": "Eth1/49",
		"TenGigabitEthernet1/1/1": "Te1/1/1", "Port-channel1": "Po1", "FastEthernet0/1": "Fa0/1", "mgmt0": "mgmt0", "TwentyFiveGigE1/0/1": "Twe1/0/1"} {
		if got := ShortIf(in); got != want {
			t.Errorf("ShortIf(%q) = %q, quiero %q", in, got, want)
		}
	}
}

// Enrutamiento y STP: OSPF, BGP, HSRP, resumen de rutas y raíces de STP.
func TestRoutingYSTP(t *testing.T) {
	ospf, ok := ParseOSPF(fx(t, "dist1_show-ip-ospf-neighbor"))
	if !ok || len(ospf) != 2 || ospf[0].State != "FULL" || ospf[0].Role != "BDR" || ospf[1].Role != "-" || ospf[1].Interface != "GigabitEthernet1/0/24" || ospf[1].Address != "203.0.113.2" {
		t.Errorf("ospf %+v", ospf)
	}
	bgp, ok := ParseBGP(fx(t, "dist1_show-ip-bgp-summary"))
	if !ok || len(bgp) != 2 || !bgp[0].Established || bgp[0].Prefixes != 118 || bgp[0].AS != "65002" || bgp[0].UpDown != "1w2d" {
		t.Errorf("bgp %+v", bgp)
	}
	// IPv6 largo: IOS parte la fila en dos líneas
	bgp, _ = ParseBGP("Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n2001:DB8::1\n                4        65002      10      10        5    0    0 00:01:10 Idle\n")
	if len(bgp) != 1 || bgp[0].State != "Idle" || bgp[0].Established || len(bgp[0].Lines) != 2 {
		t.Errorf("bgp partido %+v", bgp)
	}
	if n, ok := ParseBGP("% BGP not active"); !ok || n != nil {
		t.Errorf("bgp apagado %v %v", n, ok)
	}
	hs, ok := ParseHSRP(fx(t, "dist1_show-standby-brief"))
	if !ok || len(hs) != 2 || hs[0].State != "Active" || hs[1].State != "Standby" || hs[1].Active != "198.51.100.131" || hs[1].VIP != "198.51.100.129" {
		t.Errorf("hsrp %+v", hs)
	}
	rs, ok := ParseRouteSummary(fx(t, "dist1_show-ip-route-summary"))
	if !ok || len(rs) != 5 || rs[3] != (RouteSummary{"ospf 1", 3, 12}) || rs[4] != (RouteSummary{"bgp 65001", 138, 0}) {
		t.Errorf("resumen %+v", rs)
	}
	root, ok := ParseSTPRootTable(fx(t, "dist1_show-spanning-tree-root"))
	if !ok || len(root) != 3 || root[1] != (STPRoot{"VLAN0010", "24586", "00a3.d14f.0001", ""}) {
		t.Errorf("stp root %+v", root)
	}
	det, ok := ParseSTPDetail(fx(t, "lab1_show-spanning-tree-detail"))
	if !ok || len(det) != 1 || det[0].Name != "VLAN0010" || det[0].Changes != 40 || !det[0].SinceOK || det[0].Since.Minutes() != 70 || det[0].From != "GigabitEthernet1/0/7" || len(det[0].Lines) != 2 {
		t.Errorf("stp detail %+v", det)
	}
	if n, ok := ParseSTPDetail("No spanning tree instance exists."); !ok || n != nil {
		t.Errorf("sin instancias %v %v", n, ok)
	}
	for in, want := range map[string]time.Duration{"00:01:10": 70 * time.Second, "3d04h": 76 * time.Hour, "1w2d": 9 * 24 * time.Hour} {
		if d, ok := IOSDuration(in); !ok || d != want {
			t.Errorf("IOSDuration(%q) = %v %v", in, d, ok)
		}
	}
	if _, ok := IOSDuration("never"); ok {
		t.Error("never no es duración")
	}
	junk := "% Invalid input detected at '^' marker.\n"
	if _, ok := ParseOSPF(junk); ok {
		t.Error("ospf")
	}
	if _, ok := ParseBGP(junk); ok {
		t.Error("bgp")
	}
	if _, ok := ParseHSRP(junk); ok {
		t.Error("hsrp")
	}
}

// Lo que el análisis y el cambio asistido piden: línea citada, contadores con evidencia, uptime y razones de reinicio.
func TestCampos(t *testing.T) {
	c, ok := ParseCPU(fx(t, "lab1_show-processes-cpu-sorted"))
	if !ok || c.FiveMin != 45 || !strings.HasPrefix(c.Line, "CPU utilization for five seconds: 48%") {
		t.Errorf("cpu %+v", c)
	}
	m, ok := ParseMem(fx(t, "lab1_show-processes-memory-sorted"))
	if !ok || m.Free != 1061783824 || !strings.HasPrefix(m.Line, "Processor Pool Total") {
		t.Errorf("mem %+v", m)
	}
	if m, ok := ParseMem("Processor  7F8A1C000  1000  400  600\n"); !ok || m.Total != 1000 || m.Free != 600 {
		t.Errorf("show memory statistics %+v", m)
	}
	ifs, _ := ParseInterfaces("GigabitEthernet1/0/7 is up, line protocol is up\n  Input queue: 0/2000/12/0 (size/max/drops/flushes); Total output drops: 3\n     4 interface resets\n")
	if len(ifs) != 1 || ifs[0].Raw != "GigabitEthernet1/0/7" || ifs[0].Name != "Gi1/0/7" || ifs[0].InDrops != 12 || ifs[0].Resets != 4 || ifs[0].OutDrops != 3 ||
		!strings.HasPrefix(ifs[0].Evidence["input_drops"], "  Input queue") {
		t.Errorf("interfaces %+v", ifs)
	}
	v, ok := ParseVersion(fx(t, "lab1_show-version"))
	if !ok || !v.UptimeKnown || v.Uptime.Hours() != 412+0.2 || !strings.HasPrefix(v.UptimeLine, "SW1 uptime is 2 weeks") || len(v.Reasons) != 2 {
		t.Errorf("version %+v", v)
	}
	nx, ok := ParseVersion("Cisco Nexus Operating System (NX-OS) Software\n  NXOS: version 9.3(8)\n  cisco Nexus9000 C93180YC-EX Chassis\n  Device name: N9K-1\nKernel uptime is 3 day(s), 2 hour(s)\n")
	if !ok || nx.Host != "N9K-1" || nx.Version != "9.3(8)" || nx.Model != "C93180YC-EX" || nx.Uptime.Hours() != 74 {
		t.Errorf("nx-os %+v", nx)
	}
	br, _ := ParseIPBrief(fx(t, "dist1_show-ip-interface-brief"))
	if len(br) != 6 || br[0].IP != "unassigned" || br[0].Status != "administratively down" || br[0].Protocol != "down" || br[3].Raw != "GigabitEthernet1/0/1" || br[3].Iface != "Gi1/0/1" {
		t.Errorf("brief %+v", br)
	}
}

// Lo que lee la verificación previa a un upgrade.
func TestSistema(t *testing.T) {
	b, ok := ParseBoot("BOOT variable = flash:packages.conf;\nMANUAL_BOOT variable = yes\nBoot Variables on next reload:\nBOOT variable = flash:next.bin,12;\n")
	if !ok || !b.Manual || len(b.Entries) != 1 || b.Entries[0] != "flash:next.bin" {
		t.Errorf("boot %+v", b)
	}
	if _, ok := ParseBoot("Switch#"); ok {
		t.Error("boot sin variable")
	}
	pk, ok := ParseInstallSummary("  IMG   C    17.09.04a.0.1\n  SMU   U    smu_1.bin\n")
	if !ok || len(pk) != 2 || pk[1] != (InstallPkg{"SMU", "U", "smu_1.bin"}) {
		t.Errorf("install %+v", pk)
	}
	r, ok := ParseRedundancy("Operating Redundancy Mode = sso\n STANDBY HOT\n")
	if !ok || r.Mode != "sso" || !r.StandbyHot || r.Simplex {
		t.Errorf("redundancia %+v", r)
	}
	if _, ok := ParseRedundancy(""); ok {
		t.Error("redundancia vacía")
	}
	if m, ok := ParseVerifyMD5("Verified (flash:cat9k.bin) = ABCDEFABCDEFABCDEFABCDEFABCDEFAB"); !ok || m.Path != "flash:cat9k.bin" || m.Sum != "abcdefabcdefabcdefabcdefabcdefab" {
		t.Errorf("md5 %+v", m)
	}
	h, ok := ParseConfigHeader("! Last configuration change at 09:40:11 UTC Tue Nov 3 2026 by admin\n! NVRAM config last updated at 09:30:00 UTC Tue Nov 3 2026 by admin\n")
	if !ok || h.SavedAt.IsZero() || !h.SavedAt.Before(h.LastChangeAt) {
		t.Errorf("cabecera %+v", h)
	}
	d, ok := ParseDir("Directory of flash:/\n\n    1  -rw-   500  Nov 3 2026 cat9k.bin\n\n1000 bytes total (400 bytes free)\n")
	if !ok || len(d.Files) != 1 || d.Files[0] != (DirFile{"cat9k.bin", 500}) {
		t.Errorf("dir %+v", d)
	}
	v, _ := ParseVersion("SW uptime is 1 day\nSystem image file is \"flash:packages.conf\"\nInstallation mode is INSTALL\nConfiguration register is 0x102\n")
	if v.Image != "flash:packages.conf" || v.InstallMode != "install" || v.Register != "0x102" {
		t.Errorf("version %+v", v)
	}
}

func TestRelojYLog(t *testing.T) {
	if c, ok := ParseClock("*10:05:00.123 CST Wed Nov 4 2026\n"); !ok || c.Format("2006-01-02 15:04:05") != "2026-11-04 10:05:00" {
		t.Errorf("reloj %v %v", c, ok)
	}
	l, ok := ParseLogLine("*Nov  4 09:58:12.345: %LINK-3-UPDOWN: Interface Gi1/0/1, changed state to down")
	if !ok || !l.Unsynced || l.Year != 0 || l.Month != "Nov" || l.Zone != "" || l.Severity != 3 || !strings.HasPrefix(l.Text, "%LINK-3-UPDOWN") {
		t.Errorf("log %+v", l)
	}
	l, ok = ParseLogLine("000045: Nov  4 2026 10:00:01.123 UTC: %SYS-5-CONFIG_I: Configured from console")
	if at, err := l.At(2026); !ok || err != nil || l.Zone != "UTC" || l.Year != 2026 || at.Second() != 1 || l.Severity != 5 {
		t.Errorf("log con año %+v %v", l, err)
	}
	if _, ok := ParseLogLine("Syslog logging: enabled"); ok {
		t.Error("sin marca")
	}
	if !LogUptimeStamp("3d04h: %SYS-5-RESTART: x") || LogUptimeStamp("*Nov  4 09:58:12: %X-1-Y: z") {
		t.Error("marca de uptime")
	}
}

// Formato de la documentación de Cisco; sin validar en laboratorio.
const ifConfigSample = `Building configuration...

Current configuration : 187 bytes
!
interface GigabitEthernet1/0/5
 description Impresora  piso 2
 switchport access vlan 10
 switchport mode access
 switchport voice vlan 110
 shutdown
 spanning-tree portfast
end
`

func TestParseInterfaceConfig(t *testing.T) {
	c, ok := ParseInterfaceConfig(ifConfigSample)
	if !ok || c.Name != "GigabitEthernet1/0/5" || c.Description != "Impresora  piso 2" || !c.HasDescription ||
		c.AccessVlan != "10" || c.VoiceVlan != "110" || !c.Shutdown || c.Mode != "access" || c.Trunk || c.Routed || c.ChannelGroup {
		t.Fatalf("%+v ok=%v", c, ok)
	}
	tr, _ := ParseInterfaceConfig("interface Gi1/0/1\n switchport trunk allowed vlan 1,2\n channel-group 3 mode on\nend\n")
	if !tr.Trunk || !tr.ChannelGroup {
		t.Fatalf("%+v", tr)
	}
	if r, _ := ParseInterfaceConfig("interface Gi1/0/1\n no switchport\n ip address 10.0.0.1 255.255.255.0\nend\n"); !r.Routed {
		t.Fatalf("%+v", r)
	}
	if _, ok := ParseInterfaceConfig("% Invalid input detected at '^' marker.\n"); ok {
		t.Fatal("un error no es una interfaz")
	}
}

// Hallazgo 3: la VLAN de voz puede ser dot1p, untagged o none; se guarda tal cual, no como 0.
func TestParseInterfaceConfigKeepsVoiceVlanText(t *testing.T) {
	for _, v := range []string{"dot1p", "untagged", "none", "110"} {
		c, _ := ParseInterfaceConfig("interface Gi1/0/1\n switchport mode access\n switchport voice vlan " + v + "\nend\n")
		if c.VoiceVlan != v {
			t.Errorf("voice vlan %q se leyó como %q", v, c.VoiceVlan)
		}
	}
	if c, _ := ParseInterfaceConfig("interface Gi1/0/1\n switchport access vlan dynamic\nend\n"); c.AccessVlan != "dynamic" {
		t.Errorf("access vlan = %q", c.AccessVlan)
	}
}

// Hallazgo 2: lo que hace de un puerto uno ruteado o de administración.
func TestParseInterfaceConfigL3Markers(t *testing.T) {
	for name, body := range map[string]string{
		"ip address": " ip address 10.0.0.1 255.255.255.0\n",
		"ipv6":       " ipv6 address 2001:db8::1/64\n",
		"vrf":        " vrf forwarding Mgmt-vrf\n",
		"ip vrf":     " ip vrf forwarding Mgmt-vrf\n",
		"ip nat":     " ip nat outside\n",
		"unnumbered": " ip unnumbered Loopback0\n",
		"ipv6 unnum": " ipv6 unnumbered Loopback0\n",
		"secondary":  " ip address 10.0.0.2 255.255.255.0 secondary\n",
	} {
		if c, _ := ParseInterfaceConfig("interface GigabitEthernet0/0\n" + body + "end\n"); !c.L3 {
			t.Errorf("%s: L3 = false", name)
		}
	}
	if c, _ := ParseInterfaceConfig("interface Gi1/0/1\n switchport mode access\n spanning-tree portfast\nend\n"); c.L3 {
		t.Error("puerto de acceso marcado como L3")
	}
}

func TestParseSwitchportAdminMode(t *testing.T) {
	const out = "Name: Gi1/0/5\nSwitchport: Enabled\nAdministrative Mode: static access\nOperational Mode: static access\n"
	if m, ok := ParseSwitchportMode(out); !ok || m != "static access" {
		t.Fatalf("%q %v", m, ok)
	}
	if m, _ := ParseSwitchportMode("Name: Gi1/0/5\nSwitchport: Enabled\nAdministrative Mode: dynamic auto\n"); m != "dynamic auto" {
		t.Fatalf("%q", m)
	}
	if _, ok := ParseSwitchportMode("Name: Gi0/0\nSwitchport: Disabled\n"); ok {
		t.Fatal("puerto ruteado: no hay modo administrativo")
	}
}

func TestParseVlanID(t *testing.T) {
	const ok = "VLAN Name                             Status    Ports\n---- -------------------------------- --------- -------------------------------\n20   VLAN0020                         active    Gi1/0/1, Gi1/0/2\n"
	if st, found := ParseVlanID(ok, 20); !found || st != "active" {
		t.Fatalf("%q %v", st, found)
	}
	if _, found := ParseVlanID("VLAN id 99 not found in current VLAN database\n", 99); found {
		t.Fatal("VLAN inexistente")
	}
	if _, found := ParseVlanID(ok, 21); found {
		t.Fatal("otra VLAN")
	}
}

func TestParseInterfacesPortadora(t *testing.T) {
	ifs, ok := ParseInterfaces(fx(t, "sw3560cx_show-interfaces"))
	if !ok || len(ifs) != 1 {
		t.Fatalf("%v %+v", ok, ifs)
	}
	i := ifs[0]
	if i.Resets != 7 || i.LostCarrier != 4 || i.NoCarrier != 2 || i.Evidence["lost_carrier"] == "" {
		t.Fatalf("%+v", i)
	}
	if _, has := i.Evidence["carrier_transitions"]; has || i.CarrierTransitions != 0 {
		t.Fatalf("el switch no imprime carrier transitions: %+v", i)
	}
	// Los routers y algunas versiones sí imprimen "N carrier transitions".
	ifs, _ = ParseInterfaces("Serial0/0/0 is up, line protocol is up\n     12 carrier transitions     DCD=up  DSR=up  DTR=up  RTS=up  CTS=up\n")
	if len(ifs) != 1 || ifs[0].CarrierTransitions != 12 || ifs[0].Evidence["carrier_transitions"] == "" {
		t.Fatalf("%+v", ifs)
	}
}

func TestParseProcessMemory(t *testing.T) {
	ps, ok := ParseProcessMemory(fx(t, "sw3560cx_show-processes-memory-sorted"))
	if !ok || len(ps) != 7 {
		t.Fatalf("%v %d", ok, len(ps))
	}
	if ps[3].PID != 66 || ps[3].Name != "HRPC qos request" || ps[3].Holding != 2012188 || ps[3].Allocated != 2305552 || ps[3].Freed != 301696 {
		t.Fatalf("%+v", ps[3])
	}
	if ps[0].Name != "*Init*" || ps[2].Holding != 1331216 {
		t.Fatalf("%+v %+v", ps[0], ps[2])
	}
	// El fixture de IOS-XE (lab1) trae el mismo formato.
	if ps, ok = ParseProcessMemory(fx(t, "lab1_show-processes-memory-sorted")); !ok || len(ps) != 2 || ps[1].Name != "BGP Router" {
		t.Fatalf("lab1: %v %+v", ok, ps)
	}
	// Otro comando (show processes memory platform) o texto ajeno no se reconoce.
	for _, bad := range []string{"", "Pid Text Data Stack Dynamic RefCnt Name\n 1 100 200 300 400 1 init\n", fx(t, "core1_show-version")} {
		if ps, ok := ParseProcessMemory(bad); ok || len(ps) != 0 {
			t.Fatalf("aceptó %q", bad)
		}
	}
	// Un Holding negativo (se ve en versiones con contadores desbordados) no rompe la fila.
	if ps, ok = ParseProcessMemory(" PID TTY  Allocated      Freed    Holding    Getbufs    Retbufs Process\n  10   0       100        200       -100          0          0 Weird Proc\n"); !ok || ps[0].Holding != -100 {
		t.Fatalf("%v %+v", ok, ps)
	}
}
