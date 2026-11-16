package asa

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fx(t testing.TB, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func eq[T comparable](t *testing.T, what string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, quería %v", what, got, want)
	}
}

func TestFailoverAS(t *testing.T) {
	f, ok := ParseFailover(fx(t, "as_show-failover.txt"))
	if !ok {
		t.Fatal("no reconoció show failover")
	}
	eq(t, "On", f.On, true)
	eq(t, "Unit", f.Unit, "Primary")
	eq(t, "LAN", f.LANName+"|"+f.LANIface+"|"+f.LANState, "folink|GigabitEthernet0/3|up")
	eq(t, "unit poll", f.UnitPoll*100+f.UnitHold, int64(115))
	eq(t, "monitored", f.Monitored*10000+f.MonitoredMax, int64(21292))
	eq(t, "version", f.VersionOurs+"/"+f.VersionMate, "9.22(1)7/9.22(1)7")
	eq(t, "serie", f.SerialOurs+"/"+f.SerialMate, "9ABCDEF0001/9ABCDEF0002")
	eq(t, "last", f.LastFailover[0], "10:21:44 UTC Nov 9 2026")
	this, _ := f.Host(true)
	eq(t, "this role/state", this.Role+"|"+this.State, "Primary|Active") // la línea trae un espacio al final
	eq(t, "this active", this.ActiveTime, int64(5120))
	other, _ := f.Host(false)
	eq(t, "other state", other.State, "Standby Ready")
	if len(other.Ifaces) != 2 || other.Ifaces[1].State != "Failed" || other.Ifaces[1].Monitoring != "Waiting" || other.Ifaces[1].Context != "" {
		t.Errorf("interfaces del par: %+v", other.Ifaces)
	}
	eq(t, "link", f.LinkName+"|"+f.LinkState, "folink|up")
	if r, ok := f.Stat("Umbrella Device-ID"); !ok || r.Rerr != 0 {
		t.Errorf("fila desconocida de 9.22 perdida: %+v %v", r, ok)
	}
	if r, _ := f.Stat("STS Table"); r.Rerr != 2 {
		t.Errorf("STS Table = %+v", r)
	}
	if r, _ := f.Stat("sys cmd"); r.Xmit != 380 {
		t.Errorf("sys cmd = %+v", r)
	}
	eq(t, "filas", len(f.Stats), 20)
	eq(t, "RecvQ", f.RecvQ, Queue{0, 4, 1873})
	eq(t, "XmitQ", f.XmitQ, Queue{0, 9, 2394})
}

func TestFailoverAA(t *testing.T) {
	f, ok := ParseFailover(fx(t, "aa_show-failover.txt"))
	if !ok {
		t.Fatal("no reconoció show failover A/A")
	}
	this, _ := f.Host(true)
	eq(t, "role", this.Role, "Primary")
	if len(this.Groups) != 2 || this.Groups[0].State != "Active" || this.Groups[0].ActiveTime != 2896 || this.Groups[1].State != "Standby Ready" {
		t.Errorf("grupos: %+v", this.Groups)
	}
	eq(t, "ifaces", len(this.Ifaces), 6)
	eq(t, "ctx de la interfaz", this.Ifaces[4].Context+"/"+this.Ifaces[4].Name+"/"+this.Ifaces[4].Monitoring, "ctx2/outside/Waiting")
	eq(t, "ip con v6", this.Ifaces[1].IP, "10.130.8.5/fe80::1:5")
	eq(t, "last grupo 2", f.LastFailover[2], "13:40:06 UTC Nov 9 2026")
	eq(t, "link", f.LinkIface, "Ethernet1/8")
	if _, ok := f.Stat("Umbrella Device-ID"); !ok {
		t.Error("fila Umbrella perdida")
	}
	eq(t, "RecvQ", f.RecvQ, Queue{0, 5, 1873})
}

// Los mismos datos con espacios en lugar de tabulaciones dan el mismo resultado.
func TestFailoverTabsYEspacios(t *testing.T) {
	src := fx(t, "as_show-failover.txt")
	a, _ := ParseFailover(src)
	b, _ := ParseFailover(strings.ReplaceAll(src, "\t", "        "))
	eq(t, "filas", len(a.Stats), len(b.Stats))
	eq(t, "RecvQ", a.RecvQ, b.RecvQ)
	ha, _ := a.Host(true)
	hb, _ := b.Host(true)
	eq(t, "estado", ha.State, hb.State)
}

// Ours y Mate distintos: un intercambio de columnas no pasa desapercibido.
func TestFailoverOursMate(t *testing.T) {
	f, _ := ParseFailover("Failover On\nVersion: Ours 9.22(1)7, Mate 9.20(2)\nSerial Number: Ours AAA, Mate BBB\n")
	eq(t, "version", f.VersionOurs+"/"+f.VersionMate, "9.22(1)7/9.20(2)")
	eq(t, "serie", f.SerialOurs+"/"+f.SerialMate, "AAA/BBB")
}

func TestFailoverFilasDesconocidasYOff(t *testing.T) {
	src := "Failover On\nStateful Failover Logical Update Statistics\n  Link : Unconfigured.\n  Stateful Obj xmit xerr rcv rerr\n  Nueva Fila X   1 2 3 4\n  basura sin numeros\n  General 5 0 5 0\n"
	f, ok := ParseFailover(src)
	if !ok || len(f.Stats) != 2 || f.Stats[0].Name != "Nueva Fila X" || f.Stats[0].Rerr != 4 {
		t.Errorf("filas: %+v ok=%v", f.Stats, ok)
	}
	f, ok = ParseFailover("Failover Off\nFailover unit Secondary\n")
	if !ok || f.On || f.Unit != "Secondary" {
		t.Errorf("off: %+v", f)
	}
	if _, ok := ParseFailover("% Invalid input\n"); ok {
		t.Error("aceptó basura")
	}
}

func TestFailoverState(t *testing.T) {
	st, ok := ParseFailoverState(fx(t, "aa_show-failover-state.txt"))
	if !ok || len(st.Rows) != 6 {
		t.Fatalf("A/A: %d filas ok=%v: %+v", len(st.Rows), ok, st.Rows)
	}
	var g1 FailoverStateRow
	for _, r := range st.Rows {
		if r.Group == 1 && r.This {
			g1 = r
		}
	}
	eq(t, "grupo 1", g1.State+"|"+g1.Reason+"|"+g1.Time, "Failed|Backplane Failure|03:42:29 UTC Apr 17 2009")
	eq(t, "cfg", st.ConfigState, "Sync Done")
	eq(t, "comm", st.CommState, "Mac set")

	st, ok = ParseFailoverState(fx(t, "as_show-failover-state.txt"))
	if !ok || len(st.Rows) != 2 {
		t.Fatalf("A/S: %+v", st.Rows)
	}
	eq(t, "this", st.Rows[0].State+"|"+st.Rows[0].Role+"|"+st.Rows[0].Reason, "Active|Primary|None")
	eq(t, "other", st.Rows[1].State+"|"+st.Rows[1].Reason+"|"+st.Rows[1].Time, "Standby Ready|Comm Failure|10:21:44 UTC Nov 9 2026")
}

func TestFailoverHistory(t *testing.T) {
	h, ok := ParseFailoverHistory(fx(t, "aa_show-failover-history.txt"))
	if !ok || len(h) != 7 {
		t.Fatalf("%d entradas ok=%v", len(h), ok)
	}
	eq(t, "to", h[1].From+">"+h[1].To+">"+h[1].Reason, "Active>Failed>Interface check")
	eq(t, "this host", h[1].ThisHost, 3)
	eq(t, "detalle", len(h[1].Details), 3) // admin, ctx-1, ctx-2
	eq(t, "motivo con doble espacio", h[2].Reason, "Failover state check delayed due to mate failure")
	d, _ := ParseFailoverHistory(fx(t, "aa_show-failover-history-details.txt"))
	peer := 0
	for _, e := range d {
		if e.Peer {
			peer++
		}
	}
	eq(t, "entradas", len(d), 12)
	eq(t, "del par", peer, 6)
	eq(t, "from con espacios", d[4].From, "Active Applying Config")
}

func TestChecksumModeCounts(t *testing.T) {
	c, ok := ParseChecksum(fx(t, "as_show-checksum.txt"))
	eq(t, "checksum", c, "0a1b2c3d4e5f60718293a4b5c6d7e8f9")
	eq(t, "ok", ok, true)
	if _, ok := ParseChecksum("Cryptochecksum: zz"); ok {
		t.Error("aceptó checksum no hexadecimal")
	}
	m, _ := ParseMode(fx(t, "sys_show-mode.txt"))
	eq(t, "mode", m, "multiple")
	m, _ = ParseMode(fx(t, "ctx_show-mode.txt"))
	eq(t, "mode ctx", m, "multiple")
	cc, ok := ParseCount(fx(t, "as_show-conn-count.txt"))
	if !ok || len(cc) != 4 || cc[0].InUse != 40 || cc[0].MostUsed != 55 || cc[3].Name != "centralized connections" {
		t.Errorf("conn count: %+v", cc)
	}
	xc, _ := ParseCount(fx(t, "as_show-xlate-count.txt"))
	if len(xc) != 1 || xc[0].InUse != 12 {
		t.Errorf("xlate count: %+v", xc)
	}
}

func TestContexts(t *testing.T) {
	l, total, ok := ParseContexts(fx(t, "sys_show-context.txt"))
	if !ok || len(l) != 3 || total != 3 {
		t.Fatalf("%+v %d %v", l, total, ok)
	}
	eq(t, "admin", l[0].Admin && l[0].Name == "admin", true)
	eq(t, "ifaces", strings.Join(l[0].Interfaces, ","), "Ethernet1/1.100,Management1/1")
	eq(t, "class", l[1].Class, "gold")
	eq(t, "modo", l[2].Mode, "Transparent")
	eq(t, "url", l[2].URL, "ftp://192.0.2.10/ctx2.cfg")
}

func TestResourceUsage(t *testing.T) {
	r, ok := ParseResourceUsage(fx(t, "sys_show-resource-usage-summary.txt"))
	if !ok || len(r) != 8 {
		t.Fatalf("%d filas", len(r))
	}
	eq(t, "rate", r[0].Rate && r[0].Name == "Syslogs", true)
	eq(t, "flag", r[0].Flag+"|"+strconv.FormatInt(r[0].Limit, 10), "U|12000")
	eq(t, "denied", r[4].Denied, int64(1704))
	eq(t, "nombre largo", r[6].Name, "Other VPN Sessions")
	s, _ := ParseResourceUsage(fx(t, "sys_show-resource-usage-system.txt"))
	eq(t, "N/A", s[2].Limit, int64(-1))
	eq(t, "contexto", s[0].Context, "System")
	c, _ := ParseResourceUsage(fx(t, "ctx_show-resource-usage-context-admin.txt"))
	eq(t, "ctx", len(c) > 0 && c[0].Context == "admin", true)
}

func TestAspDrop(t *testing.T) {
	d, ok := ParseAspDrop(fx(t, "as_show-asp-drop.txt"))
	if !ok || len(d.Rows) != 9 {
		t.Fatalf("%d filas", len(d.Rows))
	}
	eq(t, "acl frame", d.Rows[3].Keyword+"|"+d.Rows[3].Section, "acl-drop|frame")
	eq(t, "cuenta", d.Rows[3].Count, int64(2210))
	eq(t, "acl flow", d.Rows[6].Section, "flow")
	eq(t, "clear", d.Cleared["frame"], "08:15:02 UTC Nov 9 2026 by enable_15")
	eq(t, "never", d.Cleared["flow"], "Never")
}

func TestCluster(t *testing.T) {
	for _, n := range []string{"cl_show-cluster-info.txt", "cl_show-cluster-info-control-data.txt"} {
		c, ok := ParseClusterInfo(fx(t, n))
		if !ok || len(c.Members) != 4 {
			t.Fatalf("%s: %+v", n, c)
		}
		eq(t, n+" nombre", c.Name+"|"+c.Mode, "cluster1|spanned")
		m := c.Members[0]
		eq(t, n+" local", m.Local && m.IsControl() && m.ID == 2 && m.Serial == "FCH0000A002", true)
		eq(t, n+" último", c.Members[3].Name+"|"+c.Members[3].LastLeave[:12], "unit-2-1|20:24:55 UTC")
		eq(t, n+" data", c.Members[1].IsControl(), false)
	}
	h, ok := ParseClusterHealth(fx(t, "cl_show-cluster-info-health.txt"))
	if !ok || len(h.Members) != 3 || !h.Members[0].Local || h.Members[2].Name != "unit-1-3" {
		t.Fatalf("health: %+v", h)
	}
	eq(t, "filas", len(h.Rows), 4)
	eq(t, "valor", h.Rows[1].Label+"="+h.Rows[1].Values[2], "Port-channel1=down")
}

func TestVersion(t *testing.T) {
	v, ok := ParseVersion(fx(t, "sys_show-version.txt"))
	if !ok {
		t.Fatal("version")
	}
	eq(t, "sw", v.Software+"|"+v.SSP, "9.17(1)|2.11(1.288i)")
	eq(t, "hw", v.Model, "FPR-2130")
	eq(t, "ram", v.RAMMB, int64(13703))
	eq(t, "serie", v.Serial, "FCH0000A001")
	eq(t, "licencia", v.LicenseMode, "Smart Licensing")
	eq(t, "failover", v.FailoverFeature, "Active/Active")
	eq(t, "contextos", v.Contexts, int64(5))
	eq(t, "host", v.Hostname+"|"+v.Uptime, "asa|1 day 23 hours")
}

func TestRunningConfigNormalizada(t *testing.T) {
	a, ok := NormalizeRunningConfig(fx(t, "sys_show-running-config.txt"))
	if !ok {
		t.Fatal("sin ASA Version")
	}
	for _, bad := range []string{": Saved", "Cryptochecksum", "show running-config"} {
		if strings.Contains(a, bad) {
			t.Errorf("quedó %q", bad)
		}
	}
	if !strings.Contains(a, "hostname asa") || !strings.Contains(a, ": end") {
		t.Error("quitó de más")
	}
	// mismo contenido, otras líneas volátiles
	b, _ := NormalizeRunningConfig(strings.Replace(fx(t, "sys_show-running-config.txt"), ": Saved", ": Written by enable_15 at 10:00:00.000 UTC Mon Nov 9 2026", 1) + "asa#\n")
	b = strings.Replace(b, "Cryptochecksum:ffff", "Cryptochecksum:0", 1)
	eq(t, "estable", a, b)
}

func TestPacketTracer(t *testing.T) {
	for _, n := range []string{"as_show-packet-tracer.txt", "as_show-packet-tracer-xml.txt"} {
		p, ok := ParsePacketTrace(fx(t, n))
		if !ok || !p.Allowed() {
			t.Fatalf("%s: %+v", n, p)
		}
		eq(t, n+" if", p.InputIf+"->"+p.OutputIf, "inside->outside")
		eq(t, n+" estado", p.InputStatus+p.OutputLine, "upup")
		if p.Phases[0].Type == "" || p.Phases[len(p.Phases)-1].Result != "ALLOW" {
			t.Errorf("%s fases: %+v", n, p.Phases)
		}
	}
	p, _ := ParsePacketTrace(fx(t, "as_show-packet-tracer.txt"))
	eq(t, "fases", len(p.Phases), 4)
	eq(t, "ruta", p.Phases[2].Subtype, "Resolve Egress Interface")
	if !strings.Contains(p.Phases[3].Config, "permit tcp 10.0.0.0") || !strings.Contains(p.Phases[3].Extra, "priority=13") {
		t.Errorf("config/extra: %+v", p.Phases[3])
	}
	x, _ := ParsePacketTrace(fx(t, "as_show-packet-tracer-xml.txt"))
	eq(t, "fases xml", len(x.Phases), 2)
	eq(t, "nat", x.Phases[1].Type+"|"+x.Phases[1].Subtype, "NAT|")
	eq(t, "id", x.Phases[1].ID, 2)
	d, ok := ParsePacketTrace(fx(t, "as_show-packet-tracer-drop.txt"))
	if !ok || d.Allowed() || d.Action != "drop" || !strings.HasPrefix(d.DropReason, "(acl-drop)") || d.Phases[0].Result != "DROP" {
		t.Errorf("drop: %+v", d)
	}
}

func TestFormatoDesconocido(t *testing.T) {
	s := "% Invalid input detected at '^' marker.\n"
	_, a := ParseFailoverState(s)
	_, b := ParseFailoverHistory(s)
	_, c := ParseChecksum(s)
	_, d := ParseMode(s)
	_, _, e := ParseContexts(s)
	_, f := ParseResourceUsage(s)
	_, g := ParseAspDrop(s)
	_, h := ParseCount(s)
	_, i := ParseClusterInfo(s)
	_, j := ParseClusterHealth(s)
	_, k := ParseVersion(s)
	_, l := NormalizeRunningConfig(s)
	_, m := ParsePacketTrace(s)
	if a || b || c || d || e || f || g || h || i || j || k || l || m {
		t.Error("algún parser aceptó un error de CLI como salida válida")
	}
}

// FuzzParsers pasa un mismo texto por todos los parsers: ninguno entra en pánico ni tarda más de un tope.
func FuzzParsers(f *testing.F) {
	fs, _ := filepath.Glob("testdata/*.txt")
	for _, p := range fs {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(string(b))
		}
	}
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<20 {
			return
		}
		start := time.Now()
		ParseFailover(s)
		ParseFailoverState(s)
		ParseFailoverHistory(s)
		ParseChecksum(s)
		ParseMode(s)
		ParseContexts(s)
		ParseResourceUsage(s)
		ParseAspDrop(s)
		ParseCount(s)
		ParseClusterInfo(s)
		ParseClusterHealth(s)
		ParseVersion(s)
		NormalizeRunningConfig(s)
		ParsePacketTrace(s)
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("los parsers tardaron %v con %d bytes", d, len(s))
		}
	})
}

func TestFailoverEstadosDeInterfazDeDosPalabras(t *testing.T) {
	src := "Failover On\n\tThis host: Primary - Active\n\t\tInterface a (203.0.113.1): Normal (Monitored)\n\t\tInterface dmz (203.0.113.9): No Link (Waiting)\n\t\tInterface b (203.0.113.2): Link Down (Not-Monitored)\n\t\tInterface c (203.0.113.3): Failed (Waiting)\n\t\tInterface d (203.0.113.4): Unknown (Waiting)\n\t\tctx1 Interface e (203.0.113.5): Normal\n"
	f, _ := ParseFailover(src)
	h, _ := f.Host(true)
	want := []string{"Normal|Monitored", "No Link|Waiting", "Link Down|Not-Monitored", "Failed|Waiting", "Unknown|Waiting", "Normal|"}
	if len(h.Ifaces) != len(want) {
		t.Fatalf("interfaces: %+v", h.Ifaces)
	}
	for i, w := range want {
		eq(t, "estado", h.Ifaces[i].State+"|"+h.Ifaces[i].Monitoring, w)
	}
	eq(t, "contexto", h.Ifaces[5].Context, "ctx1")
}

func TestFailoverDentroDeUnContexto(t *testing.T) {
	src := "Failover On\n\tLast Failover at: 10:21:44 UTC Nov 9 2026\n\tThis context: Active\n\t\tActive time: 5 (sec)\n\tPeer context: Standby Ready\n"
	if _, ok := ParseFailover(src); ok {
		t.Error("show failover dentro de un contexto no tiene bloques de host: debe dar ok=false")
	}
}

func TestFailoverStateSeccionVaciaYFechaConRelleno(t *testing.T) {
	src := "\t\tState\tLast Failure Reason\tDate/Time\nThis host  -\tPrimary\n\t\tActive\t\tNone\nOther host -\tSecondary\n\t\tStandby Ready\tComm Failure\t\t10:21:44 UTC Jan  5 2026\n====Configuration State===\n\tSync Done\n====Communication State===\n====Otra Seccion===\n\tValor\n"
	st, ok := ParseFailoverState(src)
	if !ok {
		t.Fatal("no reconoció")
	}
	eq(t, "hora con relleno", st.Rows[1].Time, "10:21:44 UTC Jan  5 2026")
	eq(t, "motivo", st.Rows[1].Reason, "Comm Failure")
	eq(t, "comm vacía", st.CommState, "")
	h, _ := ParseFailoverHistory("From State To State Reason\n10:21:44 UTC Jan  5 2026\nActive    Failed    Interface check\n")
	if len(h) != 1 || h[0].To != "Failed" {
		t.Errorf("historial con relleno: %+v", h)
	}
}

func TestRunningConfigSinSerieNiHardwareDeLaCabecera(t *testing.T) {
	mk := func(serial string) string {
		return ": Saved\n:\n: Serial Number: " + serial + "\n: Hardware:   ASAv, 2048 MB RAM\n:\nASA Version 9.22(1)7\n!\nhostname asa\nbanner motd : Saved\n: end\n"
	}
	a, ok := NormalizeRunningConfig(mk("9AAAAAAAAA1"))
	b, _ := NormalizeRunningConfig(mk("9BBBBBBBBB2"))
	if !ok || a != b {
		t.Errorf("las series distintas no deben afectar:\n%q\n%q", a, b)
	}
	if !strings.Contains(a, "banner motd : Saved") || !strings.Contains(a, ": end") {
		t.Errorf("quitó de más: %q", a)
	}
}

func TestVersionLicenciaPAKConDuracion(t *testing.T) {
	v, _ := ParseVersion("Cisco Adaptive Security Appliance Software Version 9.12(4)\n\nLicensed features for this platform:\nSecurity Contexts                 : 5          perpetual\nFailover                          : Active/Active perpetual\n\nSerial Number: 9AAAAAAAAA1\n")
	eq(t, "contextos", v.Contexts, int64(5))
	eq(t, "failover", v.FailoverFeature, "Active/Active")
}

func TestPacketTraceDropLocationYAllowed(t *testing.T) {
	p, _ := ParsePacketTrace(fx(t, "as_show-packet-tracer-drop.txt"))
	eq(t, "motivo", p.DropReason, "(acl-drop) Flow is denied by configured rule")
	eq(t, "ubicación", p.DropLocation, "frame 0x00005555aaaa flow (NA)/NA")
	// Action: allow con motivo de drop no es permitido
	q := PacketTrace{Action: "allow", DropReason: "(x) y"}
	eq(t, "allowed", q.Allowed(), false)
}

func TestPacketTraceXMLConEcoYSinEco(t *testing.T) {
	x := fx(t, "as_show-packet-tracer-xml.txt")
	body := x[strings.Index(x, "\n")+1:]
	for _, src := range []string{x, body, "\n\n" + body, "asa 1 # packet-tracer input inside tcp 10.0.0.1 1 10.0.0.2 2 xml\n" + body} {
		if p, ok := ParsePacketTrace(src); !ok || len(p.Phases) != 2 || !p.Allowed() {
			t.Errorf("xml: %+v", p)
		}
	}
	// texto con un "</" en la config no se toma por XML
	t1 := "Phase: 1\nType: ACCESS-LIST\nResult: ALLOW\nConfig:\nbanner motd </x>\nAdditional Information:\nResult:\nAction: allow\n"
	if p, _ := ParsePacketTrace(t1); len(p.Phases) != 1 || p.Phases[0].Type != "ACCESS-LIST" {
		t.Errorf("texto con </: %+v", p)
	}
}

func TestAspDropSinEncabezado(t *testing.T) {
	src := "asa# show asp drop frame\n  No route to host   (no-route)   14\n  NAT failed   (nat-failed)   2\nLast clearing: Never\n"
	d, ok := ParseAspDrop(src)
	if !ok || len(d.Rows) != 2 || d.Rows[0].Section != "" || d.Cleared[""] != "Never" {
		t.Errorf("frame: %+v %v", d, ok)
	}
	d, ok = ParseAspDrop("  NAT failed   (nat-failed)   2\n")
	if !ok || len(d.Rows) != 1 || d.Rows[0].Section != "" {
		t.Errorf("sin encabezado: %+v", d)
	}
	d, ok = ParseAspDrop("Last clearing: Never\n")
	if !ok || len(d.Rows) != 0 {
		t.Errorf("equipo sano sin drops: %+v %v", d, ok)
	}
}
