package analyze

import (
	"archive/zip"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

const lab = "testdata/lab_20261104-100000"

func load(t *testing.T) *Bundle {
	t.Helper()
	b, err := Load(lab)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rules(t *testing.T) []Rule {
	t.Helper()
	rs, err := DefaultRules()
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestLoadPerRoundAndConsolidated(t *testing.T) {
	b := load(t)
	if got := b.Devices(); fmt.Sprint(got) != "[RTR2_10.0.0.2 SW1_10.0.0.1]" {
		t.Fatalf("devices = %v", got)
	}
	if got := b.Rounds(""); fmt.Sprint(got) != "[1 2 3]" {
		t.Fatalf("rounds = %v", got)
	}
	s := b.find("SW1_10.0.0.1", 3, "show version")
	if s == nil || !s.At.Equal(time.Date(2026, 11, 4, 10, 20, 1, 0, time.UTC)) || !strings.Contains(s.Text, "SW1 uptime is 4 minutes") {
		t.Fatalf("SW1 r3 show version = %+v", s)
	}
	if strings.Contains(s.Text, "=====") {
		t.Fatal("header leaked into the output text")
	}
	inv := b.find("RTR2_10.0.0.2", 2, "show ip bgp neighbors 10.0.99.9")
	if inv == nil || !inv.Invalid {
		t.Fatalf("invalid command not flagged: %+v", inv)
	}
	if s := b.find("RTR2_10.0.0.2", 3, "show standby brief"); s == nil || !strings.Contains(s.Text, "Vl30") {
		t.Fatalf("consolidated r3 = %+v", s)
	}
}

// zipDir imita ZipAtEnd con borrado de sueltos: solo queda el zip.
func zipDir(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), filepath.Base(src))
	os.MkdirAll(dst, 0o700)
	f, _ := os.Create(filepath.Join(dst, filepath.Base(src)+".zip"))
	zw := zip.NewWriter(f)
	filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(src, p)
		w, _ := zw.Create(filepath.ToSlash(rel))
		b, _ := os.ReadFile(p)
		w.Write(b)
		return nil
	})
	zw.Close()
	f.Close()
	return dst
}

func TestLoadFromZip(t *testing.T) {
	loose := load(t)
	b, err := Load(zipDir(t, lab))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Sections) != len(loose.Sections) || len(b.Sections) == 0 {
		t.Fatalf("zip sections = %d, loose = %d", len(b.Sections), len(loose.Sections))
	}
}

func TestLoadRejectsNonJobFolder(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("empty folder accepted")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "nada")); err == nil {
		t.Fatal("missing folder accepted")
	}
}

func TestDefaultRulesAreComplete(t *testing.T) {
	rs := rules(t)
	seen := map[string]bool{}
	for _, r := range rs {
		if seen[r.ID] {
			t.Errorf("duplicate id %s", r.ID)
		}
		seen[r.ID] = true
		if r.Title == "" || r.Explanation == "" || r.Action == "" || len(r.Commands) == 0 || sevRank[r.Severity] == 0 {
			t.Errorf("incomplete rule %+v", r)
		}
	}
	for _, id := range []string{"cpu-alta", "cpu-tendencia", "memoria-baja", "memoria-fuga", "interfaz-crc-creciente", "interfaz-drops-salida",
		"reload-reciente", "reload-entre-rondas", "reload-causa-falla", "log-mallocfail", "log-cpuhog", "log-traceback", "log-flap-interfaz",
		"stp-cambios-topologia", "bgp-vecino-caido", "bgp-vecino-flap", "ospf-vecino-no-full", "ospf-vecino-perdido",
		"hsrp-inestable", "hsrp-estado-anomalo", "crashinfo-presente"} {
		if !seen[id] {
			t.Errorf("missing rule %s", id)
		}
	}
}

func TestLoadRulesRejectsBadFiles(t *testing.T) {
	for name, body := range map[string]string{
		"check":    "- {id: x, title: t, severity: alta, commands: [show version], check: nope, explanation: e, action: a}",
		"severity": "- {id: x, title: t, severity: grave, commands: [show version], check: uptime_reset, explanation: e, action: a}",
		"regex":    "- {id: x, title: t, severity: alta, commands: [show logging], check: match, params: {pattern: '('}, explanation: e, action: a}",
		"param":    "- {id: x, title: t, severity: alta, commands: [show version], check: uptime, params: {below: diez}, explanation: e, action: a}",
		"unknown":  "- {id: x, title: t, severity: alta, commands: [show version], check: uptime_reset, explanation: e, action: a, extra: 1}",
		"empty":    "- {id: x, title: t, severity: alta, commands: [], check: uptime_reset, explanation: e, action: a}",
	} {
		fsys := fstest.MapFS{"r.yaml": {Data: []byte(body)}}
		if _, err := LoadRules(fsys); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func key(f Finding) string {
	return fmt.Sprintf("%s %s r%d", f.Rule, strings.SplitN(f.Device, "_", 2)[0], f.Round)
}

func keys(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, key(f))
	}
	sort.Strings(out)
	return out
}

func TestAnalyzeFixture(t *testing.T) {
	r := Analyze(load(t), rules(t), Options{})
	want := []string{
		"bgp-vecino-caido RTR2 r2", "bgp-vecino-flap RTR2 r3",
		"cpu-alta SW1 r3", "cpu-tendencia SW1 r3",
		"crashinfo-presente SW1 r3",
		"hsrp-estado-anomalo RTR2 r3", "hsrp-inestable RTR2 r2", "hsrp-inestable RTR2 r3",
		"interfaz-crc SW1 r1", "interfaz-crc-creciente SW1 r2", "interfaz-drops-salida SW1 r2", "interfaz-errores-entrada SW1 r2",
		"log-adyacencia-caida RTR2 r2", "log-adyacencia-caida RTR2 r3",
		"log-cpuhog SW1 r2", "log-flap-interfaz SW1 r2", "log-mallocfail SW1 r2", "log-traceback SW1 r2",
		"memoria-baja SW1 r3", "memoria-fuga SW1 r3",
		"ospf-vecino-no-full RTR2 r2", "ospf-vecino-perdido RTR2 r3",
		"reload-causa-falla SW1 r3", "reload-entre-rondas SW1 r3", "reload-reciente SW1 r3",
		"stp-cambios-topologia SW1 r2", "stp-cambios-topologia SW1 r3",
	}
	sort.Strings(want)
	if got := keys(r.Findings); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(r.Warnings) != 0 {
		t.Fatalf("warnings on clean fixture: %+v", r.Warnings)
	}
	// Orden: críticas primero.
	if r.Findings[0].Severity != "critica" {
		t.Fatalf("first finding = %+v", r.Findings[0])
	}
	for _, f := range r.Findings {
		if len(f.Evidence) == 0 || f.Explanation == "" || f.Action == "" || f.At.IsZero() || f.Command == "" {
			t.Errorf("incomplete finding %+v", f)
		}
	}
}

func finding(t *testing.T, fs []Finding, k string) Finding {
	t.Helper()
	for _, f := range fs {
		if key(f) == k {
			return f
		}
	}
	t.Fatalf("no finding %s", k)
	return Finding{}
}

func TestEvidenceIsExactLines(t *testing.T) {
	r := Analyze(load(t), rules(t), Options{})
	b := load(t)
	for _, f := range r.Findings {
		s := b.find(f.Device, f.Round, f.Command)
		if s == nil {
			t.Fatalf("%s: no section for %q", key(f), f.Command)
		}
		for _, ln := range f.Evidence {
			if !strings.Contains("\n"+s.Text+"\n", "\n"+ln+"\n") {
				t.Errorf("%s: evidence %q is not a line of the output", key(f), ln)
			}
		}
	}
	if ev := finding(t, r.Findings, "cpu-alta SW1 r3").Evidence; !strings.Contains(ev[0], "five minutes: 91%") {
		t.Errorf("cpu evidence = %q", ev)
	}
	crc := finding(t, r.Findings, "interfaz-crc-creciente SW1 r2")
	if !strings.Contains(crc.Detail, "GigabitEthernet1/0/1") || !strings.Contains(crc.Detail, "15 → 1515") {
		t.Errorf("crc detail = %q", crc.Detail)
	}
	flap := finding(t, r.Findings, "log-flap-interfaz SW1 r2")
	if !strings.Contains(flap.Detail, "GigabitEthernet1/0/7") || len(flap.Evidence) != 6 {
		t.Errorf("flap = %+v", flap)
	}
	// El búfer de log se repite entre rondas: un mensaje ya reportado no vuelve a salir.
	adj := finding(t, r.Findings, "log-adyacencia-caida RTR2 r3")
	if len(adj.Evidence) != 1 || !strings.Contains(adj.Evidence[0], "10.255.0.4") {
		t.Errorf("r3 adjacency evidence = %q", adj.Evidence)
	}
	if bgp := finding(t, r.Findings, "bgp-vecino-caido RTR2 r2"); len(bgp.Evidence) != 1 || !strings.HasPrefix(bgp.Evidence[0], "10.0.13.1") {
		t.Errorf("bgp evidence = %q (Idle (Admin) must be ignored)", bgp.Evidence)
	}
	if ms := finding(t, r.Findings, "log-mallocfail SW1 r2"); ms.Severity != "critica" {
		t.Errorf("severity = %s", ms.Severity)
	}
}

func TestAnalyzeRoundAndDeviceFilter(t *testing.T) {
	r := Analyze(load(t), rules(t), Options{Round: 2})
	for _, f := range r.Findings {
		if f.Round != 2 {
			t.Fatalf("round filter leaked %s", key(f))
		}
	}
	// Las reglas de tendencia usan las rondas anteriores aunque se pida solo una.
	finding(t, r.Findings, "interfaz-crc-creciente SW1 r2")
	r = Analyze(load(t), rules(t), Options{Device: "10.0.0.2"})
	for _, f := range r.Findings {
		if !strings.HasPrefix(f.Device, "RTR2") {
			t.Fatalf("device filter leaked %s", key(f))
		}
	}
}

func TestMissingCommandsAreListed(t *testing.T) {
	r := Analyze(load(t), rules(t), Options{Device: "RTR2"})
	if !contains(r.Missing, "show interfaces") || contains(r.Missing, "show version") {
		t.Fatalf("missing = %v", r.Missing)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// bundleOf arma un paquete en memoria con una sección por ronda del mismo comando.
func bundleOf(cmd string, texts ...string) *Bundle {
	b := &Bundle{}
	for i, tx := range texts {
		b.Sections = append(b.Sections, Section{Device: "X_10.9.9.9", Round: i + 1, At: time.Date(2026, 11, 4, 10, i, 0, 0, time.UTC), Command: cmd, Text: tx})
	}
	return b
}

// Formato inesperado: sin hallazgo y con aviso, nunca pánico.
func TestUnexpectedFormatWarnsWithoutFinding(t *testing.T) {
	rs := rules(t)
	for _, cmd := range []string{"show processes cpu sorted", "show processes memory sorted", "show memory statistics", "show interfaces",
		"show version", "show spanning-tree detail", "show ip bgp summary", "show ip ospf neighbor", "show standby brief"} {
		r := Analyze(bundleOf(cmd, "algo totalmente distinto\n\x00\xff basura 99%\n", "otra cosa\n"), rs, Options{})
		if len(r.Findings) != 0 {
			t.Errorf("%s: findings on garbage: %v", cmd, keys(r.Findings))
		}
		if len(r.Warnings) == 0 {
			t.Errorf("%s: no warning on garbage", cmd)
		}
	}
	// Un comando inválido en el equipo también avisa.
	b := bundleOf("show version", "% Invalid input detected at '^' marker.\n")
	b.Sections[0].Invalid = true
	if r := Analyze(b, rs, Options{}); len(r.Warnings) == 0 || len(r.Findings) != 0 {
		t.Errorf("invalid: %+v", r)
	}
}

// Cualquier recorte de las salidas reales debe terminar sin pánico.
func TestTruncatedOutputsNeverPanic(t *testing.T) {
	full := load(t)
	rs := rules(t)
	for _, cut := range []int{1, 7, 40, 90, 200, 600, 1500} {
		b := &Bundle{}
		for _, s := range full.Sections {
			if len(s.Text) > cut {
				s.Text = s.Text[:cut]
			}
			b.Sections = append(b.Sections, s)
		}
		Analyze(b, rs, Options{})
		for _, r := range b.Rounds("") {
			if r > 1 {
				Diff(b, r-1, r, "")
			}
		}
	}
}

func TestMatchExcludeAndGroup(t *testing.T) {
	rs := rules(t)
	log := "Nov  4 2026 10:00:00.000 UTC: %PLATFORM-2-FAN_FAIL: fan tray 1 failed\nNov  4 2026 10:00:01.000 UTC: %SYS-2-MALLOCFAIL: x\n"
	r := Analyze(bundleOf("show logging", log), rs, Options{})
	crit := finding(t, r.Findings, "log-critico X r1")
	if len(crit.Evidence) != 1 || !strings.Contains(crit.Evidence[0], "FAN_FAIL") {
		t.Fatalf("critico evidence = %q", crit.Evidence)
	}
	// Tres flaps no alcanzan el mínimo de cuatro por interfaz.
	three := strings.Repeat("*Nov  4 10:00:00.000: %LINK-3-UPDOWN: Interface Gi1/0/2, changed state to down\n", 3)
	if r := Analyze(bundleOf("show logging | include LINK", three), rs, Options{}); len(r.Findings) != 0 {
		t.Fatalf("3 flaps: %v", keys(r.Findings))
	}
}

func TestLegitEmptyOrNormalStatesAreQuiet(t *testing.T) {
	rs := rules(t)
	ospf := "\nNeighbor ID     Pri   State           Dead Time   Address         Interface\n10.255.0.9        1   2WAY/DROTHER    00:00:33    10.0.9.1        Vlan9\n"
	for cmd, text := range map[string]string{
		"show ip bgp summary":   "% BGP not active\n",
		"show ip ospf neighbor": ospf,
		"show standby brief":    "",
	} {
		r := Analyze(bundleOf(cmd, text, text), rs, Options{})
		if len(r.Findings) != 0 || len(r.Warnings) != 0 {
			t.Errorf("%s: %v %+v", cmd, keys(r.Findings), r.Warnings)
		}
	}
}

func TestLooseAndZipAreNotDuplicated(t *testing.T) {
	dst := zipDir(t, lab)
	filepath.WalkDir(lab, func(p string, d fs.DirEntry, err error) error {
		rel, _ := filepath.Rel(lab, p)
		if d.IsDir() {
			os.MkdirAll(filepath.Join(dst, rel), 0o700)
			return nil
		}
		b, _ := os.ReadFile(p)
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600)
	})
	b, err := Load(dst)
	if err != nil || len(b.Sections) != len(load(t).Sections) {
		t.Fatalf("sections = %d, err %v", len(b.Sections), err)
	}
}

func TestFlapGroupNotRepeatedWithoutNewLines(t *testing.T) {
	var four string
	for i := 0; i < 4; i++ {
		four += fmt.Sprintf("*Nov  4 10:00:0%d.000: %%LINK-3-UPDOWN: Interface Gi1/0/2, changed state to down\n", i)
	}
	r := Analyze(bundleOf("show logging", four, four), rules(t), Options{})
	if got := keys(r.Findings); fmt.Sprint(got) != "[log-flap-interfaz X r1]" {
		t.Fatalf("findings = %v", got)
	}
}

// Causas de recarga de IOS-XE: las de falla disparan, las ordenadas no.
func TestReloadReasonClassification(t *testing.T) {
	rs := rules(t)
	for reason, crash := range map[string]bool{
		"Critical process cpp_cp_svr fault on rp_0_0 (rc=139)": true,
		"LocalSoft":                   true,
		"Critical software exception": true,
		"Kernel panic":                true,
		"Watchdog timeout":            true,
		"Reload Command":              false,
		"PowerOn":                     false,
		"power-on":                    false,
		"Image Install":               false,
		"Reload Slot Command":         false,
		"redundancy force-switchover": false,
	} {
		r := Analyze(bundleOf("show version", "R uptime is 2 hours\nLast reload reason: "+reason+"\n"), rs, Options{})
		got := false
		for _, f := range r.Findings {
			got = got || f.Rule == "reload-causa-falla"
		}
		if got != crash {
			t.Errorf("%q: crash=%v, want %v", reason, got, crash)
		}
	}
}

// Dos adyacencias con el mismo Router-ID (dos enlaces al mismo vecino) son distintas.
const ospfHdr = "\nNeighbor ID     Pri   State           Dead Time   Address         Interface\n"

func ospfTwoLinks() *Bundle {
	both := ospfHdr + "10.255.0.9        1   FULL/DR         00:00:33    10.0.91.1       GigabitEthernet0/0/1\n" +
		"10.255.0.9        1   FULL/DR         00:00:35    10.0.92.1       GigabitEthernet0/0/2\n"
	one := ospfHdr + "10.255.0.9        1   FULL/DR         00:00:33    10.0.91.1       GigabitEthernet0/0/1\n"
	return bundleOf("show ip ospf neighbor", both, one)
}

func TestOSPFSameRouterIDTwoLinks(t *testing.T) {
	r := Analyze(ospfTwoLinks(), rules(t), Options{})
	f := finding(t, r.Findings, "ospf-vecino-perdido X r2")
	if !strings.Contains(f.Detail, "GigabitEthernet0/0/2") {
		t.Fatalf("detail = %q", f.Detail)
	}
}

func textBytes(b *Bundle) int64 {
	var n int64
	for _, s := range b.Sections {
		n += int64(len(s.Text))
	}
	return n
}

func hasWarn(ws []Warning, sub string) bool {
	for _, w := range ws {
		if strings.Contains(w.Msg, sub) {
			return true
		}
	}
	return false
}

func withMaxTotal(t *testing.T, n int64) {
	old := maxTotal
	maxTotal = n
	t.Cleanup(func() { maxTotal = old })
}

func TestTotalCapWarnsVisibly(t *testing.T) {
	withMaxTotal(t, 4096)
	b, err := Load(lab)
	if err != nil {
		t.Fatal(err)
	}
	if textBytes(b) > 4096 || !hasWarn(b.Warnings, "se leyó parcialmente") {
		t.Fatalf("bytes=%d warnings=%+v", textBytes(b), b.Warnings)
	}
	if r := Analyze(b, rules(t), Options{}); !hasWarn(r.Warnings, "se leyó parcialmente") {
		t.Fatal("analyze report hides the cap")
	}
	if d, _ := Diff(b, 1, 1, ""); !hasWarn(d.Warnings, "se leyó parcialmente") {
		t.Fatal("diff report hides the cap")
	}
}

// Un zip hostil (texto muy comprimible) no pasa del tope total.
func TestHostileZipBoundedByTotalCap(t *testing.T) {
	withMaxTotal(t, 1<<20)
	dir := t.TempDir()
	f, _ := os.Create(filepath.Join(dir, "x.zip"))
	zw := zip.NewWriter(f)
	for i := 0; i < 3; i++ {
		w, _ := zw.Create(fmt.Sprintf("D_1.1.1.1/r%03d_20261104-100000.txt", i+1))
		w.Write([]byte("===== 2026-11-04T10:00:01Z · show tech-support =====\n"))
		w.Write([]byte(strings.Repeat("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", 200000)))
	}
	zw.Close()
	f.Close()
	b, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if textBytes(b) > 1<<20 || !hasWarn(b.Warnings, "se leyó parcialmente") {
		t.Fatalf("bytes=%d warnings=%+v", textBytes(b), b.Warnings)
	}
}

func TestLoadUpToRound(t *testing.T) {
	b, err := LoadUpTo(lab, 1)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(b.Rounds("")) != "[1]" || fmt.Sprint(b.Devices()) != "[RTR2_10.0.0.2 SW1_10.0.0.1]" {
		t.Fatalf("rounds=%v devices=%v", b.Rounds(""), b.Devices())
	}
	z, _ := LoadUpTo(zipDir(t, lab), 2)
	if fmt.Sprint(z.Rounds("")) != "[1 2]" {
		t.Fatalf("zip rounds=%v", z.Rounds(""))
	}
}

// IOS parte la fila de un vecino IPv6 largo: la dirección sola y los datos abajo.
func TestBGPSplitIPv6RowIsNotDropped(t *testing.T) {
	out := "BGP router identifier 10.255.0.2, local AS number 65001\n\n" +
		"Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n" +
		"10.0.12.1       4        65000    1234    1200      145    0    0 1w2d           10\n" +
		"2001:DB8:0:12::1\n" +
		"                4        65000       0       0        1    0    0 00:03:11 Active\n" +
		"2001:DB8:0:13::1\n" +
		"                4        65002     120     118      145    0    0 2d01h           7\n"
	r := Analyze(bundleOf("show bgp ipv6 unicast summary", out), rules(t), Options{})
	if len(r.Warnings) != 0 {
		t.Fatalf("warnings = %+v", r.Warnings)
	}
	if got := keys(r.Findings); fmt.Sprint(got) != "[bgp-vecino-caido X r1]" {
		t.Fatalf("findings = %v", got)
	}
	f := r.Findings[0]
	if !strings.Contains(f.Detail, "2001:DB8:0:12::1") || len(f.Evidence) != 2 || f.Evidence[0] != "2001:DB8:0:12::1" || !strings.HasSuffix(f.Evidence[1], "Active") {
		t.Fatalf("finding = %+v", f)
	}
}

// El escritor de Patrol escapa con "\" las líneas de la salida que parecen cabecera; Load las
// restaura y no crea secciones de más. Un paquete viejo, sin escapes, se lee como antes.
func TestLoadRestauraLineasEscapadasYNoCreaSecciones(t *testing.T) {
	dir := t.TempDir()
	d := filepath.Join(dir, "SW1_192.0.2.1")
	os.MkdirAll(d, 0o755)
	var sb strings.Builder
	sb.WriteString("===== 2026-11-06T10:00:00Z · show running-config =====\nhostname SW1\nbanner motd ^C\n")
	for i := 0; i < 30; i++ {
		sb.WriteString("\\===== 2099-01-01T00:00:00Z · show running-config =====\n")
	}
	sb.WriteString("\\\\===== ya tenía una barra\n  ===== con sangría\n")
	os.WriteFile(filepath.Join(d, "r001_20261106-100000.txt"), []byte(sb.String()), 0o600)
	b, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Sections) != 1 {
		t.Fatalf("secciones = %d, quiero 1", len(b.Sections))
	}
	txt := b.Sections[0].Text
	if strings.Count(txt, "\n===== 2099-01-01T00:00:00Z · show running-config =====") != 30 ||
		!strings.Contains(txt, "\n\\===== ya tenía una barra\n") || !strings.Contains(txt, "\n  ===== con sangría\n") {
		t.Errorf("texto mal restaurado:\n%s", txt)
	}
	// Compatibilidad: sin escape, una cabecera sigue abriendo sección.
	old := "===== 2026-11-06T10:00:00Z · show version =====\nx\n===== 2026-11-06T10:00:01Z · show clock =====\ny\n"
	os.WriteFile(filepath.Join(d, "r001_20261106-100000.txt"), []byte(old), 0o600)
	if b, _ = Load(dir); len(b.Sections) != 2 {
		t.Errorf("paquete viejo: %d secciones", len(b.Sections))
	}
}
