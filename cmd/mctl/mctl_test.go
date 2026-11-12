package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/core"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

func ctx() context.Context { return context.Background() }

func TestMain(m *testing.M) {
	vault.MinMemoryKiB = 8192
	// Las pruebas viven bajo /tmp (1777): sus ancestros se dan por seguros; la regla real la prueba prefs.
	service.AncestorInfo = func(string) (os.FileMode, uint32, error) { return 0o755, uint32(os.Getuid()), nil }
	os.Exit(m.Run())
}

type env struct {
	out    string
	target string
}

func startCore(t *testing.T) *env { return startCoreWith(t, nil) }

// startCoreWith deja preparar las carpetas del núcleo (por ejemplo una bóveda ya creada) antes de arrancarlo.
func startCoreWith(t *testing.T, prepare func(core.Paths)) *env {
	t.Helper()
	root := t.TempDir()
	rt, _ := os.MkdirTemp("", "mctl")
	t.Cleanup(func() { os.RemoveAll(rt) })
	t.Setenv("XDG_RUNTIME_DIR", rt)
	p := core.Paths{Config: filepath.Join(root, "c"), Data: filepath.Join(root, "d"), State: filepath.Join(root, "s"), Runtime: filepath.Join(rt, "macuahuitl"), Outputs: filepath.Join(root, "o")}
	if prepare != nil {
		prepare(p)
	}
	o := core.Options{VaultParams: &vault.Params{MemoryKiB: 8192, Iterations: 1, Threads: 1}, Actor: "tester", RetryBackoff: []time.Duration{}}
	if bin := os.Getenv("MCTL_TEST_DIAG_BIN"); bin != "" {
		o.DiagLookPath = func(name string) (string, error) { return filepath.Join(bin, name), nil }
	}
	c, err := core.New(p, o)
	if err != nil {
		t.Fatal(err)
	}
	sock, _ := ipc.SocketPath()
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go c.Serve(ctx, l)
	t.Cleanup(func() { cancel(); c.Close() })
	_, f, _, _ := runtime.Caller(0)
	addr, _ := simulator.Start(t, simulator.Config{Hostname: "SW-LAB-01", Username: "admin", Password: "pw-lab", Enable: "en-lab",
		Transcripts: filepath.Join(filepath.Dir(f), "..", "..", "test", "transcripts", "ios-xe")})
	os.MkdirAll(p.Outputs, 0o700)
	return &env{out: p.Outputs, target: addr}
}

func mctl(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := run(args, strings.NewReader(stdin), &out)
	return out.String(), err
}

func must(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	out, err := mctl(t, stdin, args...)
	if err != nil {
		t.Fatalf("mctl %v: %v\n%s", args, err, out)
	}
	return out
}

func TestVaultCreateUnlockViaStdin(t *testing.T) {
	startCore(t)
	must(t, "maestra\nmaestra\n", "vault", "create")
	must(t, "", "vault", "lock")
	if out := must(t, "", "vault", "status"); !strings.Contains(out, "cerrada") {
		t.Fatalf("status = %q", out)
	}
	if _, err := mctl(t, "mala\n", "vault", "unlock"); err == nil {
		t.Fatal("wrong password accepted")
	}
	must(t, "maestra\n", "vault", "unlock")
	if out := must(t, "", "vault", "status"); !strings.Contains(out, "abierta") {
		t.Fatalf("status = %q", out)
	}
}

func TestCreateRejectsMismatch(t *testing.T) {
	startCore(t)
	if _, err := mctl(t, "una\notra\n", "vault", "create"); err == nil {
		t.Fatal("mismatched confirmation accepted")
	}
}

func TestNoPasswordFlag(t *testing.T) {
	startCore(t)
	_, err := mctl(t, "", "vault", "unlock", "--password", "x")
	if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("err = %v", err)
	}
}

// Fase 28g: un guion puede omitir la línea de enable (EOF = sin enable) o pedirlo con --no-enable; la contraseña de login sigue siendo obligatoria.
func TestCredAddEnableOptionalInScripts(t *testing.T) {
	startCore(t)
	must(t, "maestra\nmaestra\n", "vault", "create")
	list := func() string { return must(t, "", "cred", "list") }
	hasEnable := func(label string) bool {
		for _, l := range strings.Split(list(), "\n") {
			if strings.Contains(l, "  "+label+"  ") {
				return strings.Contains(l, "+enable")
			}
		}
		t.Fatalf("no está %s en %q", label, list())
		return false
	}
	must(t, "pw\nen\n", "cred", "add", "--label", "con", "--user", "admin")
	must(t, "pw\n", "cred", "add", "--label", "eof", "--user", "admin")
	must(t, "pw", "cred", "add", "--label", "sinsalto", "--user", "admin")
	must(t, "pw\nsobra\n", "cred", "add", "--label", "no", "--user", "admin", "--no-enable")
	must(t, "pw\n", "cred", "add", "--label", "no2", "--no-enable", "--user", "admin")
	if !hasEnable("con") || hasEnable("eof") || hasEnable("sinsalto") || hasEnable("no") || hasEnable("no2") {
		t.Fatalf("enable guardado mal: %q", list())
	}
	// Un enable vacío explícito sigue siendo «sin enable».
	must(t, "pw\n\n", "cred", "add", "--label", "vacio", "--user", "admin")
	if hasEnable("vacio") {
		t.Fatal("enable vacío guardado")
	}
	// La contraseña de login es obligatoria: sin su línea, o con --no-enable, falla.
	for _, args := range [][]string{{"--user", "admin"}, {"--user", "admin", "--no-enable"}} {
		if _, err := mctl(t, "", append([]string{"cred", "add", "--label", "x"}, args...)...); err == nil {
			t.Errorf("cred add %v sin contraseña aceptado", args)
		}
	}
}

func TestJobLifecycleAgainstSimulator(t *testing.T) {
	e := startCore(t)
	must(t, "maestra\nmaestra\n", "vault", "create")
	cred := strings.TrimSpace(must(t, "pw-lab\nen-lab\n", "cred", "add", "--label", "lab", "--user", "admin"))
	if out := must(t, "", "cred", "list"); !strings.Contains(out, cred) || strings.Contains(out, "pw-lab") {
		t.Fatalf("cred list = %q", out)
	}
	ap := netip.MustParseAddrPort(e.target)
	spec := fmt.Sprintf("name: lab\ntargets:\n  - address: %s\n    port: %d\n    device_id: sw1\ndefault_credential_id: %s\ncustom_commands: |\n  show version\noutput_dir: %s\nwindow_hours: 1\nschedule:\n  interval_seconds: 1\n  rounds: 2\n",
		ap.Addr(), ap.Port(), cred, e.out)
	f := filepath.Join(t.TempDir(), "job.yaml")
	os.WriteFile(f, []byte(spec), 0o600)
	job := strings.TrimSpace(must(t, "", "job", "create", "-f", f))
	lt, _ := mctl(t, "", "job", "logintest", job)
	fp := regexp.MustCompile(`SHA256:\S+`).FindString(lt)
	if fp == "" {
		t.Fatalf("logintest output has no fingerprint:\n%s", lt)
	}
	must(t, "", "job", "arm", "--accept", fp, job)
	if out := must(t, "", "job", "watch", job); !strings.Contains(out, "closed") || !strings.Contains(out, "fase  COMPLETED") {
		t.Fatalf("watch = %q", out)
	}
	if zips, _ := filepath.Glob(filepath.Join(e.out, "lab_*", "*.zip")); len(zips) != 1 {
		t.Fatalf("zips = %v", zips)
	}
	if out := must(t, "", "job", "list"); !strings.Contains(out, job) || !strings.Contains(out, "completed") {
		t.Fatalf("list = %q", out)
	}
}

func TestAuditVerifyIntact(t *testing.T) {
	startCore(t)
	must(t, "maestra\nmaestra\n", "vault", "create")
	if out := must(t, "", "audit", "verify"); !strings.Contains(out, "íntegra") {
		t.Fatalf("verify = %q", out)
	}
	if out := must(t, "", "audit", "export"); !strings.Contains(out, `"action":"vault.create"`) {
		t.Fatalf("export = %q", out)
	}
}

func TestVersion(t *testing.T) {
	if out := must(t, "", "--version"); !strings.Contains(out, "macuahuitl dev") {
		t.Fatalf("version = %q", out)
	}
}

func TestUsageBeforeDial(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	_, err := mctl(t, "", "frob", "x")
	if err == nil || !strings.Contains(err.Error(), "uso:") {
		t.Fatalf("unknown command should print usage without dialing: %v", err)
	}
	if out, err := mctl(t, "", "--help"); err != nil || !strings.Contains(out, "uso:") {
		t.Fatalf("--help: %q %v", out, err)
	}
}

func TestAclConvertAndAnalyze(t *testing.T) {
	startCore(t)
	f := filepath.Join(t.TempDir(), "edge.txt")
	os.WriteFile(f, []byte("access-list EDGE extended permit tcp 10.0.0.0 255.255.255.0 any eq 22\naccess-list EDGE extended deny tcp host 10.0.0.5 any eq 22\n"), 0o600)
	out := must(t, "", "acl", "convert", "--from", "asa", "--to", "nx-os", "-f", f)
	if !strings.Contains(out, "ip access-list EDGE") || !strings.Contains(out, "permit tcp 10.0.0.0/24 any eq 22") {
		t.Fatalf("convert = %q", out)
	}
	out, err := mctl(t, "", "acl", "analyze", "--vendor", "asa", "-f", f)
	if err == nil || !strings.Contains(out, "regla 2") || !strings.Contains(out, "sombreada") {
		t.Fatalf("analyze = %q %v (debe fallar con hallazgos)", out, err)
	}
}

func TestDiagPing(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	t.Setenv("MCTL_TEST_DIAG_BIN", filepath.Join(filepath.Dir(here), "..", "..", "internal", "diag", "testdata", "bin"))
	startCore(t)
	out := must(t, "", "diag", "ping", "192.0.2.1", "-o", "count=3")
	if !strings.Contains(out, "ARGV: -n -c 3 192.0.2.1") || !strings.Contains(out, "guardado en") {
		t.Fatalf("out = %q", out)
	}
	if _, err := mctl(t, "", "diag", "ping", "-iL"); err == nil {
		t.Fatal("bad target accepted")
	}
}

func TestDiagInterfaces(t *testing.T) {
	startCore(t)
	if out := must(t, "", "diag", "interfaces"); !strings.Contains(out, "127.0.0.1/8") {
		t.Fatalf("out = %q", out)
	}
}

func TestToolsCommands(t *testing.T) {
	startCore(t)
	dir := t.TempDir()
	pc := filepath.Join(dir, "vacia.pcap")
	// Cabecera pcap clásica (little endian, v2.4, snaplen 65535, Ethernet) sin paquetes.
	os.WriteFile(pc, []byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0}, 0o600)
	t.Chdir(dir)
	if out, err := mctl(t, "", "pcap", "analyze", "vacia.pcap"); err != nil || out == "" {
		t.Fatalf("pcap: %q %v", out, err)
	}
	if out, err := mctl(t, "", "dns", "query", "example.com", "-s", "127.0.0.1:1", "--timeout", "300"); err != nil || !strings.Contains(out, "127.0.0.1") {
		t.Fatalf("dns query: %q %v", out, err)
	}
	if _, err := mctl(t, "", "dns", "trace", "example.com"); err == nil || !strings.Contains(err.Error(), "profundo") {
		t.Fatalf("trace without --deep: %v", err)
	}
	if _, err := mctl(t, "", "tls", "inspect", "127.0.0.1:1", "--timeout", "300"); err == nil {
		t.Fatal("tls to closed port succeeded")
	}
	if out, err := mctl(t, "", "syslog", "listen", "--addr", "127.0.0.1:0", "--for", "1"); err != nil || !strings.Contains(out, "escuchando en 127.0.0.1:") {
		t.Fatalf("syslog: %q %v", out, err)
	}
	out, err := mctl(t, "", "syslog", "listen", "--addr", "127.0.0.1:0", "--for", "1", "--save", "--rate", "50", "--burst", "60", "--rate-global", "500", "--burst-global", "600", "--queue", "128",
		"--rotate-mb", "5", "--rotate-min", "10", "--name", "x_{fecha}", "--max-files", "3", "--format", "crudo")
	if err != nil || !strings.Contains(out, "escuchando en 127.0.0.1:") || !strings.Contains(out, "guardando en") {
		t.Fatalf("syslog con opciones: %q %v", out, err)
	}
	for _, bad := range [][]string{{"--rate", "20000"}, {"--queue", "5"}, {"--rotate-mb", "2000"}, {"--name", "../x"}, {"--format", "xml"}, {"--max-files", "5000"}, {"--rate", "4294967396"}, {"--for", "4294967297"}, {"--rotate-mb", "-4294967295"}} {
		if _, err := mctl(t, "", append([]string{"syslog", "listen", "--addr", "127.0.0.1:0", "--for", "1"}, bad...)...); err == nil {
			t.Errorf("%v debía rechazarse", bad)
		}
	}
}

func TestChangeCommands(t *testing.T) {
	e := startCore(t)
	_, here, _, _ := runtime.Caller(0)
	td := func(p string) string { return filepath.Join(filepath.Dir(here), "..", "..", "internal", p) }
	out, err := mctl(t, "", "compliance", "check", "--config", td("compliance/testdata/debil.txt"), "--template", td("compliance/testdata/plantilla.txt"))
	if err == nil || !strings.Contains(out, "FALLA") || !strings.Contains(out, "aaa-new-model") {
		t.Fatalf("compliance = %q %v (debe fallar con fallas)", out, err)
	}
	if out := must(t, "", "compliance", "check", "--config", td("compliance/testdata/endurecido.txt"), "--json"); !strings.HasPrefix(out, "{") {
		t.Fatalf("compliance json = %q", out)
	}
	out, err = mctl(t, "", "upgrade", "check", "--outputs", td("upgrade/testdata/isr4451-bundle.txt"), "--image", "isr4400-universalk9.17.09.04a.SPA.bin",
		"--size", "700000000", "--md5", "0123456789abcdef0123456789abcdef")
	if err == nil || !strings.Contains(out, "verify /md5 bootflash:isr4400-universalk9.17.09.04a.SPA.bin") {
		t.Fatalf("upgrade = %q %v", out, err)
	}
	if _, err := mctl(t, "", "upgrade", "check", "--outputs", td("upgrade/testdata/isr4451-bundle.txt")); err == nil {
		t.Fatal("upgrade without image accepted")
	}

	must(t, "maestra\nmaestra\n", "vault", "create")
	cred := strings.TrimSpace(must(t, "pw-lab\nen-lab\n", "cred", "add", "--label", "lab", "--user", "admin"))
	ap := netip.MustParseAddrPort(e.target)
	f := filepath.Join(t.TempDir(), "cambio.yaml")
	os.WriteFile(f, []byte(fmt.Sprintf("name: crq-1\ntargets:\n  - address: %s\n    port: %d\ndefault_credential_id: %s\noutput_dir: %s\n", ap.Addr(), ap.Port(), cred, e.out)), 0o600)
	id := strings.TrimSpace(must(t, "", "change", "create", "-f", f))
	out, err = mctl(t, "", "change", "pre", id)
	if err == nil || !strings.Contains(out, "mctl job logintest") {
		t.Fatalf("pre without accepted key = %q %v", out, err)
	}
	job := regexp.MustCompile(`trabajo ([0-9a-f]+)`).FindStringSubmatch(out)[1]
	lt, _ := mctl(t, "", "job", "logintest", job)
	fp := regexp.MustCompile(`SHA256:\S+`).FindString(lt)
	pre := regexp.MustCompile(`trabajo ([0-9a-f]+)`).FindStringSubmatch(must(t, "", "change", "pre", "--accept", fp, id))[1]
	waitChange(t, id, "pre="+pre+" completed")
	post := regexp.MustCompile(`trabajo ([0-9a-f]+)`).FindStringSubmatch(must(t, "", "change", "post", id))[1]
	waitChange(t, id, "post="+post+" completed")
	if out := must(t, "", "change", "list"); !strings.Contains(out, id) || !strings.Contains(out, "crq-1") {
		t.Fatalf("list = %q", out)
	}
	out, err = mctl(t, "", "change", "report", id)
	for i := 0; err != nil && i < 100; i++ { // el manifest se escribe justo después de "completed"
		time.Sleep(50 * time.Millisecond)
		out, err = mctl(t, "", "change", "report", id)
	}
	if !strings.Contains(out, "SIN CAMBIOS INESPERADOS") {
		t.Fatalf("report = %q", out)
	}
	dirs, _ := filepath.Glob(filepath.Join(e.out, "crq-1-p*_*"))
	sort.Strings(dirs) // crq-1-post_… antes que crq-1-pre_…
	if out := must(t, "", "change", "report", "--pre", dirs[1], "--post", dirs[0], "--json"); !strings.Contains(out, `"verdict":"ok"`) {
		t.Fatalf("report por carpetas = %q (%v)", out, dirs)
	}
}

// waitChange sondea change list: una captura de una ronda puede cerrar antes de que job watch se suscriba.
func waitChange(t *testing.T, id, want string) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if out := must(t, "", "change", "list"); strings.Contains(out, want) {
			return
		}
	}
	t.Fatalf("%s: no llegó a %q", id, want)
}

func TestAnalysisCommands(t *testing.T) {
	startCore(t)
	lab, _ := filepath.Abs("../../internal/analyze/testdata/lab_20261104-100000")
	if out, err := mctl(t, "", "analyze", lab, "--round", "3", "--device", "SW1"); err != nil || !strings.Contains(out, "CPU alta") || strings.Contains(out, "RTR2") {
		t.Fatalf("analyze: %q %v", out, err)
	}
	if out, err := mctl(t, "", "analyze", lab, "--json"); err != nil || !json.Valid([]byte(out)) {
		t.Fatalf("analyze --json: %q %v", out, err)
	}
	// Ruta relativa a una carpeta: se resuelve en el cliente.
	t.Chdir(filepath.Dir(lab))
	if out, err := mctl(t, "", "diff", filepath.Base(lab), "--from", "1", "--to", "2"); err != nil || !strings.Contains(out, "(+1500)") {
		t.Fatalf("diff: %q %v", out, err)
	}
	if out, err := mctl(t, "", "timeline", lab, "--around", "2026-11-04T10:09:18Z", "--window", "30s", "--device", "RTR2"); err != nil || !strings.Contains(out, "ADJCHANGE") || strings.Contains(out, "SW1") {
		t.Fatalf("timeline: %q %v", out, err)
	}
	if _, err := mctl(t, "", "timeline", lab, "--around", "ayer"); err == nil {
		t.Fatal("bad --around accepted")
	}
	if _, err := mctl(t, "", "diff", lab, "--from", "1"); err == nil {
		t.Fatal("diff without --to accepted")
	}
}

func TestCalcCommands(t *testing.T) {
	startCore(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"calc", "subnet", "192.168.1.77", "255.255.255.192"}, "192.168.1.127"},
		{[]string{"calc", "vlsm", "10.0.0.0/24", "ventas=100", "30"}, "10.0.0.128/27"},
		{[]string{"calc", "summarize", "10.0.0.0/24", "10.0.1.0/24"}, "10.0.0.0/23"},
		{[]string{"calc", "wildcard", "0.0.0.255"}, "255.255.255.0"},
		{[]string{"calc", "wildcard", "10.0.0.0", "0.0.254.255"}, "10.0.2.0/24"},
		{[]string{"calc", "ipv6", "2001:db8:1:2::/64", "--mac", "0050.56ab.cdef"}, "2001:db8:1:2:250:56ff:feab:cdef"},
		{[]string{"calc", "mtu", "nat-t", "esp-tunnel:aes-cbc:sha256", "--mtu", "1500"}, "1382"},
		{[]string{"calc", "tcp", "--bw", "1g", "--rtt", "50", "--window", "64k"}, "ventana"},
		{[]string{"calc", "dscp", "0xb8", "--by", "tos"}, "EF"},
		{[]string{"calc", "optics", "--tx", "-8.2", "--rx", "-14.4", "--km", "10"}, "NO cierra"},
		{[]string{"calc", "optics", "--convert", "-3dBm"}, "0.501"},
		{[]string{"calc", "bgp", "--route", "name=A,path=65001 {65002,65003},med=50,ebgp,rid=10.0.0.1", "--route", "name=B,path=65001 65009,med=10,ebgp,rid=10.0.0.2,lp=100"}, "Gana B"},
	} {
		if out := must(t, "", c.args...); !strings.Contains(out, c.want) {
			t.Errorf("%v: falta %q en\n%s", c.args, c.want, out)
		}
	}
	out := must(t, "", "calc", "mtu", "gre", "--json")
	if !strings.HasPrefix(out, "{") || !strings.Contains(out, `"mss":1436`) {
		t.Fatalf("--json: %s", out)
	}
	for _, bad := range [][]string{{"calc", "subnet"}, {"calc", "vlsm", "10.0.0.0/24", "x=y"}, {"calc", "bgp", "--route", "name=A,frob=1", "--route", "name=B"}, {"calc", "mtu"}} {
		if _, err := mctl(t, "", bad...); err == nil {
			t.Errorf("%v aceptado", bad)
		}
	}
}

// Las banderas repetibles y opcionales no guardan estado entre dos run() del mismo proceso.
func TestCalcFlagsDoNotLeakBetweenRuns(t *testing.T) {
	startCore(t)
	must(t, "", "calc", "bgp", "--route", "name=A,med=50,ebgp,rid=10.0.0.1", "--route", "name=B,med=10,ebgp,rid=10.0.0.2")
	if out := must(t, "", "calc", "bgp", "--route", "name=C,rid=10.0.0.3", "--route", "name=D,rid=10.0.0.4"); strings.Contains(out, "A vs B") || !strings.Contains(out, "C vs D") {
		t.Fatalf("rutas de la corrida anterior: %s", out)
	}
	with := must(t, "", "calc", "optics", "--tx", "-8.2", "--rx", "-14.4", "--km", "10", "--overload", "-20")
	without := must(t, "", "calc", "optics", "--tx", "-8.2", "--rx", "-14.4", "--km", "10")
	base := must(t, "", "calc", "optics", "--tx", "-8.2", "--rx", "-14.4", "--km", "10")
	if with == without || without != base {
		t.Fatalf("--overload se arrastró:\nCON:\n%s\nSIN:\n%s", with, without)
	}
}
