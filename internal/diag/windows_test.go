package diag

import (
	"errors"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func req(tool Tool, target string, opts map[string]string, dir string) Request {
	r := Request{Tool: tool, Options: opts, OutputDir: dir}
	if target != "" {
		r.Targets = []string{target}
	}
	return r
}

func localTest(t *testing.T) {
	localIPs = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.0.2.9")} }
	t.Cleanup(func() { localIPs = realLocalIPs })
}

// Estas pruebas corren en Linux: llaman directo a la variante de Windows (como resolvePathsWindows en internal/paths).

func TestBuildWindowsArgv(t *testing.T) {
	localTest(t)
	cases := []struct {
		r       Request
		bin, wa string
	}{
		{req(Ping, "192.0.2.1", map[string]string{"count": "4", "size": "1200"}, ""), "ping", "-n 4 -l 1200 -w 2000 192.0.2.1"},
		{req(Ping, "sw1.example", nil, ""), "ping", "-n 4 -w 2000 sw1.example"},
		{req(Traceroute, "192.0.2.1", map[string]string{"max_hops": "12"}, ""), "tracert", "-d -h 12 -w 2000 192.0.2.1"},
		{req(Traceroute, "192.0.2.1", nil, ""), "tracert", "-d -w 2000 192.0.2.1"},
		{req(Nmap, "192.0.2.0/24", map[string]string{"ports": "22,80", "scan": "connect", "timing": "3"}, ""), "nmap", "-sT -p 22,80 -T3 -n -oG - 192.0.2.0/24"},
		{req(Iperf3, "192.0.2.1", map[string]string{"seconds": "10", "reverse": "true"}, ""), "iperf3", "-c 192.0.2.1 -t 10 -R"},
		// En Windows no hay puertos privilegiados (ADR 0012 h): el servidor iperf3 puede escuchar en el 80.
		{req(Iperf3, "", map[string]string{"mode": "server", "bind": "192.0.2.9", "port": "80"}, ""), "iperf3", "-s -B 192.0.2.9 -p 80 -1"},
		{req(Pcap, "", map[string]string{"interface": "3", "seconds": "30"}, `C:\o`), "dumpcap", "-i 3 -a duration:30"},
		// sin seconds la captura igual lleva condición de parada: cancelar en Windows es terminar el job
		{req(Pcap, "", map[string]string{"interface": `\Device\NPF_{1A2B3C4D-0000-4abc-9DEF-0123456789AB}`}, `C:\o`), "dumpcap", `-i \Device\NPF_{1A2B3C4D-0000-4abc-9DEF-0123456789AB} -a duration:60`},
		{req(Pcap, "", map[string]string{"interface": `\Device\NPF_Loopback`, "seconds": "5", "packets": "9"}, `C:\o`), "dumpcap", `-i \Device\NPF_Loopback -a duration:5 -c 9`},
	}
	for _, c := range cases {
		bin, argv, err := buildWindows(c.r)
		if err != nil {
			t.Errorf("%v %v: %v", c.r.Tool, c.r.Options, err)
			continue
		}
		if got := strings.Join(argv, " "); bin != c.bin || got != c.wa {
			t.Errorf("%v: %q %q, quiero %q %q", c.r.Tool, bin, got, c.bin, c.wa)
		}
	}
}

func TestBuildWindowsRechaza(t *testing.T) {
	localTest(t)
	cases := map[string]Request{
		"ping interval sin equivalente": req(Ping, "192.0.2.1", map[string]string{"interval": "1"}, ""),
		"nmap syn":                      req(Nmap, "192.0.2.1", map[string]string{"scan": "syn"}, ""),
		"iface con guion":               req(Pcap, "", map[string]string{"interface": "-w"}, `C:\o`),
		"iface amistosa":                req(Pcap, "", map[string]string{"interface": "Ethernet 2"}, `C:\o`),
		"iface guid corto":              req(Pcap, "", map[string]string{"interface": `\Device\NPF_{1}`}, `C:\o`),
		"iface con sufijo":              req(Pcap, "", map[string]string{"interface": `\Device\NPF_{1A2B3C4D-0000-4abc-9DEF-0123456789AB} -w x`}, `C:\o`),
		"iface ruta ajena":              req(Pcap, "", map[string]string{"interface": `\Device\Foo`}, `C:\o`),
		"iface indice enorme":           req(Pcap, "", map[string]string{"interface": "99999"}, `C:\o`),
	}
	for n, r := range cases {
		if _, _, err := buildWindows(r); err == nil {
			t.Errorf("%s: debió fallar", n)
		}
	}
	// el rechazo del intervalo es el propio, no cualquier error
	_, _, err := buildWindows(cases["ping interval sin equivalente"])
	if err == nil || !strings.Contains(i18n.In(i18n.En, err), "does not exist on Windows") {
		t.Errorf("interval: %v", err)
	}
	// en Windows «/x» es una opción: la defensa final lo rechaza (un destino no puede empezar con «/», pero el filtro de pcap sí)
	if _, _, err := buildWindows(req(Pcap, "", map[string]string{"interface": "3", "filter": "/?"}, `C:\o`)); err != nil {
		t.Errorf("filtro tras -f no es una opción: %v", err)
	}
	if err := checkFlagLike([]string{"-i", "3", "/?"}, true); err == nil {
		t.Error("«/?» debe rechazarse en Windows")
	}
	if err := checkFlagLike([]string{"-i", "3", "/?"}, false); err != nil {
		t.Error("en Linux «/?» no es una bandera")
	}
	if _, _, err := Build(req(Ping, "192.0.2.1", map[string]string{"interval": "1"}, "")); err != nil && runtime.GOOS == "linux" {
		t.Errorf("en Linux interval sigue siendo válido: %v", err)
	}
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

var winEnv = map[string]string{
	"SystemRoot": `C:\Windows`, "ProgramFiles": `C:\Program Files`, "ProgramFiles(x86)": `C:\Program Files (x86)`, "TEMP": `C:\Users\u\AppData\Local\Temp`,
}

func TestWinLook(t *testing.T) {
	all := func(string) bool { return true }
	cases := []struct {
		bin, want string
		env       map[string]string
		exeDir    string
		isFile    func(string) bool
	}{
		{"ping", `C:\Windows\System32\PING.EXE`, winEnv, "", all},
		{"tracert", `C:\Windows\System32\TRACERT.EXE`, winEnv, "", all},
		{"nmap", `C:\Program Files\Nmap\nmap.exe`, winEnv, "", all},
		{"nmap", `C:\Program Files (x86)\Nmap\nmap.exe`, winEnv, "", func(p string) bool { return strings.Contains(p, "(x86)") }},
		{"dumpcap", `C:\Program Files\Wireshark\dumpcap.exe`, winEnv, "", all},
		{"iperf3", `C:\Program Files\iperf3\iperf3.exe`, winEnv, `D:\app`, all},
		{"iperf3", `D:\app\tools\iperf3.exe`, winEnv, `D:\app\`, func(p string) bool { return p == `D:\app\tools\iperf3.exe` }},
	}
	for _, c := range cases {
		got, err := winLook(env(c.env), c.exeDir, c.isFile, c.bin)
		if err != nil || got != c.want {
			t.Errorf("%s: %q %v, quiero %q", c.bin, got, err, c.want)
		}
	}
	// nunca el PATH ni variables que no sean una unidad local
	for n, e := range map[string]map[string]string{
		"unc":      {"SystemRoot": `\\srv\share`, "ProgramFiles": `\\srv\share`},
		"relativa": {"SystemRoot": `Windows`, "ProgramFiles": `..\x`},
		"vacia":    {"PATH": `C:\evil`},
		"puntos":   {"SystemRoot": `C:\a\..\b`, "ProgramFiles": `C:\a\..\b`},
	} {
		for _, b := range []string{"ping", "tracert", "nmap", "dumpcap", "iperf3"} {
			if p, err := winLook(env(e), "", func(string) bool { return true }, b); err == nil {
				t.Errorf("%s/%s: aceptó %q", n, b, p)
			}
		}
	}
	if _, err := winLook(env(winEnv), `relativo`, func(p string) bool { return p == `relativo\tools\iperf3.exe` }, "iperf3"); err == nil {
		t.Error("carpeta del ejecutable relativa debe ignorarse")
	}
	if _, err := winLook(env(winEnv), "", func(string) bool { return false }, "nmap"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("sin archivo: %v", err)
	}
	if _, err := winLook(env(winEnv), "", func(string) bool { return true }, "cmd"); err == nil {
		t.Error("herramienta fuera de la lista")
	}
}

func TestWinChildEnv(t *testing.T) {
	e := map[string]string{"SystemRoot": `C:\Windows`, "TEMP": `C:\T`, "TMP": `\\evil\x`, "PATH": `C:\evil`, "USERPROFILE": `C:\Users\u`}
	got := strings.Join(winChildEnv(env(e), `C:\Program Files\Nmap\nmap.exe`), "|")
	want := `SystemRoot=C:\Windows|TEMP=C:\T|PATH=C:\Windows\System32;C:\Program Files\Nmap`
	if got != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
	// TEMP inválido: %LOCALAPPDATA%\Temp si es válida; si no, sin TEMP ni TMP (nunca C:\Windows\Temp)
	e["LOCALAPPDATA"] = `C:\Users\u\AppData\Local`
	if got := strings.Join(winChildEnv(env(e), `C:\x\a.exe`), "|"); got != `SystemRoot=C:\Windows|TEMP=C:\T|TMP=C:\Users\u\AppData\Local\Temp|PATH=C:\Windows\System32;C:\x` {
		t.Errorf("con LOCALAPPDATA: %s", got)
	}
	e["LOCALAPPDATA"] = `rel`
	if got := strings.Join(winChildEnv(env(e), `C:\x\a.exe`), "|"); strings.Contains(got, "TMP=") {
		t.Errorf("sin LOCALAPPDATA válida no hay TMP: %s", got)
	}
}

func TestInstallErr(t *testing.T) {
	for bin, frag := range map[string]string{"nmap": "nmap.org/download", "dumpcap": "wireshark.org/download", "iperf3": `tools\iperf3.exe`, "ping": `System32`} {
		for _, l := range []string{i18n.Es, i18n.En} {
			e := installErr("windows", bin)
			if s := i18n.In(l, e); !strings.Contains(s, frag) || strings.Contains(s, "apt") || !errors.Is(e, ErrNotInstalled) {
				t.Errorf("%s/%v: %q", bin, l, s)
			}
		}
	}
	if s := installErr("linux", "nmap").Error(); !strings.Contains(s, "apt install nmap") {
		t.Errorf("linux: %q", s)
	}
}

func TestWinIfaceName(t *testing.T) {
	ads := []winAdapter{{Friendly: "Ethernet 2", Name: "{1A2B3C4D-0000-4abc-9DEF-0123456789AB}"}, {Friendly: "Wi-Fi", Name: "{AAAAAAAA-0000-4abc-9DEF-0123456789AB}"}}
	if got := winIfaceName("Ethernet 2", ads); got != `\Device\NPF_{1A2B3C4D-0000-4abc-9DEF-0123456789AB}` {
		t.Errorf("amistoso: %q", got)
	}
	for _, in := range []string{"ethernet 2", "Ethernet 2 ", "-w", "3", `\Device\NPF_Loopback`, "Nada", ""} {
		if got := winIfaceName(in, ads); got != in {
			t.Errorf("%q debe quedar igual, dio %q", in, got)
		}
	}
	// un adaptador cuyo nombre amistoso es «-w» no puede colar una opción: el resultado igual pasa por winIfaceRe
	bad := []winAdapter{{Friendly: "x y", Name: "-w"}}
	r := req(Pcap, "", map[string]string{"interface": "x y"}, `C:\o`)
	old := winAdapters
	winAdapters = func() []winAdapter { return bad }
	t.Cleanup(func() { winAdapters = old })
	if _, _, err := buildWindows(r); err == nil {
		t.Error("el nombre traducido también se valida")
	}
	winAdapters = func() []winAdapter { return ads }
	_, argv, err := buildWindows(req(Pcap, "", map[string]string{"interface": "Wi-Fi", "seconds": "5"}, `C:\o`))
	if err != nil || strings.Join(argv, " ") != `-i \Device\NPF_{AAAAAAAA-0000-4abc-9DEF-0123456789AB} -a duration:5` {
		t.Errorf("%v %v", argv, err)
	}
}
