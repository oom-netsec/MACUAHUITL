package analyze

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/pcapan"
)

// golden es el JSON y el texto en español de un informe, tal como salían antes de la fase 30c.
type golden struct{ JSON, Text string }

func gold(v any, text string) golden {
	b, _ := json.Marshal(v)
	return golden{string(b), text}
}

// synth arma un paquete de Patrol con las salidas dadas: archivos[equipo][nombre de archivo] = cuerpo.
func synth(t *testing.T, archivos map[string]map[string]string) *Bundle {
	t.Helper()
	d := t.TempDir()
	for dev, fs := range archivos {
		for name, body := range fs {
			p := filepath.Join(d, dev, name)
			os.MkdirAll(filepath.Dir(p), 0o755)
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	b, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	tmpDirs = append(tmpDirs, d)
	return b
}

func sec(ts, cmd, body string) string {
	return "===== " + ts + " · " + cmd + " =====\n" + body + "\n"
}

// regCases arma informes que recorren detalles, avisos, notas y eventos que los datos de ejemplo no alcanzan.
// Solo usa lo que ya existía antes de la fase 30c.
func regCases(t *testing.T) (map[string]golden, map[string]any) {
	t.Helper()
	out, ptrs := map[string]golden{}, map[string]any{}
	tmpDirs = nil
	add := func(name string, v any, text string) { out[name], ptrs[name] = gold(v, text), v }
	rs := rules(t)
	run := func(name string, b *Bundle, o Options) Report {
		r := Analyze(b, rs, o)
		add("analyze-"+name, &r, r.Text())
		return r
	}

	lab := load(t)
	rep := run("lab", lab, Options{})
	run("lab-r2", lab, Options{Round: 2})
	run("lab-sw1", lab, Options{Device: "sw1"})
	for _, p := range [][2]int{{1, 2}, {2, 3}, {1, 3}} {
		d, err := Diff(lab, p[0], p[1], "")
		if err != nil {
			t.Fatal(err)
		}
		add(fmt.Sprintf("diff-%d-%d", p[0], p[1]), &d, d.Text())
	}
	if _, err := Diff(lab, 1, 9, ""); err != nil {
		add("diff-err", &struct{ Err string }{err.Error()}, err.Error())
	}
	evs, warns := BundleEvents(lab, rep.Findings)
	tl := TimelineReport{Dir: lab.Dir, Events: Timeline(evs, TimelineOptions{}), Warnings: warns}
	add("timeline-lab", &tl, tl.Text())

	// formatos ilegibles y comandos rechazados: un aviso por regla
	bad := map[string]map[string]string{"R1_10.0.0.1": {"r001_20261104-100000.txt": strings.Join([]string{
		sec("2026-11-04T10:00:01Z", "show processes cpu", "nada"),
		sec("2026-11-04T10:00:02Z", "show processes memory", "nada"),
		sec("2026-11-04T10:00:03Z", "show interfaces", "nada"),
		sec("2026-11-04T10:00:04Z", "show version", "nada"),
		sec("2026-11-04T10:00:05Z", "show spanning-tree detail", "nada"),
		sec("2026-11-04T10:00:06Z", "show ip bgp summary", "nada"),
		sec("2026-11-04T10:00:07Z", "show ip ospf neighbor", "nada"),
		sec("2026-11-04T10:00:08Z", "show standby brief", "nada"),
		"===== 2026-11-04T10:00:09Z · show logging · comando inválido =====\n% Invalid input\n",
		sec("2026-11-04T10:00:10Z", "show clock detail", "10:00:10.000 UTC Wed Nov 4 2026"),
	}, "")}}
	bb := synth(t, bad)
	run("bad", bb, Options{})
	d0, _ := Diff(bb, 1, 1, "")
	add("diff-same", &d0, d0.Text())

	// topes: salida recortada y paquete leído a medias
	restore := SetLimits(120, 1<<30)
	trunc := synth(t, map[string]map[string]string{"R1_10.0.0.1": {"r001_20261104-100000.txt": sec("2026-11-04T10:00:01Z", "show logging", strings.Repeat("x", 400))}})
	restore()
	run("trunc", trunc, Options{})
	restore = SetLimits(1<<20, 300)
	over := synth(t, map[string]map[string]string{"R1_10.0.0.1": {"r001_20261104-100000.txt": sec("2026-11-04T10:00:01Z", "show logging", strings.Repeat("y\n", 400)) + sec("2026-11-04T10:00:02Z", "show clock detail", strings.Repeat("z\n", 400))}})
	restore()
	run("over", over, Options{})

	// diferencias entre rondas: comando solo en una, demasiado distinto y más de 400 líneas
	big := func(n int, p string) string {
		var s []string
		for i := 0; i < n; i++ {
			s = append(s, fmt.Sprintf("%s%d", p, i))
		}
		return strings.Join(s, "\n")
	}
	df := synth(t, map[string]map[string]string{
		"R1_10.0.0.1": {
			"r001_20261104-100000.txt": sec("2026-11-04T10:00:01Z", "show alfa", "uno") + sec("2026-11-04T10:00:02Z", "show enorme", big(2100, "a")) + sec("2026-11-04T10:00:03Z", "show largo", big(10, "l")),
			"r002_20261104-101000.txt": sec("2026-11-04T10:10:01Z", "show beta", "dos") + sec("2026-11-04T10:10:02Z", "show enorme", big(2100, "b")) + sec("2026-11-04T10:10:03Z", "show largo", big(500, "m")),
		},
		"R2_10.0.0.2": {"r001_20261104-100000.txt": sec("2026-11-04T10:00:01Z", "show alfa", "uno")},
	})
	dd, err := Diff(df, 1, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	add("diff-notes", &dd, dd.Text())

	// línea de tiempo: eventos de pcap, auditoría y syslog con avisos
	pr := pcapan.Report{}
	at := time.Date(2026, 11, 4, 10, 9, 18, 0, time.UTC)
	pr.TCP.Events = []pcapan.TCPEvent{{At: at, Kind: "rst", Client: "10.0.0.1", Server: "10.0.0.2"}, {At: at, Kind: "retransmit", Client: "10.0.0.1", Server: "10.0.0.2"}}
	pr.DNS.Slow = []pcapan.DNSQuery{{Name: "a.example", Type: "A", Client: "10.0.0.1", Server: "10.0.0.53", Latency: 2 * time.Second, At: at}}
	pr.DNS.Errors = []pcapan.DNSQuery{{Name: "b.example", Type: "A", RCode: "NXDOMAIN", At: at}}
	pr.DNS.Unanswered = []pcapan.DNSQuery{{Name: "c.example", Type: "A", Client: "10.0.0.1", Server: "10.0.0.53", At: at}}
	pr.ICMP.Unreachable = []pcapan.ICMPEvent{{From: "10.0.0.2", Target: "10.0.0.9", Code: 3, At: at}}
	pr.ICMP.TTLExceeded = []pcapan.ICMPEvent{{From: "10.0.0.3", Target: "10.0.0.9", At: at}}
	audit := `{"at":"2026-11-04T10:09:19Z","actor":"ana","action":"job.start","target":"j1","detail":"rounds=3"}` + "\n" + `{"at":"2026-11-04T10:09:20Z","actor":"bot","action":"fleet.find","target":"","detail":""}` + "\n"
	sl := t.TempDir()
	os.WriteFile(filepath.Join(sl, "syslog_20261103-000000.log"), []byte(
		"2026-11-04T10:09:19Z 10.0.0.2:514 <189>%BGP-5-ADJCHANGE: neighbor 10.0.13.1 Down\nmalformada\nmas basura\n"), 0o600)
	sev, swarn := SyslogFiles([]string{filepath.Join(sl, "syslog_20261103-000000.log")}, at.Add(-time.Hour), at.Add(time.Hour), 40)
	allEv := append(append(append([]Event{}, PcapEvents(pr)...), AuditEvents(strings.NewReader(audit))...), sev...)
	tl2 := TimelineReport{Dir: "d", Events: Timeline(allEv, TimelineOptions{}), Warnings: swarn}
	add("timeline-extra", &tl2, tl2.Text())
	sev2, swarn2 := SyslogFiles([]string{filepath.Join(sl, "syslog_20261103-000000.log")}, at.Add(-time.Hour), at.Add(time.Hour), 1<<20)
	tl3 := TimelineReport{Dir: "d", Around: at, Window: "30s", Events: Timeline(sev2, TimelineOptions{Around: at, Window: 30 * time.Second}), Warnings: swarn2}
	add("timeline-syslog", &tl3, tl3.Text())

	// STP recién cambiado en la primera ronda, y un zip que no abre
	stp := "VLAN0010 is executing the rstp compatible Spanning Tree protocol\n  Current root has priority 24586, address 0011.2233.4455\n  Number of topology changes 46 last change occurred 00:00:35 ago\n          from GigabitEthernet1/0/7\n"
	zb := synth(t, map[string]map[string]string{"R1_10.0.0.1": {"r001_20261104-100000.txt": sec("2026-11-04T10:00:01Z", "show spanning-tree detail", stp)}, "": {"roto.zip": "esto no es un zip"}})
	run("stp-zip", zb, Options{})
	if os.Geteuid() != 0 {
		ub := t.TempDir()
		os.MkdirAll(filepath.Join(ub, "R1_10.0.0.1"), 0o755)
		os.WriteFile(filepath.Join(ub, "R1_10.0.0.1", "r001_20261104-100000.txt"), []byte(sec("2026-11-04T10:00:01Z", "show version", "x")), 0o600)
		os.WriteFile(filepath.Join(ub, "R1_10.0.0.1", "r002_20261104-101000.txt"), []byte(sec("2026-11-04T10:10:01Z", "show version", "x")), 0o600)
		os.Chmod(filepath.Join(ub, "R1_10.0.0.1", "r002_20261104-101000.txt"), 0)
		if b, err := Load(ub); err == nil {
			r := Analyze(b, rs, Options{})
			add("analyze-unreadable", &r, r.Text())
			tmpDirs = append(tmpDirs, ub)
		}
	}

	// el log del equipo: hora local con y sin show clock, reloj sin sincronizar, marcas de uptime
	lg := synth(t, map[string]map[string]string{
		"R1_10.0.0.1": {"r001_20261104-100000.txt": strings.Join([]string{
			sec("2026-11-04T10:00:01Z", "show clock detail", "09:00:01.000 CST Wed Nov 4 2026\nTime source is NTP"),
			sec("2026-11-04T10:00:02Z", "show logging", "Nov  4 09:00:00.123 CST: %SYS-5-CONFIG_I: Configured from console by ana\n*Nov  4 09:00:01.123 CST: %LINK-3-UPDOWN: Interface Gi1, changed state to down\n000123: 3d04h: %SYS-5-RESTART: System restarted\n"),
		}, "")},
		"R2_10.0.0.2": {"r001_20261104-100000.txt": sec("2026-11-04T10:00:02Z", "show logging", "Nov  4 09:00:00.123 PST: %SYS-5-CONFIG_I: Configured from console by ana\n")},
	})
	e4, w4 := BundleEvents(lg, nil)
	tl4 := TimelineReport{Dir: lg.Dir, Events: Timeline(e4, TimelineOptions{}), Warnings: w4}
	add("timeline-log", &tl4, tl4.Text())
	// las rutas de las carpetas temporales cambian en cada corrida: no entran en el golden
	for k, g := range out {
		for _, d := range tmpDirs {
			g = golden{strings.ReplaceAll(g.JSON, d, "<DIR>"), strings.ReplaceAll(g.Text, d, "<DIR>")}
		}
		out[k] = golden{tmpRe.ReplaceAllString(g.JSON, "<DIR>"), tmpRe.ReplaceAllString(g.Text, "<DIR>")}
	}
	return out, ptrs
}

func TestRegresionEs(t *testing.T) {
	got, _ := regCases(t)
	const file = "testdata/regresion_es.golden.json"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		b, _ := json.MarshalIndent(got, "", " ")
		if err := os.WriteFile(file, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]golden
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(got))
	for n := range got {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if got[n] != want[n] {
			t.Errorf("%s: el español cambió\n got: %+v\nwant: %+v", n, got[n], want[n])
		}
	}
	if len(want) != len(got) {
		t.Errorf("casos: %d vs %d", len(got), len(want))
	}
}

// tmpDirs son las carpetas temporales de los escenarios; tmpRe las que arma t.TempDir() en general.
var (
	tmpDirs []string
	tmpRe   = regexp.MustCompile(`/tmp/Test[A-Za-z0-9_]*/\d+`)
)
