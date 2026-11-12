package analyze

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/pcapan"
)

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}

func bySource(evs []Event, src string) []Event {
	var out []Event
	for _, e := range evs {
		if e.Source == src {
			out = append(out, e)
		}
	}
	return out
}

func TestBundleEvents(t *testing.T) {
	b := load(t)
	rep := Analyze(b, rules(t), Options{})
	evs, warns := BundleEvents(b, rep.Findings)
	if len(warns) != 0 {
		t.Fatalf("warnings = %+v", warns)
	}
	if n := len(bySource(evs, "patrol")); n != 6 {
		t.Fatalf("round events = %d", n)
	}
	if n := len(bySource(evs, "hallazgo")); n != len(rep.Findings) {
		t.Fatalf("finding events = %d", n)
	}
	logs := bySource(evs, "log-equipo")
	seen := map[string]int{}
	for _, e := range logs {
		seen[e.At.String()+" "+e.Device+" "+e.Text]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Errorf("log line repeated across rounds: %s", k)
		}
	}
	var flap, bgp *Event
	for i, e := range logs {
		if strings.Contains(e.Text, "GigabitEthernet1/0/7, changed state to down") && flap == nil {
			flap = &logs[i]
		}
		if strings.Contains(e.Text, "%BGP-5-ADJCHANGE: neighbor 10.0.13.1 Down") {
			bgp = &logs[i]
		}
	}
	if flap == nil || !flap.At.Equal(ts("2026-11-04T09:58:12.345Z")) || !strings.Contains(flap.Note, "sin sincronizar") || flap.Severity != "alta" {
		t.Fatalf("flap = %+v", flap)
	}
	if bgp == nil || !bgp.At.Equal(ts("2026-11-04T10:09:18.640Z")) || bgp.Note != "" || !strings.HasPrefix(bgp.Device, "RTR2") || bgp.Severity != "baja" {
		t.Fatalf("bgp = %+v", bgp)
	}
}

func TestLogYearInferenceAndUptimeStamps(t *testing.T) {
	b := &Bundle{Sections: []Section{{Device: "X_1.1.1.1", Round: 1, At: ts("2027-01-01T00:05:00Z"), Command: "show logging",
		Text: "Dec 31 23:59:00.000 UTC: %SYS-5-CONFIG_I: x\n1d02h: %LINK-3-UPDOWN: Interface Gi1, changed state to down\nNov  4 10:00:00 CST: %SYS-5-CONFIG_I: y\n"}}}
	evs, warns := BundleEvents(b, nil)
	logs := bySource(evs, "log-equipo")
	if len(logs) != 2 || !logs[0].At.Equal(ts("2026-12-31T23:59:00Z")) {
		t.Fatalf("logs = %+v", logs)
	}
	if !strings.Contains(logs[1].Note, "CST") {
		t.Errorf("non-UTC zone not noted: %+v", logs[1])
	}
	var msgs []string
	for _, w := range warns {
		msgs = append(msgs, w.Msg)
	}
	if len(warns) != 2 || !strings.Contains(strings.Join(msgs, "|"), "uptime") || !strings.Contains(strings.Join(msgs, "|"), "sin referencia de zona") {
		t.Fatalf("warnings = %+v", warns)
	}
}

func TestSyslogEvents(t *testing.T) {
	in := "2026-11-04T10:09:19Z 10.0.0.2:514 <189>%BGP-5-ADJCHANGE: neighbor 10.0.13.1 Down\n" +
		"basura sin hora\n" +
		"2026-11-04T10:09:21Z [2001:db8::2]:514 <187>%LINK-3-UPDOWN: Interface Gi0/0/1, changed state to down\n"
	evs, warns := SyslogEvents(strings.NewReader(in), "syslog_x.log", time.Time{}, time.Time{})
	if len(evs) != 2 || len(warns) != 1 {
		t.Fatalf("evs=%+v warns=%+v", evs, warns)
	}
	if evs[0].Device != "10.0.0.2" || evs[0].Severity != "baja" || !strings.Contains(evs[0].Text, "ADJCHANGE") || evs[1].Device != "2001:db8::2" || evs[1].Severity != "alta" {
		t.Fatalf("evs = %+v", evs)
	}
	b := load(t)
	b.Resolve(evs)
	if evs[0].Device != "RTR2_10.0.0.2" || evs[1].Device != "2001:db8::2" {
		t.Fatalf("resolve = %+v", evs)
	}
}

func TestAuditEvents(t *testing.T) {
	in := `{"seq":7,"at":"2026-11-04T10:09:00Z","actor":"ana","action":"diag.run","target":"10.0.0.2","detail":"ping"}` + "\n{roto\n"
	evs := AuditEvents(strings.NewReader(in))
	if len(evs) != 1 || evs[0].Source != "auditoria" || !strings.Contains(evs[0].Text, "diag.run 10.0.0.2 ping") || !evs[0].At.Equal(ts("2026-11-04T10:09:00Z")) {
		t.Fatalf("evs = %+v", evs)
	}
}

func TestPcapEvents(t *testing.T) {
	at := ts("2026-11-04T10:09:18Z")
	rep := pcapan.Report{File: "/x.pcap"}
	rep.TCP.Events = []pcapan.TCPEvent{{At: at, Kind: "rst", Client: "10.0.0.1:4000", Server: "10.0.13.1:179"}}
	rep.DNS.Slow = []pcapan.DNSQuery{{Client: "a", Server: "b", Name: "x.example", Latency: 700 * time.Millisecond, At: at}}
	rep.DNS.Unanswered = []pcapan.DNSQuery{{Name: "mudo.example", At: at}}
	rep.ICMP.Unreachable = []pcapan.ICMPEvent{{From: "10.0.0.254", Target: "10.0.0.9", Code: 1, At: at}}
	evs := PcapEvents(rep)
	var got []string
	for _, e := range evs {
		got = append(got, e.Text)
	}
	if len(evs) != 4 || !strings.Contains(strings.Join(got, "|"), "RST 10.0.0.1:4000 → 10.0.13.1:179") || !strings.Contains(strings.Join(got, "|"), "700ms") {
		t.Fatalf("evs = %q", got)
	}
}

func TestTimelineFilters(t *testing.T) {
	b := load(t)
	evs, _ := BundleEvents(b, nil)
	evs = append(evs, Event{At: ts("2026-11-04T10:09:10Z"), Source: "auditoria", Text: "diag.run"})
	around := ts("2026-11-04T10:09:18Z")
	got := Timeline(evs, TimelineOptions{Around: around, Window: 30 * time.Second, Device: "RTR2"})
	if len(got) == 0 {
		t.Fatal("empty")
	}
	for i, e := range got {
		if e.At.Sub(around) > 30*time.Second || around.Sub(e.At) > 30*time.Second {
			t.Errorf("outside window: %+v", e)
		}
		if e.Device != "" && !strings.HasPrefix(e.Device, "RTR2") {
			t.Errorf("device filter leaked %+v", e)
		}
		if i > 0 && got[i-1].At.After(e.At) {
			t.Errorf("not sorted at %d", i)
		}
	}
	srcs := fmt.Sprint(len(bySource(got, "auditoria")), len(bySource(got, "log-equipo")))
	if srcs != "1 4" {
		t.Fatalf("sources = %s in %+v", srcs, got)
	}
	if all := Timeline(evs, TimelineOptions{}); len(all) != len(evs) {
		t.Fatalf("no filter dropped events: %d of %d", len(all), len(evs))
	}
}

// Con "service timestamps log datetime localtime" sin show-timezone el log no trae
// zona: la hora se corrige con el desfase entre show clock detail y la ronda.
func TestLocalLogTimeCorrectedWithShowClock(t *testing.T) {
	at := ts("2026-11-04T10:00:05Z")
	b := &Bundle{Sections: []Section{
		{Device: "R_1.1.1.1", Round: 1, At: at, Command: "show clock detail", Text: "04:00:04.871 CST Wed Nov 4 2026\nTime source is NTP\n"},
		{Device: "R_1.1.1.1", Round: 1, At: at.Add(2 * time.Second), Command: "show logging", Text: "Nov  4 04:00:01.123: %LINK-3-UPDOWN: Interface Gi1, changed state to down\nNov  4 2026 10:00:02.000 UTC: %SYS-5-CONFIG_I: utc explícito\n"},
	}}
	evs, warns := BundleEvents(b, nil)
	logs := bySource(evs, "log-equipo")
	if len(warns) != 0 || len(logs) != 2 {
		t.Fatalf("logs=%+v warns=%+v", logs, warns)
	}
	if !logs[0].At.Equal(ts("2026-11-04T10:00:01.123Z")) || !strings.Contains(logs[0].Note, "-06:00") {
		t.Fatalf("local line = %+v", logs[0])
	}
	if !logs[1].At.Equal(ts("2026-11-04T10:00:02Z")) || logs[1].Note != "" {
		t.Fatalf("explicit UTC line must not move: %+v", logs[1])
	}
}

func TestLocalLogWithoutClockWarnsOncePerDevice(t *testing.T) {
	var b Bundle
	for r := 1; r <= 2; r++ {
		b.Sections = append(b.Sections, Section{Device: "R_1.1.1.1", Round: r, At: ts("2026-11-04T10:00:05Z").Add(time.Duration(r) * 10 * time.Minute),
			Command: "show logging", Text: fmt.Sprintf("Nov  4 04:0%d:01.123: %%SYS-5-CONFIG_I: x\n", r)})
	}
	_, warns := BundleEvents(&b, nil)
	if len(warns) != 1 || !strings.Contains(warns[0].Msg, "hora del log sin referencia de zona") || warns[0].Device != "R_1.1.1.1" {
		t.Fatalf("warnings = %+v", warns)
	}
}

func TestSyslogFilesBoundedByWindowStampAndBytes(t *testing.T) {
	dir := t.TempDir()
	from, to := ts("2026-11-04T10:00:00Z"), ts("2026-11-04T10:30:00Z")
	name := func(at time.Time) string {
		return filepath.Join(dir, "syslog_"+at.In(time.Local).Format("20060102-150405")+".log")
	}
	in := "2026-11-04T10:09:19Z 10.0.0.2:514 <189>dentro\n"
	early := name(from.Add(-time.Hour))
	os.WriteFile(early, []byte("2026-11-04T08:00:00Z 10.0.0.2:514 <189>antes\n"+in+"2026-11-04T23:00:00Z 10.0.0.2:514 <189>despues\n"), 0o600)
	// Empezó después de to: ni se abre, aunque traiga una línea dentro de la ventana.
	late := name(to.Add(time.Minute))
	os.WriteFile(late, []byte("2026-11-04T10:09:20Z 10.0.0.2:514 <189>tardio\n"), 0o600)
	evs, warns := SyslogFiles([]string{late, early}, from, to, 1<<20)
	if len(evs) != 1 || !strings.Contains(evs[0].Text, "dentro") || len(warns) != 0 {
		t.Fatalf("evs=%+v warns=%+v", evs, warns)
	}
	big := name(from)
	os.WriteFile(big, []byte(strings.Repeat(in, 1000)), 0o600)
	evs, warns = SyslogFiles([]string{big}, from, to, 4096)
	if len(evs) == 0 || len(evs) >= 1000 || len(warns) == 0 || !strings.Contains(warns[len(warns)-1].Msg, "tope") {
		t.Fatalf("cap: %d events, warns=%+v", len(evs), warns)
	}
}

func TestEventosTraenLaFichaDeLaBaseDeMensajes(t *testing.T) {
	b := &Bundle{Sections: []Section{{Device: "R_1.1.1.1", Round: 1, At: ts("2026-11-04T10:00:05Z"), Command: "show logging",
		Text: "Nov  4 2026 10:00:01.000 UTC: %SYS-2-MALLOCFAIL: Memory allocation of 100 bytes failed\nNov  4 2026 10:00:02.000 UTC: %NO-6-CONOCIDO: nada\n"}}}
	evs, _ := BundleEvents(b, nil)
	logs := bySource(evs, "log-equipo")
	if len(logs) != 2 || !strings.Contains(logs[0].KB, "%SYS-2-MALLOCFAIL") || !strings.Contains(logs[0].KB, "Acción:") || logs[1].KB != "" {
		t.Fatalf("%+v", logs)
	}
	sys, _ := SyslogEvents(strings.NewReader("2026-11-04T10:09:19Z 10.0.0.2:514 <189>%PM-4-ERR_DISABLE: bpduguard error detected on Fa0/1\n"), "s.log", time.Time{}, time.Time{})
	if len(sys) != 1 || !strings.Contains(sys[0].KB, "%PM-4-ERR_DISABLE") {
		t.Fatalf("%+v", sys)
	}
	rep := TimelineReport{Events: logs[:1]}
	if !strings.Contains(rep.Text(), "[%SYS-2-MALLOCFAIL:") {
		t.Fatalf("texto sin la ficha:\n%s", rep.Text())
	}
}
