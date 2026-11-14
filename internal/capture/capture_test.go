package capture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
	"github.com/oom-netsec/MACUAHUITL/internal/platform"
)

func TestSplitPatrolHeaders(t *testing.T) {
	text := "===== 2026-11-04T10:00:00Z · show version =====\nCisco IOS XE Software\n" +
		"===== 2026-11-04T10:00:01Z · show  IP  arp =====\nInternet 192.0.2.1\n" +
		"===== 2026-11-04T10:00:02Z · show bogus · comando inválido =====\n% Invalid input\n" +
		"===== ronda 2 · 2026-11-04T10:00:03Z · show clock =====\n10:00:03\n"
	m := Split(text)
	if m["show version"] != "Cisco IOS XE Software\n" || m["show ip arp"] != "Internet 192.0.2.1\n" || m["show clock"] != "10:00:03\n" {
		t.Fatalf("m = %q", m)
	}
	if _, ok := m["show bogus"]; ok {
		t.Fatal("invalid command kept")
	}
}

func TestSplitPrompts(t *testing.T) {
	text := "SW-LAB-01#show version\nCisco IOS XE Software\nSW-LAB-01# dir flash:\nDirectory of flash:/\n\nSW-LAB-01#\n"
	m := Split(text)
	if m["show version"] != "Cisco IOS XE Software\n" || m["dir flash:"] != "Directory of flash:/\n\n" || len(m) != 2 {
		t.Fatalf("m = %q", m)
	}
}

func TestGet(t *testing.T) {
	m := map[string]string{"show bootvar": "x"}
	if got, cmd := Get(m, "show boot", "show bootvar"); got != "x" || cmd != "show bootvar" {
		t.Fatalf("%q %q", got, cmd)
	}
	if got, _ := Get(m, "show version"); got != "" {
		t.Fatal("phantom output")
	}
}

func TestReadDir(t *testing.T) {
	root := t.TempDir()
	start := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	w, err := patrol.NewWriter(root, patrol.Spec{Name: "cambio-pre"}, start)
	if err != nil {
		t.Fatal(err)
	}
	dev := patrol.Device{Host: "SW-LAB-01", IP: "192.0.2.10", Platform: "ios-xe"}
	for r, txt := range []string{"uno", "dos"} {
		w.Write(dev, r+1, start.Add(time.Duration(r)*time.Minute), platform.Output{Command: "show clock", Text: txt, Started: start}, false)
	}
	w.Write(dev, 2, start.Add(time.Minute), platform.Output{Command: "show version", Text: "Version 17.9", Started: start}, false)
	m := patrol.Manifest{Name: "cambio-pre", Devices: []patrol.DeviceResult{
		{Target: patrol.Target{Address: "192.0.2.10"}, Round: 1, Hostname: "SW-LAB-01", State: "failed"},
		{Target: patrol.Target{Address: "192.0.2.10"}, Round: 2, Hostname: "SW-LAB-01", State: "completed"},
		{Target: patrol.Target{Address: "192.0.2.11"}, Round: 2, State: "failed", Detail: "auth"},
	}}
	b, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(w.Dir(), "manifest.json"), b, 0o600)
	devs, err := ReadDir(w.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 2 || devs[0].Address != "192.0.2.10" || devs[0].State != "completed" || devs[0].Hostname != "SW-LAB-01" {
		t.Fatalf("devs = %+v", devs)
	}
	if devs[0].Outputs["show clock"] != "dos\n" || devs[0].Outputs["show version"] != "Version 17.9\n" {
		t.Fatalf("outputs = %q", devs[0].Outputs)
	}
	if devs[1].State != "failed" || len(devs[1].Outputs) != 0 {
		t.Fatalf("failed device = %+v", devs[1])
	}
	if _, err := ReadDir(root); err == nil {
		t.Fatal("dir without manifest accepted")
	}
}

// Una salida marcada « · incompleto» (comando cortado) no sirve como evidencia.
func TestSplitDescartaLasIncompletas(t *testing.T) {
	text := "===== 2026-11-04T10:00:00Z · show version · incompleto =====\nCisco IO\n" +
		"===== 2026-11-04T10:00:01Z · show clock =====\n10:00:01\n"
	m := Split(text)
	if _, ok := m["show version"]; ok || m["show clock"] != "10:00:01\n" {
		t.Fatalf("m = %q", m)
	}
}
