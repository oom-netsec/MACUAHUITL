package capture

import (
	"encoding/json"
	"fmt"
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

// Dos equipos con la misma dirección y distinto puerto son equipos distintos, cada uno con su carpeta.
func TestReadDirSeparaPorPuerto(t *testing.T) {
	root := t.TempDir()
	start := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	w, _ := patrol.NewWriter(root, patrol.Spec{Name: "puertos"}, start)
	for _, p := range []uint16{0, 2222} {
		dev := patrol.Device{Host: "SW1", IP: "192.0.2.10", Port: p, Platform: "ios-xe"}
		w.Write(dev, 1, start, platform.Output{Command: "show clock", Text: "p" + fmt.Sprint(p), Started: start}, false)
	}
	m := patrol.Manifest{Name: "puertos", Devices: []patrol.DeviceResult{
		{Target: patrol.Target{Address: "192.0.2.10"}, Round: 1, Hostname: "SW1", State: "completed"},
		{Target: patrol.Target{Address: "192.0.2.10", Port: 2222}, Round: 1, Hostname: "SW1", State: "completed"},
	}}
	b, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(w.Dir(), "manifest.json"), b, 0o600)
	devs, err := ReadDir(w.Dir())
	if err != nil || len(devs) != 2 {
		t.Fatalf("%v %+v", err, devs)
	}
	if devs[0].Address != "192.0.2.10" || devs[1].Address != "192.0.2.10:2222" {
		t.Fatalf("direcciones: %q %q", devs[0].Address, devs[1].Address)
	}
	if devs[0].Outputs["show clock"] != "p0\n" || devs[1].Outputs["show clock"] != "p2222\n" {
		t.Fatalf("salidas mezcladas: %q %q", devs[0].Outputs, devs[1].Outputs)
	}
}

// Una captura vieja, con la carpeta sin puerto, se sigue leyendo aunque el destino use otro puerto.
func TestReadDirLeeCarpetaViejaSinPuerto(t *testing.T) {
	root := t.TempDir()
	start := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	w, _ := patrol.NewWriter(root, patrol.Spec{Name: "viejo"}, start)
	w.Write(patrol.Device{Host: "SW1", IP: "192.0.2.10"}, 1, start, platform.Output{Command: "show clock", Text: "viejo", Started: start}, false)
	m := patrol.Manifest{Devices: []patrol.DeviceResult{{Target: patrol.Target{Address: "192.0.2.10", Port: 2222}, Round: 1, Hostname: "SW1", State: "completed"}}}
	b, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(w.Dir(), "manifest.json"), b, 0o600)
	devs, err := ReadDir(w.Dir())
	if err != nil || len(devs) != 1 || devs[0].Outputs["show clock"] != "viejo\n" {
		t.Fatalf("%v %+v", err, devs)
	}
}

// El reintento a la carpeta vieja no toma la evidencia de otro equipo del manifest (misma IP y hostname, otro puerto).
func TestReadDirReintentoNoTomaLaCarpetaDeOtroEquipo(t *testing.T) {
	root := t.TempDir()
	start := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	w, _ := patrol.NewWriter(root, patrol.Spec{Name: "dos"}, start)
	w.Write(patrol.Device{Host: "SW1", IP: "192.0.2.10"}, 1, start, platform.Output{Command: "show clock", Text: "del22", Started: start}, false)
	m := patrol.Manifest{Devices: []patrol.DeviceResult{
		{Target: patrol.Target{Address: "192.0.2.10"}, Round: 1, Hostname: "SW1", State: "completed"},
		{Target: patrol.Target{Address: "192.0.2.10", Port: 2222}, Round: 1, Hostname: "SW1", State: "failed"},
	}}
	b, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(w.Dir(), "manifest.json"), b, 0o600)
	devs, err := ReadDir(w.Dir())
	if err != nil || len(devs) != 2 || devs[0].Outputs["show clock"] != "del22\n" || len(devs[1].Outputs) != 0 {
		t.Fatalf("%v %+v", err, devs)
	}
}
