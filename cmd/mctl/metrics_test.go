package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// metricsJob arma la carpeta de un trabajo con dos rondas de CPU y de interfaz.
func metricsJob(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dd := filepath.Join(dir, "SW1_10.0.0.1")
	os.MkdirAll(dd, 0o700)
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	var b strings.Builder
	for r := 0; r < 2; r++ {
		ts := t0.Add(time.Duration(r) * 5 * time.Minute).Format(time.RFC3339)
		fmt.Fprintf(&b, "===== ronda %d · %s · show processes cpu sorted =====\nCPU utilization for five seconds: %d%%/0%%; one minute: 2%%; five minutes: 3%%\n", r+1, ts, 10+r)
		fmt.Fprintf(&b, "===== ronda %d · %s · show interfaces =====\nGigabitEthernet1/0/1 is up, line protocol is up\n  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,\n     100 packets input, %d bytes, 0 no buffer\n     %d input errors, %d CRC, 0 frame, 0 overrun, 0 ignored\n     100 packets output, %d bytes, 0 underruns\n     0 output errors, 0 collisions, 0 interface resets\n",
			r+1, ts, 1000+r*37_500_000, 3*r, 2*r, 5000+r*75_000_000)
	}
	os.WriteFile(filepath.Join(dd, "SW1.txt"), []byte(b.String()), 0o600)
	return dir
}

func TestJobMetricsCSVyTexto(t *testing.T) {
	startCore(t)
	dir := metricsJob(t)
	out := must(t, "", "job", "metrics", dir, "--csv")
	rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatalf("csv inválido: %v\n%s", err, out)
	}
	if strings.Join(rows[0], ",") != "equipo,serie,nombre,ronda,hora,metrica,valor" {
		t.Fatalf("cabecera = %v", rows[0])
	}
	find := func(serie, name, metric, round string) string {
		for _, r := range rows[1:] {
			if r[1] == serie && r[2] == name && r[5] == metric && r[3] == round {
				return r[6]
			}
		}
		return "(no está)"
	}
	if find("cpu", "", "5s", "2") != "11" || find("interfaz", "Gi1/0/1", "bps_entrada", "2") != "1e+06" && find("interfaz", "Gi1/0/1", "bps_entrada", "2") != "1000000" {
		t.Fatalf("filas:\n%s", out)
	}
	if find("interfaz", "Gi1/0/1", "crc", "2") != "2" || find("interfaz", "Gi1/0/1", "crc", "1") != "(no está)" {
		t.Fatalf("la primera ronda no tiene diferencias y no debe escribir ceros:\n%s", out)
	}
	txt := must(t, "", "job", "metrics", dir, "--device", "sw1")
	for _, want := range []string{"SW1 (10.0.0.1)", "CPU", "Gi1/0/1", "aviso: falta el comando show memory statistics"} {
		if !strings.Contains(txt, want) {
			t.Errorf("falta %q en:\n%s", want, txt)
		}
	}
	if _, err := mctl(t, "", "job", "metrics"); err == nil {
		t.Error("sin argumentos debe fallar")
	}
	if _, err := mctl(t, "", "job", "metrics", dir, "--csv", "--json"); err == nil {
		t.Error("--csv y --json juntos")
	}
}

func TestPortsStatusDeUnTrabajo(t *testing.T) {
	startCore(t)
	dir := t.TempDir()
	dd := filepath.Join(dir, "SW1_10.0.0.1")
	os.MkdirAll(dd, 0o700)
	read := func(n string) string {
		b, err := os.ReadFile(filepath.Join("..", "..", "internal", "parse", "iosxe", "testdata", n+".txt"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	body := "===== ronda 1 · 2026-11-06T10:00:00Z · show interfaces status =====\n" + read("ios152_show-interfaces-status") +
		"===== ronda 1 · 2026-11-06T10:00:01Z · show interfaces trunk =====\n" + read("ios152_show-interfaces-trunk") +
		"===== ronda 1 · 2026-11-06T10:00:02Z · show etherchannel summary =====\n" + read("iosxe_show-etherchannel-summary")
	os.WriteFile(filepath.Join(dd, "SW1.txt"), []byte(body), 0o600)
	out := must(t, "", "ports", "status", dir)
	for _, want := range []string{"SW1 (10.0.0.1)", "Gi1/0/1", "1/0/12", "err-disabled", "trunk Po1(P)", "canal Po1 (SU, LACP): Gi1/0/1(P) Gi1/0/2(P)", "sala de juntas"} {
		if !strings.Contains(out, want) {
			t.Errorf("falta %q en:\n%s", want, out)
		}
	}
	if j := must(t, "", "ports", "status", dir, "--json"); !strings.Contains(j, `"channelFlags"`) || !strings.Contains(j, `"speedMbps"`) {
		t.Fatalf("json:\n%s", j)
	}
	for _, args := range [][]string{{"ports", "status"}, {"ports", "status", "a", "b"}, {"ports", "status", "--device", "10.0.0.1:x"}} {
		if _, err := mctl(t, "", args...); err == nil {
			t.Errorf("mctl %v debió fallar", args)
		}
	}
}
