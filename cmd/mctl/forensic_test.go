package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestForensicMsgYCrashinfo(t *testing.T) {
	startCore(t)
	out, err := mctl(t, "", "msg", "%SYS-2-MALLOCFAIL")
	if err != nil || !strings.Contains(out, "Causa probable") || !strings.Contains(out, "show memory statistics") {
		t.Fatalf("msg = %q %v", out, err)
	}
	if out, err = mctl(t, "", "msg", "%PM-4-*"); err != nil || !strings.Contains(out, "%PM-4-ERR_DISABLE") || !strings.Contains(out, "%PM-4-ERR_RECOVER") {
		t.Fatalf("comodín = %q %v", out, err)
	}
	if out, err = mctl(t, "", "msg", "%SYS-2-MALLOCFAIL", "--json"); err != nil || !strings.HasPrefix(out, "[") {
		t.Fatalf("json = %q %v", out, err)
	}
	if out, err = mctl(t, "", "msg", "%NO-1-EXISTE"); err != nil || !strings.Contains(out, "sin coincidencias") {
		t.Fatalf("inexistente = %q %v", out, err)
	}
	if _, err = mctl(t, "", "msg", "a", "b"); err == nil {
		t.Fatal("dos consultas aceptadas")
	}
	src, _ := filepath.Abs("../../internal/crashinfo/testdata/ios15_segv.txt")
	if out, err = mctl(t, "", "crashinfo", src); err != nil || !strings.Contains(out, "IP Input") || !strings.Contains(out, "15.2(7)E3") || !strings.Contains(out, "Mensajes conocidos") {
		t.Fatalf("crashinfo = %q %v", out, err)
	}
	if out, err = mctl(t, "", "crashinfo", src, "--json"); err != nil || !strings.HasPrefix(out, "{") {
		t.Fatalf("crashinfo json = %q %v", out, err)
	}
	core := filepath.Join(t.TempDir(), "x.core")
	os.WriteFile(core, []byte("\x7fELF\x00\x00\x00"), 0o600)
	if out, err = mctl(t, "", "crashinfo", core); err != nil || !strings.Contains(out, "TAC") {
		t.Fatalf("core = %q %v", out, err)
	}
	if _, err = mctl(t, "", "crashinfo"); err == nil {
		t.Fatal("sin archivo")
	}
	if _, err = mctl(t, "", "crashinfo", filepath.Join(t.TempDir(), "nada")); err == nil {
		t.Fatal("archivo inexistente")
	}
}

func TestForensicLogsPatterns(t *testing.T) {
	e := startCore(t)
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	var b strings.Builder
	for i := 0; i < 6; i++ {
		fmt.Fprintf(&b, "%s 192.0.2.1:514 <187>%%LINK-3-UPDOWN: Interface Gi1/0/%d, changed state to down\n", t0.Add(time.Duration(i)*time.Second).Format(time.RFC3339), i+1)
	}
	file := filepath.Join(t.TempDir(), "syslog.log")
	os.WriteFile(file, []byte(b.String()), 0o600)
	out, err := mctl(t, "", "logs", "patterns", file)
	if err != nil || !strings.Contains(out, "[RÁFAGA] x6") || !strings.Contains(out, "base de mensajes:") {
		t.Fatalf("archivo = %q %v", out, err)
	}
	if out, err = mctl(t, b.String(), "logs", "patterns", "-", "--burst", "7"); err != nil || strings.Contains(out, "RÁFAGA") || !strings.Contains(out, "x6") {
		t.Fatalf("stdin con --burst 7 = %q %v", out, err)
	}
	if out, err = mctl(t, "", "logs", "patterns", file, "--json"); err != nil || !strings.HasPrefix(out, "{") {
		t.Fatalf("json = %q %v", out, err)
	}
	if out, err = mctl(t, "", "logs", "patterns", "--capture"); err != nil || !strings.Contains(out, "no hay capturas") {
		t.Fatalf("capture = %q %v", out, err)
	}
	os.MkdirAll(filepath.Join(e.out, "syslog"), 0o700)
	os.WriteFile(filepath.Join(e.out, "syslog", "syslog_20261106-100000.log"), []byte(b.String()), 0o600)
	if out, err = mctl(t, "", "logs", "patterns", "--capture"); err != nil || !strings.Contains(out, "x6") {
		t.Fatalf("capture con datos = %q %v", out, err)
	}
	for _, args := range [][]string{{"logs", "patterns"}, {"logs", "patterns", file, "--capture"}, {"logs", "patterns", "--burst", "-1", file}, {"logs", "patterns", "a", "b"}} {
		if _, err = mctl(t, "", args...); err == nil || !strings.Contains(err.Error(), "uso: mctl logs patterns") {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if _, err = mctl(t, "", "logs", "patterns", filepath.Join(t.TempDir(), "nada")); err == nil {
		t.Fatal("archivo inexistente")
	}
}

func TestForensicLogsFlaps(t *testing.T) {
	e := startCore(t)
	src, _ := filepath.Abs("../../internal/logintel/testdata/show_logging_3560cx.txt")
	out, err := mctl(t, "", "logs", "flaps", src)
	// El show logging del 3560CX trae las marcas sin año: se toma el actual y hay flapping igual.
	if err != nil || !strings.Contains(out, "[FLAPPING]") || !strings.Contains(out, "Gi0/3") || !strings.Contains(out, "down up down up down up") {
		t.Fatalf("flaps = %q %v", out, err)
	}
	if out, err = mctl(t, "", "logs", "flaps", src, "--count", "7"); err != nil || !strings.Contains(out, "Ninguna interfaz con flapping") {
		t.Fatalf("--count 7 = %q %v", out, err)
	}
	if out, err = mctl(t, "", "logs", "flaps", src, "--json"); err != nil || !strings.HasPrefix(out, "{") || !strings.Contains(out, `"counter_jumps":[]`) {
		t.Fatalf("json = %q %v", out, err)
	}
	// Un trabajo en disco: show interfaces de dos rondas.
	dir := filepath.Join(e.out, "job", "SW1_192.0.2.1")
	os.MkdirAll(dir, 0o755)
	r := func(n, resets int) string {
		return fmt.Sprintf("===== 2026-11-06T1%d:00:00Z · show interfaces =====\nGigabitEthernet0/3 is up, line protocol is up\n     0 output errors, 0 collisions, %d interface resets\n", n, resets)
	}
	os.WriteFile(filepath.Join(dir, "r001_20261106-100000.txt"), []byte(r(0, 1)), 0o600)
	os.WriteFile(filepath.Join(dir, "r002_20261106-110000.txt"), []byte(r(1, 9)), 0o600)
	if out, err = mctl(t, "", "logs", "flaps", "--job", filepath.Join(e.out, "job")); err != nil || !strings.Contains(out, "interface resets subió de 1 a 9 (+8) entre las rondas 1 y 2") {
		t.Fatalf("job = %q %v", out, err)
	}
	for _, args := range [][]string{{"logs", "flaps"}, {"logs", "flaps", src, "--count", "-1"}, {"logs", "flaps", src, "--capture"}} {
		if _, err = mctl(t, "", args...); err == nil || !strings.Contains(err.Error(), "uso: mctl logs flaps") {
			t.Fatalf("%v: %v", args, err)
		}
	}
}

func TestForensicLogsDebugs(t *testing.T) {
	startCore(t)
	var b strings.Builder
	for i := 0; i < 30; i++ {
		b.WriteString("*Nov  6 10:00:01.000: OSPF-1 ADJ   Gi0/1: Rcv hello from 10.0.0.2 area 0 10.0.12.2\n")
	}
	b.WriteString("*Nov  6 10:00:02.000: CDP-PA: Packet received from sw1\n*Nov  6 10:00:02.500: CDP-PA: Packet received from sw2\n*Nov  6 10:00:03.000: OSPF-1 ADJ   Gi0/1: Mismatched hello parameters from 10.0.12.2\n")
	file := filepath.Join(t.TempDir(), "debug.txt")
	os.WriteFile(file, []byte(b.String()), 0o600)
	out, err := mctl(t, "", "logs", "debugs", file, "--hide", "cdp-pa")
	if err != nil || !strings.Contains(out, "2 líneas ocultas por ruido") || !strings.Contains(out, "línea 33 [rara dentro de una familia frecuente") {
		t.Fatalf("archivo = %q %v", out, err)
	}
	if out, err = mctl(t, b.String(), "logs", "debugs", "-", "--hide", "cdp", "--hide", "hello from", "--json"); err != nil || !strings.HasPrefix(out, "{") || !strings.Contains(out, `"hidden":32`) {
		t.Fatalf("stdin = %q %v", out, err)
	}
	for _, args := range [][]string{{"logs", "debugs"}, {"logs", "debugs", "--capture"}, {"logs", "debugs", file, "--top", "-1"}} {
		if _, err = mctl(t, "", args...); err == nil || !strings.Contains(err.Error(), "uso: mctl logs debugs") {
			t.Fatalf("%v: %v", args, err)
		}
	}
}

func TestForensicLogsLeaks(t *testing.T) {
	e := startCore(t)
	dir := filepath.Join(e.out, "job", "SW1_192.0.2.1")
	os.MkdirAll(dir, 0o755)
	for i, h := range []int{10 << 20, 12 << 20, 15 << 20} {
		body := fmt.Sprintf("===== 2026-11-06T1%d:00:00Z · show processes memory sorted =====\nProcessor Pool Total: 100 Used: 50 Free: 50\n\n PID TTY  Allocated      Freed    Holding    Getbufs    Retbufs Process\n 312   0   45678912    1234567   %d          0          0 BGP Router\n", i, h)
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("r%03d_20261106-1%d0000.txt", i+1, i)), []byte(body), 0o600)
	}
	job := filepath.Join(e.out, "job")
	out, err := mctl(t, "", "logs", "leaks", job)
	if err != nil || !strings.Contains(out, "[FUGA POSIBLE] SW1_192.0.2.1 BGP Router (pid 312): +5.0 MiB") {
		t.Fatalf("leaks = %q %v", out, err)
	}
	if out, err = mctl(t, "", "logs", "leaks", job, "--min-growth-kib", "9000"); err != nil || strings.Contains(out, "[FUGA POSIBLE]") {
		t.Fatalf("umbral = %q %v", out, err)
	}
	if out, err = mctl(t, "", "logs", "leaks", job, "--json"); err != nil || !strings.HasPrefix(out, "{") || !strings.Contains(out, `"process":"BGP Router"`) {
		t.Fatalf("json = %q %v", out, err)
	}
	for _, args := range [][]string{{"logs", "leaks"}, {"logs", "leaks", job, "--rounds", "-1"}} {
		if _, err = mctl(t, "", args...); err == nil || !strings.Contains(err.Error(), "uso: mctl logs leaks") {
			t.Fatalf("%v: %v", args, err)
		}
	}
}
