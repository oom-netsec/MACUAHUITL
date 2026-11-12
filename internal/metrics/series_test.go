package metrics

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)

// at devuelve la hora de la ronda r (cada 5 minutos).
func at(r int) time.Time { return t0.Add(time.Duration(r-1) * 5 * time.Minute) }

type ifc struct {
	name                string
	in, out             int64
	rateIn, rateOut     int64
	crc, outErr, resets int64
	inDrops, outDrops   int64
	bwKbit              int64
	noBytes             bool
	cleared             string // hh:mm:ss de «Last clearing…»; vacío = never
}

func (i ifc) text() string {
	bw := i.bwKbit
	if bw == 0 {
		bw = 1000000
	}
	s := fmt.Sprintf("%s is up, line protocol is up (connected)\n  Description: enlace %s\n  MTU 1500 bytes, BW %d Kbit/sec, DLY 10 usec,\n", i.name, i.name, bw)
	if i.cleared != "" {
		s += "  Last clearing of \"show interface\" counters " + i.cleared + "\n"
	}
	s += fmt.Sprintf("  Input queue: 0/2000/%d/0 (size/max/drops/flushes); Total output drops: %d\n", i.inDrops, i.outDrops)
	s += fmt.Sprintf("  5 minute input rate %d bits/sec, 3 packets/sec\n  5 minute output rate %d bits/sec, 6 packets/sec\n", i.rateIn, i.rateOut)
	if !i.noBytes {
		s += fmt.Sprintf("     100 packets input, %d bytes, 0 no buffer\n", i.in)
	}
	s += fmt.Sprintf("     0 runts, 0 giants, 0 throttles\n     %d input errors, %d CRC, 0 frame, 0 overrun, 0 ignored\n", i.crc, i.crc)
	if !i.noBytes {
		s += fmt.Sprintf("     200 packets output, %d bytes, 0 underruns\n", i.out)
	}
	s += fmt.Sprintf("     %d output errors, 0 collisions, %d interface resets\n", i.outErr, i.resets)
	return s
}

type round struct {
	n       int
	cpu     string // salida completa o ""
	mem     string
	ifaces  []ifc
	version string // uptime, p. ej. "1 hour, 5 minutes"
}

func header(t time.Time, cmd string) string {
	return fmt.Sprintf("===== %s · %s =====\n", t.UTC().Format(time.RFC3339), cmd)
}

func cpuText(a, b, c int) string {
	return fmt.Sprintf("CPU utilization for five seconds: %d%%/0%%; one minute: %d%%; five minutes: %d%%\n PID Runtime(ms) Invoked uSecs 5Sec 1Min 5Min TTY Process\n", a, b, c)
}

const memText = "Processor Pool Total: 1000 Used: 400 Free: 600\n      I/O Pool Total: 200 Used: 50 Free: 150\n"

func versionText(up string) string {
	return "Cisco IOS XE Software, Version 17.09.04a\nSW1 uptime is " + up + "\n"
}

// writeJob arma <dir>/SW1_10.0.0.1/r00N_….txt, como lo deja Patrol (una ronda por archivo).
func writeJob(t *testing.T, rounds ...round) string {
	t.Helper()
	dir := t.TempDir()
	dd := filepath.Join(dir, "SW1_10.0.0.1")
	if err := os.MkdirAll(dd, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, r := range rounds {
		var b strings.Builder
		ts := at(r.n)
		if r.cpu != "" {
			b.WriteString(header(ts, "show processes cpu sorted") + r.cpu)
		}
		if r.mem != "" {
			b.WriteString(header(ts, "show processes memory") + r.mem)
		}
		if r.version != "" {
			b.WriteString(header(ts, "show version") + versionText(r.version))
		}
		if len(r.ifaces) > 0 {
			b.WriteString(header(ts.Add(5*time.Second), "show interfaces"))
			for _, i := range r.ifaces {
				b.WriteString(i.text())
			}
		}
		name := fmt.Sprintf("r%03d_%s.txt", r.n, ts.Format("20060102-150405"))
		if err := os.WriteFile(filepath.Join(dd, name), []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func near(a, b float64) bool { return math.Abs(a-b) < 0.01 }

func TestCPUYMemoria(t *testing.T) {
	dir := writeJob(t,
		round{n: 1, cpu: cpuText(5, 4, 3), mem: memText},
		round{n: 2, cpu: cpuText(10, 8, 6), mem: memText},
		round{n: 3, cpu: cpuText(20, 15, 9), mem: strings.ReplaceAll(memText, "Used: 400 Free: 600", "Used: 500 Free: 500")})
	res, err := Build(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Devices) != 1 || res.Devices[0].Hostname != "SW1" || res.Devices[0].Address != "10.0.0.1" {
		t.Fatalf("equipos = %+v", res.Devices)
	}
	d := res.Devices[0]
	if len(d.CPU) != 3 || d.CPU[2] != (CPUPoint{Round: 3, At: at(3), Five: 20, OneMin: 15, FiveMin: 9}) || d.CPU[0].Round != 1 {
		t.Fatalf("cpu = %+v", d.CPU)
	}
	if len(d.Memory) != 2 || d.Memory[0].Pool != "Processor" || d.Memory[1].Pool != "I/O" || len(d.Memory[0].Points) != 3 {
		t.Fatalf("memoria = %+v", d.Memory)
	}
	if p := d.Memory[0].Points[2]; p.Used != 500 || p.Free != 500 || p.Total != 1000 {
		t.Fatalf("pool = %+v", p)
	}
	if len(d.Warnings) != 1 || !strings.Contains(d.Warnings[0], "show interfaces") {
		t.Fatalf("avisos = %v", d.Warnings)
	}
}

func TestTasaPorContadoresYDiferencias(t *testing.T) {
	// 37 500 000 bytes en 300 s = 1 Mb/s; 75 000 000 = 2 Mb/s
	dir := writeJob(t,
		round{n: 1, ifaces: []ifc{{name: "GigabitEthernet1/0/1", in: 1_000_000, out: 2_000_000, rateIn: 111, rateOut: 222, crc: 10, outErr: 1, resets: 1, inDrops: 5, outDrops: 7}}},
		round{n: 2, ifaces: []ifc{{name: "GigabitEthernet1/0/1", in: 38_500_000, out: 77_000_000, rateIn: 333, rateOut: 444, crc: 14, outErr: 3, resets: 1, inDrops: 6, outDrops: 10}}})
	res, err := Build(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	d := res.Devices[0]
	if len(d.Interfaces) != 1 || d.Interfaces[0].Name != "Gi1/0/1" || d.Interfaces[0].BWKbit != 1000000 || d.Interfaces[0].Description != "enlace GigabitEthernet1/0/1" {
		t.Fatalf("interfaces = %+v", d.Interfaces)
	}
	p := d.Interfaces[0].Points
	if len(p) != 2 {
		t.Fatalf("puntos = %+v", p)
	}
	// ronda 1: no hay con qué restar; usa la tasa de 5 minutos del equipo y no inventa diferencias
	if p[0].Source != "5min" || p[0].InBps != 111 || p[0].OutBps != 222 || p[0].DeltaOK {
		t.Fatalf("punto 1 = %+v", p[0])
	}
	// ronda 2: por contadores, y las diferencias
	if p[1].Source != "counters" || !near(p[1].InBps, 1_000_000) || !near(p[1].OutBps, 2_000_000) || !near(p[1].InUtilPct, 0.1) || !near(p[1].OutUtilPct, 0.2) {
		t.Fatalf("punto 2 = %+v", p[1])
	}
	if !p[1].DeltaOK || p[1].CRC != 4 || p[1].InErrors != 4 || p[1].OutErrors != 2 || p[1].Resets != 0 || p[1].InDrops != 1 || p[1].OutDrops != 3 {
		t.Fatalf("diferencias = %+v", p[1])
	}
	if !p[1].At.Equal(at(2).Add(5*time.Second)) || p[1].Round != 2 {
		t.Fatalf("hora = %v ronda %d", p[1].At, p[1].Round)
	}
}

func TestReinicioDelEquipoNoDaTasasFalsas(t *testing.T) {
	// la ronda 3 llega con 5 minutos de uptime: el equipo se reinició entre 2 y 3 y los contadores empezaron de cero,
	// pero aquí vienen más altos (no bajaron): sin la corrección saldría una tasa enorme.
	dir := writeJob(t,
		round{n: 1, version: "1 week, 2 hours, 0 minutes", ifaces: []ifc{{name: "Gi1/0/1", in: 100, out: 100, rateIn: 5, rateOut: 6, crc: 1}}},
		round{n: 2, version: "1 week, 2 hours, 5 minutes", ifaces: []ifc{{name: "Gi1/0/1", in: 200, out: 200, rateIn: 5, rateOut: 6, crc: 1}}},
		round{n: 3, version: "4 minutes", ifaces: []ifc{{name: "Gi1/0/1", in: 30_000_000, out: 30_000_000, rateIn: 9, rateOut: 8, crc: 40}}},
		round{n: 4, version: "9 minutes", ifaces: []ifc{{name: "Gi1/0/1", in: 67_500_000, out: 30_000_100, rateIn: 9, rateOut: 8, crc: 41}}})
	res, err := Build(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	d := res.Devices[0]
	p := d.Interfaces[0].Points
	if p[1].Source != "counters" || !p[1].DeltaOK || p[1].Reboot {
		t.Fatalf("ronda 2 = %+v", p[1])
	}
	if !p[2].Reboot || p[2].DeltaOK || p[2].CRC != 0 || p[2].Source != "5min" || p[2].InBps != 9 {
		t.Fatalf("ronda 3 (reinicio) = %+v", p[2])
	}
	if p[3].Reboot || !p[3].DeltaOK || p[3].CRC != 1 || p[3].Source != "counters" || !near(p[3].InBps, 1_000_000) {
		t.Fatalf("ronda 4 (ya sin reinicio) = %+v", p[3])
	}
	if len(d.Reboots) != 1 || d.Reboots[0].Round != 3 {
		t.Fatalf("reinicios = %+v", d.Reboots)
	}
}

func TestContadorBajaSinVersion(t *testing.T) {
	// sin show version el reinicio se ve porque el contador baja: no hay tasa por contadores ni diferencia negativa
	dir := writeJob(t,
		round{n: 1, ifaces: []ifc{{name: "Gi1/0/1", in: 9_000_000_000, out: 9_000_000_000, rateIn: 7, rateOut: 8, resets: 5}}},
		round{n: 2, ifaces: []ifc{{name: "Gi1/0/1", in: 1000, out: 1000, rateIn: 7, rateOut: 8, resets: 0}}})
	res, _ := Build(dir, Options{})
	p := res.Devices[0].Interfaces[0].Points[1]
	if p.Source != "5min" || p.DeltaOK || p.Resets != 0 || p.InBps != 7 {
		t.Fatalf("punto = %+v", p)
	}
}

func TestUnContadorQueBajaAnulaLasDiferencias(t *testing.T) {
	dir := writeJob(t,
		round{n: 1, ifaces: []ifc{{name: "Gi1/0/1", in: 100, out: 100, crc: 5, outDrops: 50}}},
		round{n: 2, ifaces: []ifc{{name: "Gi1/0/1", in: 200, out: 200, crc: 9, outDrops: 3}}})
	res, _ := Build(dir, Options{})
	p := res.Devices[0].Interfaces[0].Points[1]
	if p.DeltaOK || p.CRC != 0 || p.OutDrops != 0 {
		t.Fatalf("no deben quedar diferencias a medias: %+v", p)
	}
}

func TestContadorDaLaVuelta(t *testing.T) {
	// la vuelta de 32 bits solo se acepta si cabe en el tiempo: aquí 5 minutos a 1 Gb/s dejarían dar varias vueltas
	dir := writeJob(t,
		round{n: 1, ifaces: []ifc{{name: "Gi1/0/1", in: 4_294_000_000, out: 1000, rateIn: 1, rateOut: 2, bwKbit: 1000}}},
		round{n: 2, ifaces: []ifc{{name: "Gi1/0/1", in: 20_000, out: 2000, rateIn: 1, rateOut: 2, bwKbit: 1000}}})
	res, _ := Build(dir, Options{})
	p := res.Devices[0].Interfaces[0].Points[1]
	// BW 1 Mb/s, 300 s: 2^32*8/1e6 = 34 360 s ≫ 300 s → la vuelta cabe: (2^32-4_294_000_000+20_000)*8/300
	want := float64(1<<32-4_294_000_000+20_000) * 8 / 300
	if p.Source != "counters" || !near(p.InBps, want) {
		t.Fatalf("punto = %+v, quería %v", p, want)
	}
}

func TestFaltaUnComando(t *testing.T) {
	dir := writeJob(t, round{n: 1, cpu: cpuText(1, 1, 1)}, round{n: 2, cpu: cpuText(2, 2, 2)})
	res, err := Build(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	d := res.Devices[0]
	if len(d.Memory) != 0 || len(d.Interfaces) != 0 {
		t.Fatalf("debe venir vacío: %+v", d)
	}
	joined := strings.Join(d.Warnings, "|")
	for _, want := range []string{"show memory statistics", "show processes memory", "show interfaces"} {
		if !strings.Contains(joined, want) {
			t.Errorf("el aviso no dice que falta %q: %v", want, d.Warnings)
		}
	}
	if strings.Contains(joined, "show processes cpu") {
		t.Errorf("el CPU sí se recolectó: %v", d.Warnings)
	}
}

func TestSalidaIlegibleSeAvisa(t *testing.T) {
	dir := writeJob(t, round{n: 1, cpu: "% Invalid input detected at '^' marker.\n"}, round{n: 2, cpu: cpuText(2, 2, 2)})
	res, _ := Build(dir, Options{})
	d := res.Devices[0]
	if len(d.CPU) != 1 || d.CPU[0].Round != 2 || !strings.Contains(strings.Join(d.Warnings, "|"), "no se pudo leer show processes cpu sorted en 1 ronda") {
		t.Fatalf("cpu = %+v avisos = %v", d.CPU, d.Warnings)
	}
}

func TestTopNYInterfacesPedidas(t *testing.T) {
	var a, b []ifc
	for i, n := range []string{"Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/4"} {
		// la utilización crece con i: Gi1/0/4 es la más usada
		a = append(a, ifc{name: n, in: 0, out: 0, rateIn: 1, rateOut: 1})
		b = append(b, ifc{name: n, in: int64(i+1) * 3_750_000, out: 0, rateIn: 1, rateOut: 1})
	}
	dir := writeJob(t, round{n: 1, ifaces: a}, round{n: 2, ifaces: b})
	res, _ := Build(dir, Options{MaxIfaces: 2})
	d := res.Devices[0]
	if d.IfaceTotal != 4 || len(d.Interfaces) != 2 || d.Interfaces[0].Name != "Gi1/0/4" || d.Interfaces[1].Name != "Gi1/0/3" {
		t.Fatalf("top 2 = %+v (total %d)", names(d), d.IfaceTotal)
	}
	if !near(d.Interfaces[0].PeakUtilPct, 0.04) {
		t.Fatalf("pico = %v", d.Interfaces[0].PeakUtilPct)
	}
	res, _ = Build(dir, Options{Ifaces: []string{"gigabitethernet1/0/1", "Gi9/9/9"}})
	d = res.Devices[0]
	if len(d.Interfaces) != 1 || d.Interfaces[0].Name != "Gi1/0/1" || !strings.Contains(strings.Join(res.Warnings, "|"), "Gi9/9/9") {
		t.Fatalf("pedidas = %+v avisos %v", names(d), res.Warnings)
	}
}

func names(d Device) []string {
	var o []string
	for _, i := range d.Interfaces {
		o = append(o, i.Name)
	}
	return o
}

func TestTopeDePuntosYFiltroDeEquipo(t *testing.T) {
	var rs []round
	for n := 1; n <= 10; n++ {
		rs = append(rs, round{n: n, cpu: cpuText(n, n, n)})
	}
	dir := writeJob(t, rs...)
	res, _ := Build(dir, Options{MaxPoints: 4})
	d := res.Devices[0]
	if len(d.CPU) != 4 || d.CPU[0].Round != 7 || d.CPU[3].Round != 10 || !d.Truncated {
		t.Fatalf("cpu = %+v truncado=%v", d.CPU, d.Truncated)
	}
	if res, _ = Build(dir, Options{Device: "10.0.0.1"}); len(res.Devices) != 1 {
		t.Fatal("filtro por dirección")
	}
	if res, _ = Build(dir, Options{Device: "sw1"}); len(res.Devices) != 1 {
		t.Fatal("filtro por nombre, sin importar mayúsculas")
	}
	res, _ = Build(dir, Options{Device: "otro"})
	if len(res.Devices) != 0 || len(res.Warnings) == 0 {
		t.Fatalf("equipo inexistente: %+v", res)
	}
}

func TestConsolidadoYComandoInvalido(t *testing.T) {
	dir := t.TempDir()
	dd := filepath.Join(dir, "SW1_10.0.0.1")
	os.MkdirAll(dd, 0o700)
	body := fmt.Sprintf("===== ronda 1 · %s · show processes cpu =====\n%s===== ronda 1 · %s · show memory statistics · comando inválido =====\n%% Invalid\n===== ronda 2 · %s · show processes cpu =====\n%s",
		at(1).Format(time.RFC3339), cpuText(1, 2, 3), at(1).Format(time.RFC3339), at(2).Format(time.RFC3339), cpuText(4, 5, 6))
	os.WriteFile(filepath.Join(dd, "SW1.txt"), []byte(body), 0o600)
	res, err := Build(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	d := res.Devices[0]
	if len(d.CPU) != 2 || d.CPU[1].Round != 2 || d.CPU[1].Five != 4 || len(d.Memory) != 0 {
		t.Fatalf("= %+v", d)
	}
	// la salida de un comando inválido no cuenta como dato: falta, no es ilegible
	if w := strings.Join(d.Warnings, "|"); !strings.Contains(w, "falta el comando show memory statistics") || strings.Contains(w, "no se pudo leer") {
		t.Fatalf("avisos = %v", d.Warnings)
	}
}

func TestSinCarpeta(t *testing.T) {
	if _, err := Build(filepath.Join(t.TempDir(), "no-existe"), Options{}); err == nil {
		t.Fatal("una carpeta inexistente es un error")
	}
}

func TestClearCountersNoEsTraficoFalso(t *testing.T) {
	// puerto de 100 Mb/s: 3e9 octetos antes y 5 000 después de un clear counters parecían una vuelta de 32 bits
	// (≈34 Mb/s falsos, que caben en el puerto y en 5 minutos)
	dir := writeJob(t,
		round{n: 1, ifaces: []ifc{{name: "Gi1/0/1", in: 3_000_000_000, out: 1000, rateIn: 7, rateOut: 8, crc: 4, bwKbit: 100000}}},
		round{n: 2, ifaces: []ifc{{name: "Gi1/0/1", in: 5000, out: 3000, rateIn: 7, rateOut: 8, crc: 1, bwKbit: 100000, cleared: "00:01:00"}}})
	res, _ := Build(dir, Options{})
	p := res.Devices[0].Interfaces[0].Points[1]
	if p.Source != "5min" || p.InBps != 7 || p.DeltaOK || p.CRC != 0 {
		t.Fatalf("tras un clear counters: %+v", p)
	}
	// una limpieza anterior a la ronda previa no afecta la diferencia
	dir = writeJob(t,
		round{n: 1, ifaces: []ifc{{name: "Gi1/0/1", in: 1000, out: 1000, crc: 4, cleared: "00:20:00"}}},
		round{n: 2, ifaces: []ifc{{name: "Gi1/0/1", in: 38_001_000, out: 2000, crc: 6, cleared: "00:25:00"}}})
	res, _ = Build(dir, Options{})
	if p = res.Devices[0].Interfaces[0].Points[1]; p.Source != "counters" || !p.DeltaOK || p.CRC != 2 {
		t.Fatalf("limpieza vieja: %+v", p)
	}
}
