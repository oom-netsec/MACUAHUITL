package fleet

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// put escribe un archivo de prueba bajo dir creando las carpetas.
func put(t *testing.T, dir, rel, txt string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(txt), 0o644); err != nil {
		t.Fatal(err)
	}
}

const errDis = "===== 2026-11-05T08:00:00Z · show interfaces status =====\nPort      Name   Status       Vlan  Duplex  Speed Type\nGi1/0/9   sala   err-disabled 10    auto    auto  10/100/1000BaseTX\n"

// C1: una carpeta que no es <host>_<ip> (outputs/diag) no es un equipo ni frena la bajada.
func TestLoadCarpetaDiagNoEsEquipo(t *testing.T) {
	d := t.TempDir()
	put(t, d, "trabajo_1/SW1_10.0.0.1/r001.txt", errDis)
	put(t, d, "diag/diag_ping_x.txt", "===== 2026-11-05T08:00:00Z · ping 1.1.1.1 =====\n!!!!!\n")
	f, err := Load(d, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, dv := range f.Devs {
		if dv.Name == "diag" {
			t.Fatalf("equipo falso diag: %+v", f.Devs)
		}
	}
	if h := f.Health(); len(h.Issues) != 1 || h.Issues[0].Severity != "critica" {
		t.Errorf("debe aparecer el err-disabled: %+v", h)
	}
	// una carpeta sin equipos reales no es una flota
	e := t.TempDir()
	put(t, e, "diag/diag_ping_x.txt", "===== 2026-11-05T08:00:00Z · ping 1.1.1.1 =====\n!!!!!\n")
	if _, err := Load(e, now); err == nil {
		t.Error("sin equipos debe fallar")
	}
	// equipo sin encabezados: no se crea y se avisa
	g := t.TempDir()
	put(t, g, "trabajo_1/SW1_10.0.0.1/r001.txt", errDis)
	put(t, g, "trabajo_1/SW2_10.0.0.2/r001.txt", "texto sin encabezados\n")
	f, err = Load(g, now)
	if err != nil || len(f.Devs) != 1 || !strings.Contains(strings.Join(f.Warnings, "|"), "SW2_10.0.0.2") {
		t.Errorf("%v %+v", err, f)
	}
}

func hdr(cmd string) string { return "===== 2026-11-05T08:00:00Z · " + cmd + " =====\n" }

// I5: Fleet.Warnings llega a cada resultado.
func TestLoadAvisosLlegaAResultados(t *testing.T) {
	d := t.TempDir()
	put(t, d, "trabajo_1/SW1_10.0.0.1/r001.txt", errDis)
	put(t, d, "trabajo_1/ronda.zip", "esto no es un zip")
	f, err := Load(d, now)
	if err != nil || len(f.Warnings) == 0 {
		t.Fatalf("%v %v", err, f.Warnings)
	}
	rs := map[string][]string{
		"health": f.Health().Warnings, "summary": f.Summary().Warnings, "capacity": f.Capacity(0).Warnings,
		"inventory": f.Inventory().Warnings, "find": f.Find("10.1.1.1").Warnings, "trace": f.Trace("aabb.cc00.0a01").Warnings,
		"path": f.Path("10.1.1.1", "10.2.2.2").Warnings,
	}
	for k, w := range rs {
		if !strings.Contains(strings.Join(w, "|"), "ronda.zip") {
			t.Errorf("%s no propaga los avisos de carga: %v", k, w)
		}
	}
}

// I5: una sección cortada por un tope nunca se guarda como completa.
func TestLoadTopesMarcanTruncado(t *testing.T) {
	defer func(a, b, c int) { maxSection, maxLine, maxFile = a, b, int64(c) }(maxSection, maxLine, int(maxFile))
	maxSection, maxLine, maxFile = 200, 1000, 100000
	d := t.TempDir()
	big := strings.Repeat("x", 150) + "\n"
	put(t, d, "trabajo_1/SW1_10.0.0.1/r001.txt",
		hdr("show ip arp")+big+big+ // excede maxSection
			hdr("show ntp status")+"Clock is synchronized, stratum 3\n"+
			hdr("show ip route")+strings.Repeat("y", 5000)+"\n"+ // línea > maxLine
			errDis)
	f, err := Load(d, now)
	if err != nil {
		t.Fatal(err)
	}
	dv := f.Devs[0]
	for _, c := range []string{"show ip arp", "show ip route"} {
		if e, ok := dv.Get(c); !ok || !e.Truncated || !rejected(e) {
			t.Errorf("%s debe quedar truncada: %+v", c, e)
		}
	}
	if e, _ := dv.Get("show ntp status"); e.Truncated || !strings.Contains(e.Text, "synchronized") {
		t.Errorf("la sección intermedia debe sobrevivir: %+v", e)
	}
	if e, ok := dv.Get("show interfaces status"); !ok || e.Truncated {
		t.Errorf("lo que sigue a la línea larga no se pierde: %+v", e)
	}
	if !strings.Contains(strings.Join(f.Warnings, "|"), "truncada") {
		t.Errorf("sin aviso: %v", f.Warnings)
	}
	if w := f.Summary().Warnings; !strings.Contains(strings.Join(w, "|"), "truncada") {
		t.Errorf("el resultado debe avisar: %v", w)
	}
	// tope por archivo
	maxFile = 300
	e := t.TempDir()
	put(t, e, "trabajo_1/SW1_10.0.0.1/r001.txt", hdr("show ntp status")+"Clock is synchronized, stratum 3\n"+hdr("show ip arp")+big+big+big)
	f, err = Load(e, now)
	if err != nil {
		t.Fatal(err)
	}
	if ev, _ := f.Devs[0].Get("show ip arp"); !ev.Truncated {
		t.Errorf("el archivo cortado deja la última sección truncada: %+v", ev)
	}
}

func zipOf(t *testing.T, p string, files map[string]string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(p), 0o755)
	fh, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(fh)
	for n, c := range files {
		w, _ := zw.Create(n)
		w.Write([]byte(c))
	}
	zw.Close()
	fh.Close()
}

// I7: topes totales contra una carpeta o un zip hostil, siempre con aviso.
func TestLoadTopesTotales(t *testing.T) {
	defer func(a int64, b, c int) { maxTotal, maxEntries, maxDevs = a, b, c }(maxTotal, maxEntries, maxDevs)
	warn := func(f *Fleet) string { return strings.Join(f.Warnings, "|") }

	// demasiados equipos
	maxTotal, maxEntries, maxDevs = 1<<30, 1000, 2
	d := t.TempDir()
	for _, h := range []string{"A_10.0.0.1", "B_10.0.0.2", "C_10.0.0.3", "D_10.0.0.4"} {
		put(t, d, "trabajo_1/"+h+"/r.txt", errDis)
	}
	f, err := Load(d, now)
	if err != nil || len(f.Devs) != 2 || !strings.Contains(warn(f), "tope de 2 equipos") {
		t.Errorf("equipos: %v %d %v", err, len(f.Devs), f.Warnings)
	}

	// demasiadas entradas en un zip
	maxDevs, maxEntries = 2000, 5
	e := t.TempDir()
	files := map[string]string{}
	for i := 0; i < 20; i++ {
		files[fmt.Sprintf("A_10.0.0.1/r%02d.txt", i)] = errDis
	}
	zipOf(t, filepath.Join(e, "trabajo_1", "x.zip"), files)
	f, err = Load(e, now)
	if err != nil || !strings.Contains(warn(f), "tope de 5 archivos") {
		t.Errorf("entradas: %v %v", err, f.Warnings)
	}

	// bytes descomprimidos: 4 entradas de 1 MiB con tope de 2 MiB
	maxEntries, maxTotal = 20000, 2<<20
	g := t.TempDir()
	files = map[string]string{}
	for i := 0; i < 4; i++ {
		files[fmt.Sprintf("A_10.0.0.1/r%d.txt", i)] = hdr("show ntp status") + strings.Repeat("z\n", 512<<10)
	}
	zipOf(t, filepath.Join(g, "trabajo_1", "x.zip"), files)
	f, err = Load(g, now)
	if err != nil || !strings.Contains(warn(f), "tope de lectura") {
		t.Errorf("bytes: %v %v", err, f.Warnings)
	}
}

// Los output_dir de los trabajos, fuera de outputs/, también entran a la flota (QA 3560CX).
func TestLoadCarpetasExtra(t *testing.T) {
	d, x := t.TempDir(), t.TempDir() // d = outputs/ por defecto, sin equipos
	put(t, x, "ronda_1/SW1_10.0.0.1/r001.txt", errDis)
	f, err := Load(d, now, x, filepath.Join(x, "no-existe"))
	if err != nil || len(f.Devs) != 1 {
		t.Fatalf("f = %+v err = %v", f, err)
	}
	if _, err := Load(d, now); err == nil {
		t.Error("sin extras y sin equipos debe fallar")
	}
	// outputs/ aún no existe pero hay una carpeta de trabajo legible
	if f, err = Load(filepath.Join(d, "no"), now, x); err != nil || len(f.Devs) != 1 {
		t.Fatalf("f = %+v err = %v", f, err)
	}
}

// Una sección marcada incompleta no desplaza la evidencia completa anterior ni cuenta como truncada.
func TestLoadSaltaSeccionesIncompletas(t *testing.T) {
	d := t.TempDir()
	put(t, d, "trabajo_1/SW1_10.0.0.1/r001.txt", hdr("show ntp status")+"Clock is synchronized, stratum 3\n")
	put(t, d, "trabajo_1/SW1_10.0.0.1/r002.txt", "===== 2026-11-05T09:00:00Z · show ntp status · incompleto =====\nClock is\n")
	f, err := Load(d, now)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := f.Devs[0].Get("show ntp status"); !ok || e.Truncated || !strings.Contains(e.Text, "synchronized") {
		t.Fatalf("%+v", e)
	}
}

// Una carpeta <equipo>_<ip>_<puerto> (puerto distinto de 22) también es un equipo, suelta o en zip.
func TestLoadCarpetaConPuerto(t *testing.T) {
	d := t.TempDir()
	put(t, d, "trabajo_1/SW1_10.0.0.1_2222/r001.txt", errDis)
	f, err := Load(d, now)
	if err != nil || len(f.Devs) != 1 || f.Devs[0].IP != "10.0.0.1" {
		t.Fatalf("suelta: %v %+v", err, f)
	}
	z := t.TempDir()
	zipOf(t, filepath.Join(z, "trabajo_1", "x.zip"), map[string]string{"SW1_10.0.0.1_2222/r001.txt": errDis})
	f, err = Load(z, now)
	if err != nil || len(f.Devs) != 1 {
		t.Fatalf("zip: %v %+v", err, f)
	}
}
