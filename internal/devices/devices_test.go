package devices

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, p, body string, mtime time.Time) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if !mtime.IsZero() {
		os.Chtimes(p, mtime, mtime)
	}
}

func manifest(ended string, devs ...string) string {
	var d []string
	for _, x := range devs { // "host|ip|plataforma|estado"
		f := strings.Split(x, "|")
		d = append(d, `{"Target":{"Address":"`+f[1]+`"},"Hostname":"`+f[0]+`","Platform":"`+f[2]+`","State":"`+f[3]+`"}`)
	}
	return `{"name":"j","started_at":"` + ended + `","ended_at":"` + ended + `","devices":[` + strings.Join(d, ",") + `]}`
}

var (
	d1 = time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	d2 = time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	d3 = time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)
)

func find(r Result, addr string) *Device {
	for i := range r.Devices {
		if r.Devices[i].Address == addr {
			return &r.Devices[i]
		}
	}
	return nil
}

func TestCollectJuntaFuentesSinDuplicados(t *testing.T) {
	out := t.TempDir()
	// trabajo viejo: SW1 y SW2 con manifiesto y evidencia
	write(t, filepath.Join(out, "j1_20261104-100000", "manifest.json"), manifest(d1.Format(time.RFC3339), "SW1|10.0.0.1|ios-xe|completed", "SW2|10.0.0.2|ios-xe|completed", "CAIDO|10.0.0.9|ios-xe|failed"), d1)
	write(t, filepath.Join(out, "j1_20261104-100000", "SW1_10.0.0.1", "r001_x.txt"), "===== x =====\n", d1)
	write(t, filepath.Join(out, "j1_20261104-100000", "SW2_10.0.0.2", "r001_x.txt"), "===== x =====\n", d1)
	// trabajo nuevo: SW1 otra vez (más reciente) y un equipo que solo está en un zip
	write(t, filepath.Join(out, "j2_20261106-090000", "manifest.json"), manifest(d3.Format(time.RFC3339), "SW1|10.0.0.1|ios-xe|completed"), d3)
	write(t, filepath.Join(out, "j2_20261106-090000", "SW1_10.0.0.1", "r001_y.txt"), "===== y =====\n", d3)
	zp := filepath.Join(out, "j3_20261105-100000", "j3.zip")
	os.MkdirAll(filepath.Dir(zp), 0o700)
	f, _ := os.Create(zp)
	zw := zip.NewWriter(f)
	zw.Create("ZIPPED_10.0.0.5/r001.txt")
	zw.Create("raiz.txt")
	zw.Create("../escape_10.0.0.6/r001.txt")
	zw.Close()
	f.Close()
	os.Chtimes(zp, d2, d2)
	// respaldos: SW2 (se junta por nombre con el de 10.0.0.2) y uno que solo tiene respaldos
	write(t, filepath.Join(out, "respaldos", "SW2", "20261105T080000Z-running.cfg"), "x", d2)
	write(t, filepath.Join(out, "respaldos", "SW2", "20261106T080000Z-running.cfg"), "x", d2)
	write(t, filepath.Join(out, "respaldos", "sw2", "20261101T080000Z-startup.cfg"), "x", d2) // otro caso de mayúsculas
	write(t, filepath.Join(out, "respaldos", "SOLO-RESP", "20261103T080000Z-startup.cfg"), "x", d2)
	write(t, filepath.Join(out, "respaldos", "SOLO-RESP", "notas.txt"), "no es un respaldo", d3)
	write(t, filepath.Join(out, "diag", "ping.txt"), "una carpeta que no es de trabajo", d3)

	r, err := Collect(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Devices) != 5 {
		t.Fatalf("%d equipos: %+v", len(r.Devices), r.Devices)
	}
	sw1 := find(r, "10.0.0.1")
	if sw1 == nil || sw1.Hostname != "SW1" || sw1.Platform != "ios-xe" || !sw1.LastSeen.Equal(d3) || strings.Join(sw1.Sources, ",") != "patrol,flota" {
		t.Fatalf("SW1 = %+v", sw1)
	}
	sw2 := find(r, "10.0.0.2")
	if sw2 == nil || strings.Join(sw2.Sources, ",") != "patrol,flota,respaldos" || !sw2.LastSeen.Equal(time.Date(2026, 11, 6, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("SW2 = %+v", sw2)
	}
	if caido := find(r, "10.0.0.9"); caido == nil || strings.Join(caido.Sources, ",") != "patrol" || !caido.LastSeen.IsZero() {
		t.Fatalf("un equipo que falló se conoce pero nunca se vio: %+v", caido)
	}
	if z := find(r, "10.0.0.5"); z == nil || z.Hostname != "ZIPPED" || strings.Join(z.Sources, ",") != "flota" || !z.LastSeen.Equal(d2) {
		t.Fatalf("zip = %+v", z)
	}
	if find(r, "10.0.0.6") != nil {
		t.Fatal("una entrada de zip con ruta fuera no es un equipo")
	}
	solo := find(r, "")
	if solo == nil || solo.Hostname != "SOLO-RESP" || strings.Join(solo.Sources, ",") != "respaldos" || !solo.LastSeen.Equal(time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("solo respaldos = %+v (todos: %+v)", solo, r.Devices)
	}
	// orden: por dirección y los sin dirección al final
	var addrs []string
	for _, d := range r.Devices {
		addrs = append(addrs, d.Address)
	}
	if strings.Join(addrs, ",") != "10.0.0.1,10.0.0.2,10.0.0.5,10.0.0.9," {
		t.Fatalf("orden = %q", addrs)
	}
}

func TestCollectOrdenNumericoYDireccionesRaras(t *testing.T) {
	out := t.TempDir()
	write(t, filepath.Join(out, "j", "manifest.json"), manifest(d1.Format(time.RFC3339), "A|10.0.0.10|ios-xe|completed", "B|10.0.0.9|ios-xe|completed", "C|r1.example.net|ios-xe|completed", "D|2001:db8::1|ios-xe|completed"), d1)
	r, err := Collect(out)
	if err != nil {
		t.Fatal(err)
	}
	var addrs []string
	for _, d := range r.Devices {
		addrs = append(addrs, d.Address)
	}
	if strings.Join(addrs, ",") != "10.0.0.9,10.0.0.10,2001:db8::1,r1.example.net" {
		t.Fatalf("orden = %q", addrs)
	}
}

func TestCollectNoSigueEnlacesNiExplotaConBasura(t *testing.T) {
	out := t.TempDir()
	write(t, filepath.Join(out, "j", "manifest.json"), "{no es json", d1)
	write(t, filepath.Join(out, "k", "manifest.json"), manifest(d1.Format(time.RFC3339), "A\\nB|10.0.0.1|ios-xe|completed", "|10.0.0.2||completed", "evil\u202egnp|10.0.0.3||completed"), d1)
	secret := t.TempDir()
	write(t, filepath.Join(secret, "SECRETO_10.9.9.9", "x.txt"), "x", d1)
	os.Symlink(secret, filepath.Join(out, "enlace"))
	r, err := Collect(out)
	if err != nil {
		t.Fatal(err)
	}
	if find(r, "10.9.9.9") != nil {
		t.Fatal("siguió un enlace simbólico fuera de outputs")
	}
	if a := find(r, "10.0.0.1"); a == nil || a.Hostname != "A?B" {
		t.Fatalf("nombre con salto de línea sin sanear: %+v", a)
	}
	if e := find(r, "10.0.0.3"); e == nil || strings.ContainsRune(e.Hostname, '\u202e') {
		t.Fatalf("nombre con carácter de formato: %+v", e)
	}
	if len(r.Warnings) == 0 || !strings.Contains(strings.Join(r.Warnings, "|"), "manifest.json") {
		t.Fatalf("un manifiesto ilegible se avisa: %v", r.Warnings)
	}
}

func TestCollectSinCarpetaYTope(t *testing.T) {
	if _, err := Collect(filepath.Join(t.TempDir(), "no-existe")); err == nil {
		t.Fatal("outputs inexistente es un error")
	}
	out := t.TempDir()
	var devs []string
	for i := 0; i < 30; i++ {
		devs = append(devs, "H|10.1.0."+string(rune('0'+i%10))+"|ios-xe|completed")
	}
	write(t, filepath.Join(out, "j", "manifest.json"), manifest(d1.Format(time.RFC3339), devs...), d1)
	old := MaxDevices
	MaxDevices = 5
	defer func() { MaxDevices = old }()
	r, _ := Collect(out)
	if len(r.Devices) > 5 {
		t.Fatalf("%d equipos con tope 5", len(r.Devices))
	}
}

func TestFilter(t *testing.T) {
	ds := []Device{{Address: "10.0.0.1", Hostname: "SW-CORE", Platform: "ios-xe"}, {Address: "10.0.0.2", Hostname: "ap1", Platform: "wlc"}}
	if got := Filter(ds, "core"); len(got) != 1 || got[0].Address != "10.0.0.1" {
		t.Fatalf("por nombre: %+v", got)
	}
	if got := Filter(ds, "10.0.0.2"); len(got) != 1 || got[0].Hostname != "ap1" {
		t.Fatalf("por dirección: %+v", got)
	}
	if got := Filter(ds, " "); len(got) != 2 {
		t.Fatalf("sin filtro: %+v", got)
	}
}

func TestCollectNombreMasNuevoYSinNombreFalso(t *testing.T) {
	out := t.TempDir()
	// el trabajo viejo se lee primero y el nuevo lo renombra: gana el nombre más reciente
	write(t, filepath.Join(out, "b_nuevo", "manifest.json"), manifest(d3.Format(time.RFC3339), "NUEVO|10.0.0.4|ios-xe|completed", "10.0.0.7|10.0.0.7|ios-xe|completed"), d3)
	write(t, filepath.Join(out, "a_viejo", "manifest.json"), manifest(d1.Format(time.RFC3339), "VIEJO|10.0.0.4|ios-xe|completed"), d1)
	// Patrol nombra la carpeta con la IP cuando no sabe el nombre; eso no es un nombre
	write(t, filepath.Join(out, "c_otro", "REAL_10.0.0.7", "r.txt"), "x", d1)
	r, _ := Collect(out)
	if d := find(r, "10.0.0.4"); d == nil || d.Hostname != "NUEVO" {
		t.Fatalf("nombre = %+v", d)
	}
	if d := find(r, "10.0.0.7"); d == nil || d.Hostname != "REAL" {
		t.Fatalf("la IP no es un nombre: %+v", d)
	}
}

func TestCollectRespaldoQueEsEnlaceNoCuenta(t *testing.T) {
	out := t.TempDir()
	os.MkdirAll(filepath.Join(out, "respaldos", "LINKED"), 0o700)
	real := filepath.Join(t.TempDir(), "x.cfg")
	os.WriteFile(real, []byte("x"), 0o600)
	os.Symlink(real, filepath.Join(out, "respaldos", "LINKED", "20261105T080000Z-running.cfg"))
	r, _ := Collect(out)
	if len(r.Devices) != 0 {
		t.Fatalf("= %+v", r.Devices)
	}
}

func TestCollectEquipoIPv6ConCarpetaDePatrol(t *testing.T) {
	out := t.TempDir()
	job := filepath.Join(out, "j1_20261106-090000")
	// Patrol cambia los «:» por «_»: la carpeta sola no dice cuál es la dirección
	write(t, filepath.Join(job, "manifest.json"), manifest(d1.Format(time.RFC3339), "SW6|2001:db8::1|ios-xe|failed"), d1)
	write(t, filepath.Join(job, "SW6_2001_db8__1", "r001_x.txt"), "===== x =====\n", d3)
	r, err := Collect(out)
	if err != nil {
		t.Fatal(err)
	}
	d := find(r, "2001:db8::1")
	if d == nil || len(r.Devices) != 1 || d.Hostname != "SW6" || strings.Join(d.Sources, ",") != "patrol,flota" || !d.LastSeen.Equal(d3) {
		t.Fatalf("= %+v", r.Devices)
	}
}

func TestCollectCarpetasExtra(t *testing.T) {
	out, extra := t.TempDir(), t.TempDir()
	dd := filepath.Join(extra, "ronda_1", "SW2_10.0.0.2")
	os.MkdirAll(dd, 0o700)
	os.WriteFile(filepath.Join(dd, "r001.txt"), []byte("x"), 0o600)
	res, err := Collect(out, extra, filepath.Join(extra, "no-existe"))
	// una carpeta extra que ya no existe (lote de respaldo borrado) no deja aviso: crecerían sin fin
	if err != nil || len(res.Devices) != 1 || res.Devices[0].Address != "10.0.0.2" || len(res.Warnings) != 0 {
		t.Fatalf("res = %+v err = %v", res, err)
	}
	// outputs/ ausente pero una extra legible: no es error
	if res, err = Collect(filepath.Join(out, "no"), extra); err != nil || len(res.Devices) != 1 {
		t.Fatalf("res = %+v err = %v", res, err)
	}
	if _, err = Collect(filepath.Join(out, "no"), filepath.Join(out, "tampoco")); err == nil {
		t.Fatal("sin ninguna carpeta legible debe fallar")
	}
}

// Los respaldos viven en respaldos/<equipo>_<IP>/ (como las carpetas de Patrol): se juntan por dirección con
// el equipo ya visto, y uno que solo tiene respaldos lleva su dirección (QA en vivo, segunda pasada).
func TestCollectRespaldosConDireccion(t *testing.T) {
	out := t.TempDir()
	write(t, filepath.Join(out, "j1_20261104-100000", "manifest.json"), manifest(d1.Format(time.RFC3339), "OOM-3560-SW|192.168.3.2|ios|completed"), d1)
	write(t, filepath.Join(out, "j1_20261104-100000", "OOM-3560-SW_192.168.3.2", "r001_x.txt"), "===== x =====\n", d1)
	write(t, filepath.Join(out, "respaldos", "OOM-3560-SW_192.168.3.2", "20261106T080000Z-startup.cfg"), "x", d2)
	write(t, filepath.Join(out, "respaldos", "RTR9_10.9.9.9", "20261105T080000Z-running.cfg"), "x", d2)
	write(t, filepath.Join(out, "respaldos", "SW_A_10.0.0.5", "20261105T080000Z-running.cfg"), "x", d2) // «_» en el nombre: se corta en el último
	r, err := Collect(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Devices) != 3 {
		t.Fatalf("equipos = %+v", r.Devices)
	}
	if a := find(r, "10.0.0.5"); a == nil || a.Hostname != "SW_A" {
		t.Fatalf("SW_A = %+v", a)
	}
	if sw := find(r, "192.168.3.2"); sw == nil || sw.Hostname != "OOM-3560-SW" || !strings.Contains(strings.Join(sw.Sources, ","), "respaldos") {
		t.Fatalf("3560 = %+v", sw)
	}
	if rt := find(r, "10.9.9.9"); rt == nil || rt.Hostname != "RTR9" || strings.Join(rt.Sources, ",") != "respaldos" {
		t.Fatalf("solo respaldos = %+v", rt)
	}
}
