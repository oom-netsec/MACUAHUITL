package ingest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testMsg es un evento mínimo con las tres formas de línea del archivo.
type testMsg struct {
	Time     time.Time
	From     string
	Raw      string
	Mnemonic string `json:",omitempty"`
}

func (m testMsg) Origin() string { return m.From }
func (m testMsg) Line(format string) []byte {
	switch format {
	case "crudo":
		return []byte(m.Raw + "\n")
	case "jsonl":
		b, _ := json.Marshal(m)
		return append(b, '\n')
	}
	return []byte(m.Time.Format(time.RFC3339) + " " + m.From + " " + m.Raw + "\n")
}

func msg(from, raw string) testMsg {
	return testMsg{Time: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC), From: from, Raw: raw}
}

func newSink(t *testing.T, r *reloj, edit func(*Sink)) (*Writer, *[]string, *[]string) {
	t.Helper()
	var abiertos, borrados []string
	s := Sink{Dir: filepath.Join(t.TempDir(), "syslog"), Template: "syslog_{fecha}_{hora}", MaxFiles: 100,
		OnOpen: func(p string) { abiertos = append(abiertos, p) }, OnRemove: func(p string) { borrados = append(borrados, p) }}
	if edit != nil {
		edit(&s)
	}
	w, err := NewWriter(s, r.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	return w, &abiertos, &borrados
}

func ls(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func TestValidateTemplate(t *testing.T) {
	bad := []string{"", "../x", "a/b", `a\b{fecha}`, "{fecha", "{otro}{fecha}", "solo_texto", "x{fecha}}", "a..b{fecha}", "sp ace{fecha}", "ñ{fecha}", strings.Repeat("a", 65) + "{fecha}", "{fe{hora}cha}", "{origen}"}
	for _, s := range bad {
		if ValidateTemplate(s) == nil {
			t.Errorf("%q debía rechazarse", s)
		}
	}
	good := []string{"syslog_{fecha}_{hora}", "{fecha}", "{hora}", "lab-{origen}.{fecha}", ".{fecha}.", strings.Repeat("a", 64-7) + "{fecha}"}
	for _, s := range good {
		if err := ValidateTemplate(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
}

func TestSinkValidate(t *testing.T) {
	ok := Sink{Dir: "/x", Template: "s_{fecha}", MaxFiles: 20}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*Sink){
		"dir":       func(s *Sink) { s.Dir = "" },
		"mb bajo":   func(s *Sink) { s.RotateBytes = 1 },
		"mb alto":   func(s *Sink) { s.RotateBytes = 1025 << 20 },
		"mb neg":    func(s *Sink) { s.RotateBytes = -1 },
		"min bajo":  func(s *Sink) { s.RotateEvery = 30 * time.Second },
		"min alto":  func(s *Sink) { s.RotateEvery = 8 * 24 * time.Hour },
		"archivos0": func(s *Sink) { s.MaxFiles = 0 },
		"archivos+": func(s *Sink) { s.MaxFiles = 1001 },
		"formato":   func(s *Sink) { s.Format = "xml" },
		"plantilla": func(s *Sink) { s.Template = "../x" },
	} {
		s := ok
		edit(&s)
		if s.Validate() == nil {
			t.Errorf("%s: debía rechazarse", name)
		}
	}
	for _, edit := range []func(*Sink){
		func(s *Sink) { s.RotateBytes = 1 << 20 }, func(s *Sink) { s.RotateBytes = 1024 << 20 },
		func(s *Sink) { s.RotateEvery = time.Minute }, func(s *Sink) { s.RotateEvery = 7 * 24 * time.Hour },
		func(s *Sink) { s.Format = "jsonl" }, func(s *Sink) { s.MaxFiles = 1000 },
	} {
		s := ok
		edit(&s)
		if err := s.Validate(); err != nil {
			t.Errorf("%+v: %v", s, err)
		}
	}
}

func TestFileNameAndPermissions(t *testing.T) {
	r := newReloj()
	w, abiertos, _ := newSink(t, r, nil)
	w.Write(msg("192.0.2.1:1", "a"))
	if len(*abiertos) != 1 || filepath.Base((*abiertos)[0]) != "syslog_20261107_120000.log" {
		t.Fatalf("abiertos = %v", *abiertos)
	}
	st, _ := os.Stat((*abiertos)[0])
	ds, _ := os.Stat(w.s.Dir)
	if st.Mode().Perm() != 0o600 || ds.Mode().Perm() != 0o700 {
		t.Errorf("permisos archivo %v carpeta %v", st.Mode().Perm(), ds.Mode().Perm())
	}
	// el mismo segundo y el mismo nombre: se agrega _N, sin pisar
	w.s.RotateBytes = 1
	w.Write(msg("192.0.2.1:1", "bb"))
	w.Write(msg("192.0.2.1:1", "cc"))
	got := ls(t, w.s.Dir)
	if strings.Join(got, ",") != "syslog_20261107_120000.log,syslog_20261107_120000_1.log,syslog_20261107_120000_2.log" {
		t.Fatalf("archivos = %v", got)
	}
}

func TestRotateBySize(t *testing.T) {
	r := newReloj()
	w, abiertos, _ := newSink(t, r, func(s *Sink) { s.Format = "crudo"; s.RotateBytes = 100 }) // Validate pide ≥1 MB; aquí se prueba con 100 B
	line := strings.Repeat("x", 49)                                                            // 50 con el salto
	for range 5 {
		r.Add(time.Second)
		w.Write(msg("192.0.2.1:1", line))
	}
	// 2 por archivo (justo 100 B, que aún cabe); la tercera pasaría de 100
	if len(*abiertos) != 3 {
		t.Fatalf("archivos abiertos = %d (%v)", len(*abiertos), *abiertos)
	}
	for i, want := range []int{100, 100, 50} {
		if b, _ := os.ReadFile((*abiertos)[i]); len(b) != want {
			t.Errorf("archivo %d: %d bytes, quería %d", i, len(b), want)
		}
	}
	// sin RotateBytes no se rota por tamaño
	w2, ab2, _ := newSink(t, newReloj(), func(s *Sink) { s.Format = "crudo" })
	for range 50 {
		w2.Write(msg("192.0.2.1:1", line))
	}
	if len(*ab2) != 1 {
		t.Fatalf("rotó sin pedirlo: %v", *ab2)
	}
}

func TestRotateByTime(t *testing.T) {
	r := newReloj()
	w, abiertos, _ := newSink(t, r, func(s *Sink) { s.RotateEvery = time.Minute })
	w.Write(msg("192.0.2.1:1", "a"))
	r.Add(59 * time.Second)
	w.Write(msg("192.0.2.1:1", "b"))
	if len(*abiertos) != 1 {
		t.Fatalf("rotó antes de tiempo: %v", *abiertos)
	}
	r.Add(time.Second)
	w.Write(msg("192.0.2.1:1", "c"))
	if len(*abiertos) != 2 || filepath.Base((*abiertos)[1]) != "syslog_20261107_120100.log" {
		t.Fatalf("abiertos = %v", *abiertos)
	}
	r.Add(30 * time.Second)
	w.Write(msg("192.0.2.1:1", "d"))
	if len(*abiertos) != 2 {
		t.Fatalf("la cuenta debía reiniciarse al rotar: %v", *abiertos)
	}
}

func TestRetentionDeletesOnlyMatchingFiles(t *testing.T) {
	r := newReloj()
	w, _, borrados := newSink(t, r, func(s *Sink) { s.MaxFiles = 3; s.Template = "syslog_{fecha}_{hora}" })
	dir := w.s.Dir
	base := time.Now().Add(-48 * time.Hour)
	mk := func(name string, age int) {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("x"), 0o600)
		os.Chtimes(p, base.Add(time.Duration(age)*time.Hour), base.Add(time.Duration(age)*time.Hour))
	}
	mk("syslog_20260101_000000.log", 1) // más viejo
	mk("syslog_20260102_000000.log", 2)
	mk("syslog_20260103_000000_1.log", 3)
	mk("syslog_20260104_000000.log", 4)
	mk("syslog_20260104_000000.jsonl", 0) // otro formato: no encaja
	mk("notas.log", 0)                    // ajeno
	mk("syslog_2026_x.log", 0)            // ajeno: casi encaja
	os.Mkdir(filepath.Join(dir, "syslog_20260101_000001.log"), 0o700)
	w.Write(msg("192.0.2.1:1", "a")) // crea el archivo nuevo y aplica la retención
	got := ls(t, dir)
	want := "notas.log,syslog_20260101_000001.log,syslog_20260104_000000.jsonl,syslog_20260104_000000.log,syslog_20260103_000000_1.log,syslog_2026_x.log,syslog_20261107_120000.log"
	have := map[string]bool{}
	for _, n := range got {
		have[n] = true
	}
	for _, n := range strings.Split(want, ",") {
		if !have[n] {
			t.Errorf("falta %s (hay %v)", n, got)
		}
	}
	for _, n := range []string{"syslog_20260101_000000.log", "syslog_20260102_000000.log"} {
		if have[n] {
			t.Errorf("%s debía borrarse", n)
		}
	}
	if len(*borrados) != 2 {
		t.Fatalf("borrados = %v", *borrados)
	}
}

func TestRetentionNeverDeletesOpenFile(t *testing.T) {
	r := newReloj()
	w, _, borrados := newSink(t, r, func(s *Sink) { s.MaxFiles = 1; s.Template = "lab-{origen}-{fecha}" })
	w.Write(msg("192.0.2.1:1", "a"))
	// el segundo origen crea archivo; el primero sigue abierto y no se borra aunque sea el más viejo
	old := time.Now().Add(-time.Hour)
	for _, n := range ls(t, w.s.Dir) {
		os.Chtimes(filepath.Join(w.s.Dir, n), old, old)
	}
	w.Write(msg("192.0.2.2:1", "b"))
	if len(*borrados) != 0 || len(ls(t, w.s.Dir)) != 2 {
		t.Fatalf("borró un archivo abierto: %v %v", *borrados, ls(t, w.s.Dir))
	}
}

func TestPerOriginFilesAndOpenLimit(t *testing.T) {
	r := newReloj()
	w, abiertos, _ := newSink(t, r, func(s *Sink) { s.Template = "lab_{origen}_{fecha}"; s.Format = "crudo"; s.MaxFiles = 1000 })
	w.Write(msg("192.0.2.1:1", "uno"))
	w.Write(msg("[2001:db8::1]:514", "dos"))
	w.Write(msg("192.0.2.1:2", "tres"))
	got := ls(t, w.s.Dir)
	if strings.Join(got, ",") != "lab_192.0.2.1_20261107.log,lab_2001-db8--1_20261107.log" {
		t.Fatalf("archivos = %v", got)
	}
	if b, _ := os.ReadFile(filepath.Join(w.s.Dir, got[0])); string(b) != "uno\ntres\n" {
		t.Fatalf("contenido = %q", b)
	}
	// más de 64 orígenes: nunca más de 64 abiertos, y al volver se reabre en append
	for i := range 100 {
		w.Write(msg("10.9.0."+itoa(i)+":1", "x"))
	}
	if w.open > maxOpen {
		t.Fatalf("abiertos = %d", w.open)
	}
	if w.files["192.0.2.1"].f != nil || w.files["2001-db8--1"].f != nil {
		t.Fatal("debían cerrarse los menos usados")
	}
	if w.files["10.9.0.099"].f == nil {
		t.Fatal("el más reciente no debe cerrarse")
	}
	n := len(*abiertos)
	w.Write(msg("192.0.2.1:9", "cuatro")) // fue expulsado por el menos usado
	if len(*abiertos) != n {
		t.Fatalf("reabrir en append no es un archivo nuevo: %d -> %d", n, len(*abiertos))
	}
	if b, _ := os.ReadFile(filepath.Join(w.s.Dir, got[0])); string(b) != "uno\ntres\ncuatro\n" {
		t.Fatalf("contenido tras reabrir = %q", b)
	}
}

func TestOriginTokenIsSafeForFilenames(t *testing.T) {
	if got := fileOrigin("fe80::1%eth0/../x"); got != "fe80--1-eth0-..-x" {
		t.Fatalf("fileOrigin = %q", got)
	}
}

// Revisión: la retención borraba archivos que el LRU solo había cerrado y el origen no podía volver.
func TestOriginComesBackAfterRetentionDeletedItsClosedFile(t *testing.T) {
	r := newReloj()
	var borrados []string
	w, _, _ := newSink(t, r, func(s *Sink) {
		s.Template = "{origen}_{fecha}"
		s.MaxFiles = 20
		s.OnRemove = func(p string) { borrados = append(borrados, p) }
	})
	for i := 1; i <= 65; i++ {
		if err := w.Write(msg("10.0.0."+itoa(i)+":514", "x")); err != nil {
			t.Fatalf("origen %d: %v", i, err)
		}
	}
	if len(borrados) == 0 {
		t.Fatal("el escenario debía hacer que la retención borrara archivos")
	}
	for _, p := range borrados {
		for k, of := range w.files {
			if of.path == p {
				t.Errorf("la entrada %s sigue apuntando a un archivo borrado", k)
			}
		}
	}
	if err := w.Write(msg("10.0.0.001:514", "otra vez")); err != nil {
		t.Fatalf("el origen 1 no pudo volver: %v", err)
	}
	if w.open > maxOpen {
		t.Fatalf("abiertos = %d", w.open)
	}
}

func TestReopenCreatesNewFileIfClosedOneWasRemovedFromOutside(t *testing.T) {
	r := newReloj()
	w, abiertos, _ := newSink(t, r, func(s *Sink) { s.Template = "{origen}_{fecha}"; s.Format = "crudo" })
	w.Write(msg("10.0.0.1:1", "a"))
	for i := 2; i <= 66; i++ { // expulsa al origen 1
		w.Write(msg("10.0.0."+itoa(i)+":1", "x"))
	}
	if w.files["10.0.0.1"].f != nil {
		t.Fatal("el origen 1 debía estar cerrado")
	}
	if err := os.Remove((*abiertos)[0]); err != nil {
		t.Fatal(err)
	}
	n := len(*abiertos)
	if err := w.Write(msg("10.0.0.1:2", "b")); err != nil {
		t.Fatal(err)
	}
	if len(*abiertos) != n+1 {
		t.Fatalf("debía crearse un archivo nuevo: %d -> %d", n, len(*abiertos))
	}
}

func TestRetentionRegexOnlyMatchesItsOwnTemplate(t *testing.T) {
	dir := t.TempDir()
	r := newReloj()
	old := time.Now().Add(-time.Hour)
	mk := func(name string) {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("x"), 0o600)
		os.Chtimes(p, old, old)
	}
	mk("syslog_20261101_093000.log") // plantilla por defecto de otra sesión
	mk("backup_20261107.log")
	mk("foo-bar-20261107.log")
	mk("syslog_20261101_093000_1.log")
	mk("t_1234567.log") // 7 dígitos: ni {fecha} ni {hora}
	for _, tpl := range []string{"syslog_{fecha}", "{origen}_{fecha}", "{origen}-{fecha}", "t_{fecha}", "t_{hora}"} {
		w, err := NewWriter(Sink{Dir: dir, Template: tpl, MaxFiles: 1}, r.Now)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(msg("10.0.0.1:1", "x"))
		w.Close()
	}
	for _, n := range []string{"syslog_20261101_093000.log", "backup_20261107.log", "foo-bar-20261107.log", "syslog_20261101_093000_1.log", "t_1234567.log"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("la retención de otra plantilla borró %s", n)
		}
	}
}

func TestRetentionRegexMatchesEveryNameItCreates(t *testing.T) {
	r := newReloj()
	w, abiertos, _ := newSink(t, r, func(s *Sink) { s.Template = "{origen}_{fecha}_{hora}"; s.MaxFiles = 1000 })
	for _, from := range []string{"192.0.2.1:1", "[2001:db8::1]:1", "[::1]:1", "[::ffff:192.0.2.9]:1", "[fe80::1%eth0]:1"} {
		w.Write(msg(from, "x"))
	}
	w.s.RotateBytes = 1 // fuerza el sufijo _N
	w.Write(msg("192.0.2.1:1", "y"))
	w.Write(msg("192.0.2.1:1", "z"))
	if len(*abiertos) != 7 {
		t.Fatalf("abiertos = %v", *abiertos)
	}
	for _, p := range *abiertos {
		if !w.re.MatchString(filepath.Base(p)) {
			t.Errorf("la regex no reconoce %s", filepath.Base(p))
		}
	}
}
