package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func at(h int) time.Time { return time.Date(2026, 11, 6, h, 0, 0, 0, time.UTC) }

func mustSave(t *testing.T, s Store, dev string, k Kind, h int, text string) Entry {
	t.Helper()
	e, _, err := s.Save(Entry{Device: dev, Kind: k, At: at(h), Masked: true}, text)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestGuardaConPermisos0600(t *testing.T) {
	root := filepath.Join(t.TempDir(), "respaldos")
	s := Store{Root: root}
	e := mustSave(t, s, "SW1_192.0.2.1", Running, 10, "hostname SW1\n")
	if e.ID != "SW1_192.0.2.1/20261106T100000Z-running" || e.Bytes != 13 || e.SHA256 == "" {
		t.Fatalf("entrada = %+v", e)
	}
	for _, p := range []string{e.Path(root), strings.TrimSuffix(e.Path(root), ".cfg") + ".json"} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", p, fi, err)
		}
	}
	for _, d := range []string{root, filepath.Join(root, "SW1_192.0.2.1")} {
		if fi, _ := os.Stat(d); fi.Mode().Perm() != 0o700 {
			t.Errorf("%s = %v", d, fi.Mode().Perm())
		}
	}
}

func TestGuardarDosVecesNoDuplicaNiPisa(t *testing.T) {
	s := Store{Root: t.TempDir()}
	a := mustSave(t, s, "SW1", Running, 10, "uno\n")
	_, created, err := s.Save(Entry{Device: "SW1", Kind: Running, At: at(10)}, "dos\n")
	if err != nil || created {
		t.Fatalf("created=%v err=%v", created, err)
	}
	_, text, err := s.Get(a.ID)
	if err != nil || text != "uno\n" {
		t.Fatalf("text=%q err=%v", text, err)
	}
}

func TestListaYGetDevuelvenLoGuardadoMasNuevoPrimero(t *testing.T) {
	s := Store{Root: t.TempDir()}
	mustSave(t, s, "SW1", Running, 10, "a\n")
	mustSave(t, s, "SW1", Startup, 10, "s\n")
	mustSave(t, s, "SW1", Running, 11, "b\n")
	mustSave(t, s, "SW2", Running, 9, "c\n")
	l, err := s.List("SW1")
	if err != nil || len(l) != 3 || l[0].At != at(11) || !l[0].Masked || l[0].Job != "" {
		t.Fatalf("lista = %+v %v", l, err)
	}
	if all, _ := s.List(""); len(all) != 4 || all[len(all)-1].Device != "SW1" && all[0].Device != "SW1" {
		t.Fatalf("todos = %+v", all)
	}
	if l, err := s.List("nadie"); err != nil || len(l) != 0 {
		t.Fatalf("equipo sin respaldos: %v %v", l, err)
	}
}

func TestSinSidecarSeTrataComoEnmascarado(t *testing.T) {
	s := Store{Root: t.TempDir()}
	e := mustSave(t, s, "SW1", Running, 10, "a\n")
	os.Remove(strings.TrimSuffix(e.Path(s.Root), ".cfg") + ".json")
	l, _ := s.List("SW1")
	if len(l) != 1 || !l[0].Masked {
		t.Fatalf("%+v", l)
	}
}

func TestNombreDeEquipoNoSaleDeLaCarpeta(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "respaldos")
	s := Store{Root: root}
	for _, dev := range []string{"..", "../../fuera", "a/b", `a\b`, ".oculto", ""} {
		if _, err := Name(dev); err == nil {
			t.Errorf("Name(%q) aceptado", dev)
		}
		if _, err := s.Prune(dev, 1); err == nil {
			t.Errorf("Prune(%q) aceptado", dev)
		}
		if _, _, err := s.Get(dev + "/20261106T100000Z-running"); err == nil {
			t.Errorf("Get(%q) aceptado", dev)
		}
	}
	// Al guardar, el nombre se sanea: nada queda fuera de la raíz.
	e, _, err := s.Save(Entry{Device: "../../fuera", Kind: Running, At: at(10)}, "x\n")
	if err != nil {
		t.Fatal(err)
	}
	if rel, err := filepath.Rel(root, e.Path(root)); err != nil || strings.HasPrefix(rel, "..") || strings.Count(rel, string(filepath.Separator)) != 1 {
		t.Fatalf("archivo en %s (rel %q)", e.Path(root), rel)
	}
	ents, _ := os.ReadDir(base)
	if len(ents) != 1 {
		t.Errorf("algo se escribió junto a la raíz: %v", ents)
	}
}

func TestRetencionConservaLosMasNuevosPorTipo(t *testing.T) {
	s := Store{Root: t.TempDir()}
	for h := 1; h <= 5; h++ {
		mustSave(t, s, "SW1", Running, h, "r\n")
	}
	mustSave(t, s, "SW1", Startup, 1, "s\n")
	mustSave(t, s, "SW2", Running, 1, "otro\n")
	n, err := s.Prune("SW1", 2)
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	l, _ := s.List("SW1")
	if len(l) != 3 || l[0].At != at(5) || l[1].At != at(4) || l[2].Kind != Startup {
		t.Fatalf("quedó %+v", l)
	}
	if l, _ := s.List("SW2"); len(l) != 1 {
		t.Fatalf("SW2 tocado: %+v", l)
	}
	for _, p := range []string{"SW1/20261106T010000Z-running.cfg", "SW1/20261106T010000Z-running.json"} {
		if _, err := os.Stat(filepath.Join(s.Root, p)); err == nil {
			t.Errorf("%s sigue", p)
		}
	}
	if _, err := s.Prune("SW1", 0); err == nil {
		t.Error("keep 0 borraría todo")
	}
}

// La carpeta del equipo es un enlace a otra carpeta: ni se borra ni se escribe a través de él.
func TestRetencionNoBorraPorUnEnlaceSimbolicoDeCarpeta(t *testing.T) {
	base := t.TempDir()
	fuera := filepath.Join(base, "fuera")
	os.MkdirAll(fuera, 0o755)
	var victimas []string
	for _, n := range []string{"20260101T000000Z-running.cfg", "20260102T000000Z-running.cfg", "20260103T000000Z-running.json", "otra-cosa.txt"} {
		p := filepath.Join(fuera, n)
		os.WriteFile(p, []byte("importante"), 0o644)
		victimas = append(victimas, p)
	}
	root := filepath.Join(base, "respaldos")
	os.MkdirAll(root, 0o700)
	if err := os.Symlink(fuera, filepath.Join(root, "SW1")); err != nil {
		t.Fatal(err)
	}
	s := Store{Root: root}
	if _, err := s.Prune("SW1", 1); err == nil {
		t.Error("Prune por un enlace aceptado")
	}
	if _, _, err := s.Save(Entry{Device: "SW1", Kind: Running, At: at(10)}, "x\n"); err == nil {
		t.Error("Save por un enlace aceptado")
	}
	if _, err := s.List("SW1"); err == nil {
		t.Error("List por un enlace aceptado")
	}
	for _, p := range victimas {
		if b, err := os.ReadFile(p); err != nil || string(b) != "importante" {
			t.Errorf("%s: %q %v", p, b, err)
		}
	}
	if ents, _ := os.ReadDir(fuera); len(ents) != len(victimas) {
		t.Errorf("se escribió fuera: %v", ents)
	}
}

// Un archivo con nombre de respaldo que en realidad es un enlace no cuenta ni se sigue.
func TestRetencionIgnoraEnlacesDentroDeLaCarpeta(t *testing.T) {
	base := t.TempDir()
	s := Store{Root: filepath.Join(base, "r")}
	mustSave(t, s, "SW1", Running, 1, "a\n")
	mustSave(t, s, "SW1", Running, 2, "b\n")
	victima := filepath.Join(base, "secreto.txt")
	os.WriteFile(victima, []byte("importante"), 0o644)
	os.Symlink(victima, filepath.Join(s.Root, "SW1", "20260101T000000Z-running.cfg"))
	if n, err := s.Prune("SW1", 1); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if b, err := os.ReadFile(victima); err != nil || string(b) != "importante" {
		t.Fatalf("%q %v", b, err)
	}
	if _, _, err := s.Get("SW1/20260101T000000Z-running"); err == nil {
		t.Error("Get siguió un enlace")
	}
}

func TestIDInvalido(t *testing.T) {
	s := Store{Root: t.TempDir()}
	for _, id := range []string{"", "SW1", "SW1/x", "SW1/20261106T100000Z-otro", "SW1/20261106T100000Z-running/../x", "SW1/20261106T100000Z-running.cfg"} {
		if _, _, err := s.Get(id); err == nil {
			t.Errorf("Get(%q) aceptado", id)
		}
	}
}

// Una ficha .json preparada como enlace no desvía la escritura hacia otro archivo.
func TestGuardarNoEscribeATravesDeUnEnlaceDeFicha(t *testing.T) {
	base := t.TempDir()
	s := Store{Root: filepath.Join(base, "r")}
	os.MkdirAll(filepath.Join(s.Root, "SW1"), 0o700)
	victima := filepath.Join(base, "secreto.txt")
	os.WriteFile(victima, []byte("importante"), 0o644)
	os.Symlink(victima, filepath.Join(s.Root, "SW1", "20261106T100000Z-running.json"))
	if _, _, err := s.Save(Entry{Device: "SW1", Kind: Running, At: at(10)}, "x\n"); err == nil {
		t.Error("Save escribió por el enlace")
	}
	if b, _ := os.ReadFile(victima); string(b) != "importante" {
		t.Fatalf("victima = %q", b)
	}
}

// Ficha firmada (fase 16c): restaurar solo confía en una ficha con firma válida de la llave de la bóveda.
func TestFichaFirmadaGuardaSerieYRecorte(t *testing.T) {
	key := []byte("llave-de-prueba-de-32-bytes-xxxx")
	s := Store{Root: t.TempDir(), Key: key}
	e, _, err := s.Save(Entry{Device: "SW1", Kind: Running, At: at(10), Serial: "FOC0001A0AA", Truncated: true}, "hostname SW1\nend\n")
	if err != nil || e.Sig == "" {
		t.Fatalf("e=%+v err=%v", e, err)
	}
	got, _, err := s.Get(e.ID)
	if err != nil || got.Serial != "FOC0001A0AA" || !got.Truncated || got.Sig != e.Sig || !got.Verify(key) {
		t.Fatalf("la ficha debe volver igual y con firma válida: %+v err=%v", got, err)
	}
	if got.Verify([]byte("otra-llave-de-32-bytes-xxxxxxxxx")) {
		t.Error("otra llave no verifica")
	}
	if got.Verify(nil) {
		t.Error("sin llave no se verifica nada")
	}
}

func TestFichaSinFirmaOAlteradaNoVerifica(t *testing.T) {
	key := []byte("llave-de-prueba-de-32-bytes-xxxx")
	root := t.TempDir()
	unsigned, _, _ := Store{Root: root}.Save(Entry{Device: "SW1", Kind: Running, At: at(9), Serial: "S1"}, "a\nend\n")
	if got, _, _ := (Store{Root: root}).Get(unsigned.ID); got.Sig != "" || got.Verify(key) {
		t.Errorf("un respaldo guardado sin llave no tiene firma: %+v", got)
	}
	s := Store{Root: root, Key: key}
	e, _, _ := s.Save(Entry{Device: "SW1", Kind: Running, At: at(10), Serial: "S1", Masked: true}, "b\nend\n")
	meta := strings.TrimSuffix(e.Path(root), ".cfg") + ".json"
	// Cada campo de la ficha está firmado: cambiar el enmascarado, la serie, el recorte o el hash invalida la firma.
	for name, edit := range map[string][2]string{
		"enmascarado": {`"masked":true`, `"masked":false`},
		"serie":       {`"serial":"S1"`, `"serial":"S2"`},
		"sha256":      {e.SHA256[:8], "00000000"},
	} {
		orig, _ := os.ReadFile(meta)
		if !strings.Contains(string(orig), edit[0]) {
			t.Fatalf("%s: la ficha no contiene %s: %s", name, edit[0], orig)
		}
		os.WriteFile(meta, []byte(strings.Replace(string(orig), edit[0], edit[1], 1)), 0o600)
		got, _, err := s.Get(e.ID)
		if err != nil || got.Verify(key) {
			t.Errorf("%s: una ficha alterada no debe verificar (err=%v)", name, err)
		}
		os.WriteFile(meta, orig, 0o600)
	}
	if got, _, _ := s.Get(e.ID); !got.Verify(key) {
		t.Error("la ficha original sí verifica")
	}
}
