package prefs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// montar arma el servicio sobre un núcleo de prueba con la carpeta de datos y la de configuración protegidas.
func montar(t *testing.T) (*prefsSvc, *servicetest.Deps, string) {
	t.Helper()
	d := servicetest.New(t)
	root := t.TempDir()
	d.S = service.NewCoreSettings(d.Out, root, filepath.Join(root, "n", "datos"), filepath.Join(root, "config"), filepath.Join(root, "run"))
	// Las pruebas viven bajo /tmp, que es de todos: los ancestros se dan por seguros salvo los que cada prueba marque.
	old := service.AncestorInfo
	service.AncestorInfo = func(string) (os.FileMode, uint32, error) { return 0o755, uint32(os.Getuid()), nil }
	t.Cleanup(func() { service.AncestorInfo = old })
	return &prefsSvc{d: d}, d, root
}

func carpeta(t *testing.T, ruta string, modo os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(ruta, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ruta, modo); err != nil {
		t.Fatal(err)
	}
	return ruta
}

func fija(s *prefsSvc, dir string) error {
	_, err := s.SetCorePrefs(context.Background(), &v1.SetCorePrefsRequest{Prefs: &v1.CorePrefs{OutputsDir: dir}})
	return err
}

func quiero(t *testing.T, err error, codigo string) {
	t.Helper()
	if status.Code(err) != codes.InvalidArgument || !strings.HasPrefix(status.Convert(err).Message(), "prefs.outputs."+codigo+":") {
		t.Fatalf("esperaba InvalidArgument prefs.outputs.%s, salió: %v", codigo, err)
	}
}

func TestOutputsReglasDeValidacion(t *testing.T) {
	s, d, root := montar(t)
	archivo := filepath.Join(root, "archivo")
	os.WriteFile(archivo, []byte("x"), 0o600)
	carpeta(t, filepath.Join(root, "n"), 0o700)
	datos := carpeta(t, filepath.Join(root, "n", "datos"), 0o700)
	carpeta(t, filepath.Join(datos, "sub"), 0o700)
	carpeta(t, filepath.Join(root, "config"), 0o700)
	laxa := carpeta(t, filepath.Join(root, "laxa"), 0o755)
	cases := []struct{ name, dir, code string }{
		{"relativa", "salidas", "relativa"},
		{"con punto punto", root + "/laxa/../x", "punto_punto"},
		{"inexistente", filepath.Join(root, "no-existe"), "no_existe"},
		{"un archivo", archivo, "no_directorio"},
		{"modo 0755", laxa, "permisos"},
		{"carpeta de datos", datos, "reservada"},
		{"dentro de la de datos", filepath.Join(datos, "sub"), "reservada"},
		{"carpeta de configuración", filepath.Join(root, "config"), "reservada"},
		{"contiene la carpeta del núcleo", filepath.Join(root, "n"), "reservada"},
		{"carpeta de ejecución", carpeta(t, filepath.Join(root, "run"), 0o700), "reservada"},
		{".ssh", carpeta(t, filepath.Join(root, ".ssh"), 0o700), "reservada"},
		{"dentro de .ssh", carpeta(t, filepath.Join(root, ".ssh", "x"), 0o700), "reservada"},
		{"HOME", root, "reservada"},
		{"un ancestro de HOME", filepath.Dir(root), "reservada"},
		{"raíz", "/", "reservada"},
		{"/tmp", "/tmp", "reservada"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			quiero(t, fija(s, c.dir), c.code)
			if got := d.Outputs(); got != d.Settings().Factory() {
				t.Fatalf("un rechazo no debe cambiar la carpeta vigente: %s", got)
			}
		})
	}
	if err := fija(s, laxa); !strings.Contains(err.Error(), "chmod 700 "+laxa) {
		t.Fatalf("el rechazo por permisos debe sugerir la orden: %v", err)
	}
}

func TestOutputsOtroDuenoSeRechaza(t *testing.T) {
	s, _, root := montar(t)
	ok := carpeta(t, filepath.Join(root, "ok"), 0o700)
	old := service.FileOwner
	service.FileOwner = func(os.FileInfo) (uint32, bool) { return uint32(os.Getuid()) + 1, true }
	defer func() { service.FileOwner = old }()
	quiero(t, fija(s, ok), "otro_dueno")
}

func TestOutputsNoEscribibleSeRechaza(t *testing.T) {
	s, _, root := montar(t)
	ok := carpeta(t, filepath.Join(root, "ok"), 0o700)
	old := service.CreateTemp
	service.CreateTemp = func(string, string) (*os.File, error) { return nil, errors.New("solo lectura") }
	defer func() { service.CreateTemp = old }()
	quiero(t, fija(s, ok), "no_escribible")
}

func TestOutputsAceptaYResuelveSymlinks(t *testing.T) {
	s, d, root := montar(t)
	real := carpeta(t, filepath.Join(root, "real"), 0o700)
	enlace := filepath.Join(root, "enlace")
	if err := os.Symlink(real, enlace); err != nil {
		t.Fatal(err)
	}
	if err := fija(s, real); err != nil {
		t.Fatal(err)
	}
	if d.Outputs() != real {
		t.Fatalf("vigente = %s", d.Outputs())
	}
	if err := fija(s, ""); err != nil || d.Outputs() != d.Settings().Factory() {
		t.Fatalf("vacío debe volver a la de fábrica: %v %s", err, d.Outputs())
	}
	if err := fija(s, enlace); err != nil {
		t.Fatal(err)
	}
	if d.Outputs() != real { // se guarda la ruta resuelta, no el enlace
		t.Fatalf("vigente = %s, quería %s", d.Outputs(), real)
	}
	// y no deja basura de la prueba de escritura
	if es, _ := os.ReadDir(real); len(es) != 0 {
		t.Fatalf("la prueba de escritura dejó %d archivos", len(es))
	}
}

func TestOutputsSymlinkAUnaCarpetaLaxaSeRechaza(t *testing.T) {
	s, _, root := montar(t)
	laxa := carpeta(t, filepath.Join(root, "laxa"), 0o755)
	enlace := filepath.Join(root, "enlace")
	os.Symlink(laxa, enlace)
	quiero(t, fija(s, enlace), "permisos")
}

func TestSetPreferenceNoEscribeClavesCore(t *testing.T) {
	s, d, _ := montar(t)
	// aunque alguien agregue una clave core.* a la lista cerrada, el camino genérico no la escribe
	prefKeys["core.outputs_dir"] = true
	defer delete(prefKeys, "core.outputs_dir")
	for _, k := range []string{"core.outputs_dir", "core.rotate_mb", "core."} {
		if _, err := s.SetPreference(context.Background(), &v1.SetPreferenceRequest{Key: k, Value: "/x"}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%s: %v", k, err)
		}
		if _, err := s.GetPreference(context.Background(), &v1.GetPreferenceRequest{Key: k}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("lectura de %s: %v", k, err)
		}
	}
	var n int
	d.DB().QueryRow(`SELECT count(*) FROM preferences WHERE key LIKE 'core.%'`).Scan(&n)
	if n != 0 {
		t.Fatal("quedó una clave core.*")
	}
}

func TestIngestDefaultsRangosInvalidos(t *testing.T) {
	s, d, _ := montar(t)
	for name, ing := range map[string]*v1.IngestDefaults{
		"rotate_mb alto": {RotateMb: 1025}, "rotate_mb negativo": {RotateMb: -1}, "minutos altos": {RotateMinutes: 10081},
		"max_files alto": {MaxFiles: 1001}, "formato": {Format: "xml"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.SetCorePrefs(context.Background(), &v1.SetCorePrefsRequest{Prefs: &v1.CorePrefs{IngestDefaults: ing}})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("%v", err)
			}
			if d.Settings().Ingest() != (service.IngestDefaults{}) {
				t.Fatal("un rechazo no debe cambiar los defaults")
			}
		})
	}
}

func TestSetCorePrefsPersisteAuditaYAvisa(t *testing.T) {
	s, d, root := montar(t)
	nueva := carpeta(t, filepath.Join(root, "nueva"), 0o700)
	r, err := s.SetCorePrefs(context.Background(), &v1.SetCorePrefsRequest{Prefs: &v1.CorePrefs{OutputsDir: nueva,
		IngestDefaults: &v1.IngestDefaults{RotateMb: 10, RotateMinutes: 30, MaxFiles: 5, Format: "jsonl"}}})
	if err != nil {
		t.Fatal(err)
	}
	st := r.State
	if st.Prefs.OutputsDir != nueva || st.OutputsDirEffective != nueva || st.OutputsDirDefault != d.Settings().Factory() || st.Note == "" {
		t.Fatalf("estado = %+v", st)
	}
	g, err := s.GetCorePrefs(context.Background(), &v1.GetCorePrefsRequest{})
	if err != nil || g.State.Prefs.IngestDefaults.GetFormat() != "jsonl" || g.State.Prefs.IngestDefaults.GetMaxFiles() != 5 || g.State.Note != "" {
		t.Fatalf("get = %+v %v", g, err)
	}
	// persistencia: otro CoreSettings sobre la misma base ve lo guardado
	otro := service.NewCoreSettings("fabrica", root)
	if err := otro.Load(d.DB(), nil); err != nil {
		t.Fatal(err)
	}
	if otro.Outputs() != nueva || otro.Ingest() != (service.IngestDefaults{RotateMB: 10, RotateMinutes: 30, MaxFiles: 5, Format: "jsonl"}) {
		t.Fatalf("recargado = %s %+v", otro.Outputs(), otro.Ingest())
	}
	log := strings.ReplaceAll(d.AuditText(), `\u003e`, ">")
	for _, quiero := range []string{`"prefs.core"`, "outputs_dir: " + d.Settings().Factory() + " -> " + nueva, "rotate_mb: 0 -> 10", "format:  -> jsonl"} {
		if !strings.Contains(log, quiero) {
			t.Fatalf("auditoría sin %q:\n%s", quiero, log)
		}
	}
	// sin cambios no hay entrada nueva ni aviso
	antes := strings.Count(d.AuditText(), `"prefs.core"`)
	r2, err := s.SetCorePrefs(context.Background(), &v1.SetCorePrefsRequest{Prefs: g.State.Prefs})
	if err != nil || r2.State.Note != "" || strings.Count(d.AuditText(), `"prefs.core"`) != antes {
		t.Fatalf("sin cambios: %v %+v", err, r2)
	}
	// volver a fábrica borra las claves
	if _, err := s.SetCorePrefs(context.Background(), &v1.SetCorePrefsRequest{Prefs: &v1.CorePrefs{}}); err != nil {
		t.Fatal(err)
	}
	var n int
	d.DB().QueryRow(`SELECT count(*) FROM preferences WHERE key LIKE 'core.%'`).Scan(&n)
	if n != 0 {
		t.Fatalf("quedaron %d claves", n)
	}
}

// Un ancestro que otros pueden escribir deja que alguien reemplace la ruta (o la cree 0777 tras una limpieza de tmpfiles).
func TestOutputsAncestroEscribiblePorOtrosSeRechaza(t *testing.T) {
	yo := uint32(os.Getuid())
	cases := []struct {
		name string
		mode os.FileMode
		uid  uint32
		ok   bool
	}{
		{"0777 de otro usuario", 0o777, yo + 1, false},
		{"0777 de root sin sticky", 0o777, 0, false},
		{"/tmp: 1777 de root", 0o777 | os.ModeSticky, 0, false},
		{"grupo escribible de otro", 0o775, yo + 1, false},
		{"grupo escribible de root", 0o775, 0, false},
		{"grupo escribible mío (umask 002)", 0o775, yo, true},
		{"0755 de root", 0o755, 0, true},
		{"0755 de otro", 0o755, yo + 1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, d, root := montar(t)
			dir := carpeta(t, filepath.Join(root, "a", "b", "salidas"), 0o700)
			malo := filepath.Join(root, "a")
			service.AncestorInfo = func(p string) (os.FileMode, uint32, error) {
				if p == malo {
					return c.mode, c.uid, nil
				}
				return 0o755, 0, nil
			}
			err := fija(s, dir)
			if c.ok {
				if err != nil || d.Outputs() != dir {
					t.Fatalf("debía aceptarse: %v", err)
				}
				return
			}
			quiero(t, err, "ancestro_inseguro")
			if !strings.Contains(err.Error(), malo) {
				t.Errorf("el mensaje debe nombrar el ancestro %s: %v", malo, err)
			}
		})
	}
}

// Con la comprobación real: una carpeta bajo /tmp (1777) no se acepta.
func TestOutputsBajoTmpCompartidoSeRechazaDeVerdad(t *testing.T) {
	fi, err := os.Stat("/tmp")
	if err != nil || fi.Mode().Perm()&0o022 == 0 {
		t.Skip("/tmp no es de todos en este sistema")
	}
	s, _, _ := montar(t)
	service.AncestorInfo = service.RealAncestorInfo
	dir := carpeta(t, filepath.Join(t.TempDir(), "salidas"), 0o700)
	quiero(t, fija(s, dir), "ancestro_inseguro")
}

// Al arrancar se revalida la carpeta guardada (dueño, 0700 y ancestros): si ya no vale, rige la de fábrica y
// queda dicho el motivo.
func TestCargarRevalidaLaCarpetaGuardada(t *testing.T) {
	_, d, root := montar(t)
	dir := carpeta(t, filepath.Join(root, "guardada"), 0o700)
	if err := service.SaveCoreSettings(d.DB(), d.Now(), dir, service.IngestDefaults{MaxFiles: 4}); err != nil {
		t.Fatal(err)
	}
	cargar := func() *service.CoreSettings {
		st := service.NewCoreSettings("fabrica", root)
		if err := st.Load(d.DB(), func(p string) error { _, err := service.CheckOutputs(p, st, false); return err }); err != nil {
			t.Fatal(err)
		}
		return st
	}
	if st := cargar(); st.Outputs() != dir || st.Issue() != "" {
		t.Fatalf("válida: %s %q", st.Outputs(), st.Issue())
	}
	os.Chmod(dir, 0o755)
	st := cargar()
	if st.Outputs() != "fabrica" || !strings.Contains(st.Issue(), "chmod 700") || st.Ingest().MaxFiles != 4 {
		t.Fatalf("laxa: %s %q %+v", st.Outputs(), st.Issue(), st.Ingest())
	}
	if out, _ := st.Configured(); out != dir {
		t.Fatalf("lo guardado debe seguir a la vista: %q", out)
	}
	// un ancestro que otros escriben también la invalida
	os.Chmod(dir, 0o700)
	service.AncestorInfo = func(string) (os.FileMode, uint32, error) { return 0o777, 0, nil }
	if st = cargar(); st.Outputs() != "fabrica" || !strings.Contains(st.Issue(), "ancestro_inseguro") {
		t.Fatalf("ancestro: %s %q", st.Outputs(), st.Issue())
	}
}

// Si la carpeta guardada ya no es válida y la persona cambia solo los defaults de ingest, el cambio se aplica y
// el estado avisa del problema de la carpeta; al corregirla vuelve a regir.
func TestCambiarSoloIngestConLaCarpetaGuardadaInvalidaAvisa(t *testing.T) {
	s, d, root := montar(t)
	dir := carpeta(t, filepath.Join(root, "salidas"), 0o700)
	if err := fija(s, dir); err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o755)
	r, err := s.SetCorePrefs(context.Background(), &v1.SetCorePrefsRequest{Prefs: &v1.CorePrefs{OutputsDir: dir, IngestDefaults: &v1.IngestDefaults{MaxFiles: 4}}})
	if err != nil {
		t.Fatalf("el cambio de ingest no debe fallar por la carpeta: %v", err)
	}
	if d.Settings().Ingest().MaxFiles != 4 || !strings.Contains(r.State.Note, "chmod 700 "+dir) || r.State.OutputsDirEffective != d.Settings().Factory() || d.Outputs() != d.Settings().Factory() {
		t.Fatalf("estado = %+v", r.State)
	}
	g, _ := s.GetCorePrefs(context.Background(), &v1.GetCorePrefsRequest{})
	if !strings.Contains(g.State.Note, "chmod 700") || g.State.Prefs.OutputsDir != dir {
		t.Fatalf("get = %+v", g.State)
	}
	if !strings.Contains(strings.ReplaceAll(d.AuditText(), `>`, ">"), "outputs_dir_invalid") {
		t.Fatalf("auditoría sin el aviso:\n%s", d.AuditText())
	}
	// cambiar la carpeta a otra inválida sigue rechazándose
	quiero(t, fija(s, filepath.Join(root, "no-existe")), "no_existe")
	// corregida, vuelve a regir y el aviso se va
	os.Chmod(dir, 0o700)
	r, err = s.SetCorePrefs(context.Background(), &v1.SetCorePrefsRequest{Prefs: &v1.CorePrefs{OutputsDir: dir, IngestDefaults: &v1.IngestDefaults{MaxFiles: 4}}})
	if err != nil || r.State.Note != "" || d.Outputs() != dir {
		t.Fatalf("corregida: %v %+v", err, r)
	}
}

// Una carpeta que contiene la carpeta personal (un ancestro de HOME) tampoco se acepta.
func TestOutputsQueContieneElHomeSeRechaza(t *testing.T) {
	s, d, root := montar(t)
	d.S = service.NewCoreSettings(d.Out, filepath.Join(root, "casa", "usuario"))
	carpeta(t, filepath.Join(root, "casa", "usuario"), 0o700)
	quiero(t, fija(s, carpeta(t, filepath.Join(root, "casa"), 0o700)), "reservada")
}

// ui.language solo acepta es o en; otro valor es InvalidArgument y no se guarda.
func TestUiLanguageSoloEsOEn(t *testing.T) {
	s, _, _ := montar(t)
	ctx := context.Background()
	for _, v := range []string{"es", "en"} {
		if _, err := s.SetPreference(ctx, &v1.SetPreferenceRequest{Key: "ui.language", Value: v}); err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		if r, _ := s.GetPreference(ctx, &v1.GetPreferenceRequest{Key: "ui.language"}); r.Value != v {
			t.Fatalf("no guardó %s: %q", v, r.Value)
		}
	}
	for _, v := range []string{"", "fr", "EN", "en-US", "en "} {
		_, err := s.SetPreference(ctx, &v1.SetPreferenceRequest{Key: "ui.language", Value: v})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%q: %v", v, err)
		}
	}
	if r, _ := s.GetPreference(ctx, &v1.GetPreferenceRequest{Key: "ui.language"}); r.Value != "en" {
		t.Fatalf("un valor inválido cambió la preferencia: %q", r.Value)
	}
}

// El aviso de carpeta inválida se actualiza aunque nada más cambie, y la auditoría dice la carpeta y el motivo
// (el código prefs.outputs.X) en inglés.
func TestAvisoDeCarpetaInvalidaCambiaDeMotivoYSeAudita(t *testing.T) {
	s, d, root := montar(t)
	dir := carpeta(t, filepath.Join(root, "salidas"), 0o700)
	if err := fija(s, dir); err != nil {
		t.Fatal(err)
	}
	guarda := func() *v1.SetCorePrefsResponse {
		r, err := s.SetCorePrefs(context.Background(), &v1.SetCorePrefsRequest{Prefs: &v1.CorePrefs{OutputsDir: dir}})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	os.RemoveAll(dir)
	if r := guarda(); !strings.Contains(r.State.Note, "no_existe") {
		t.Fatalf("nota = %q", r.State.Note)
	}
	if a := d.AuditText(); !strings.Contains(a, "outputs_dir_invalid dir=") || !strings.Contains(a, "reason=no_existe") {
		t.Fatalf("auditoría sin carpeta y motivo:\n%s", a)
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o755)
	r := guarda() // sin otros cambios: el motivo cambió y el aviso debe ponerse al día
	if !strings.Contains(r.State.Note, "permisos") || strings.Contains(r.State.Note, "no_existe") {
		t.Fatalf("nota = %q", r.State.Note)
	}
	if a := d.AuditText(); !strings.Contains(a, "reason=permisos") || !strings.Contains(a, filepath.Base(dir)) {
		t.Fatalf("auditoría sin el motivo nuevo:\n%s", a)
	}
}
