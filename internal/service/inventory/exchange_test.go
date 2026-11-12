package inventory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/devices"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

func nuevoSvc(t *testing.T) (*svc, *servicetest.Deps) {
	t.Helper()
	d := servicetest.New(t)
	os.MkdirAll(d.Out, 0o700)
	return &svc{d: d}, d
}

// exportado arma una libreta con dos hosts (uno con credencial) y la exporta; devuelve la ruta.
func exportado(t *testing.T) (path string, s *svc, d *servicetest.Deps) {
	t.Helper()
	s, d = nuevoSvc(t)
	cid := cred(t, d, "admin lab")
	poner(t, s, &v1.Device{Name: "SW-CORE", Target: &v1.Target{Address: "10.0.0.1"}, Platform: "ios-xe", Folder: "Lab", Tags: []string{"core"}, Notes: "nota privada", CredentialId: cid})
	poner(t, s, &v1.Device{Name: "SW-ACC", Target: &v1.Target{Address: "10.0.0.2"}, Profile: &v1.DeviceProfile{Port: 2222}})
	path = filepath.Join(t.TempDir(), "hosts.json")
	r, err := s.ExportHosts(bg, &v1.ExportHostsRequest{Path: path})
	if err != nil || r.Count != 2 || len(r.Warnings) != 0 {
		t.Fatalf("export: %v %v", r, err)
	}
	return
}

func TestExportaSoloLaEtiquetaDeLaCredencial(t *testing.T) {
	path, s, d := exportado(t)
	b, _ := os.ReadFile(path)
	txt := string(b)
	cid := ""
	for _, x := range lista(t, s, &v1.ListDevicesRequest{}) {
		cid += x.CredentialId
	}
	if len(cid) != 32 {
		t.Fatalf("cid = %q", cid)
	}
	for _, mal := range []string{cid, "hunter2-secreto", "enable-secreto", "credential_id"} {
		if strings.Contains(txt, mal) {
			t.Errorf("el export contiene %q", mal)
		}
	}
	if !strings.Contains(txt, `"credential_label":"admin lab"`) || !strings.Contains(txt, "nota privada") {
		t.Fatalf("export: %s", txt)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("modo = %v", fi.Mode())
	}
	// no sobrescribe sin overwrite; con overwrite sí; la ruta debe ser absoluta; y hay que tener algo que exportar
	_, err := s.ExportHosts(bg, &v1.ExportHostsRequest{Path: path})
	codigo(t, err, codes.AlreadyExists)
	if _, err = s.ExportHosts(bg, &v1.ExportHostsRequest{Path: path, Overwrite: true}); err != nil {
		t.Fatal(err)
	}
	_, err = s.ExportHosts(bg, &v1.ExportHostsRequest{Path: "hosts.json"})
	codigo(t, err, codes.InvalidArgument)
	vacio, _ := nuevoSvc(t)
	_, err = vacio.ExportHosts(bg, &v1.ExportHostsRequest{Path: filepath.Join(t.TempDir(), "x.json")})
	codigo(t, err, codes.InvalidArgument)
	// por ids: solo esos; un id que no existe es NotFound
	un := filepath.Join(t.TempDir(), "uno.json")
	var id string
	for _, x := range lista(t, s, &v1.ListDevicesRequest{Query: "acc"}) {
		id = x.Id
	}
	if r, err := s.ExportHosts(bg, &v1.ExportHostsRequest{Path: un, Ids: []string{id, id}}); err != nil || r.Count != 1 {
		t.Fatalf("por ids: %v %v", r, err)
	}
	_, err = s.ExportHosts(bg, &v1.ExportHostsRequest{Path: filepath.Join(t.TempDir(), "n.json"), Ids: []string{"nada"}})
	codigo(t, err, codes.NotFound)
	// con la bóveda cerrada el host con credencial sale sin ella y se avisa
	d.V.LockAll()
	cerrado := filepath.Join(t.TempDir(), "c.json")
	r, err := s.ExportHosts(bg, &v1.ExportHostsRequest{Path: cerrado})
	if err != nil || len(r.Warnings) != 1 {
		t.Fatalf("cerrada: %v %v", r, err)
	}
	if b, _ := os.ReadFile(cerrado); strings.Contains(string(b), "admin lab") {
		t.Fatal("sin bóveda no hay etiqueta")
	}
	if a := d.AuditText(); !strings.Contains(a, "hosts.exportar") || strings.Contains(a, "nota privada") {
		t.Fatalf("auditoría: %s", a)
	}
}

func TestImportaIdaYVueltaResolviendoLaCredencialPorEtiqueta(t *testing.T) {
	path, _, _ := exportado(t)
	// otra instalación: su bóveda tiene «admin lab» con otro id, y dos con la etiqueta repetida no se resuelven
	s2, d2 := nuevoSvc(t)
	otro := cred(t, d2, "admin lab")
	p, err := s2.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
	if err != nil || len(p.Items) != 2 || p.Token == "" || p.ExpiresMs == 0 {
		t.Fatalf("preview: %v %v", p, err)
	}
	for _, it := range p.Items {
		if it.State != "nuevo" || it.CredentialMissing || it.Host.CredentialId != "" || it.Key == "" {
			t.Fatalf("item = %v", it)
		}
	}
	if p.Items[0].Host.CredentialLabel != "admin lab" && p.Items[1].Host.CredentialLabel != "admin lab" {
		t.Fatal("la vista previa debe mostrar la etiqueta")
	}
	a, err := s2.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token})
	if err != nil || a.Created != 2 {
		t.Fatalf("apply: %v %v", a, err)
	}
	for _, x := range lista(t, s2, &v1.ListDevicesRequest{}) {
		if x.Name == "SW-CORE" && (x.CredentialId != otro || x.CredentialLabel != "admin lab" || x.Folder != "Lab" || x.Notes != "nota privada") {
			t.Fatalf("SW-CORE importado = %v", x)
		}
		if x.Name == "SW-ACC" && (x.Profile.Port != 2222 || x.CredentialId != "") {
			t.Fatalf("SW-ACC importado = %v", x)
		}
	}
	// el token es de un solo uso
	_, err = s2.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token})
	codigo(t, err, codes.NotFound)
	// ahora todo es «igual»
	p, _ = s2.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
	if p.Items[0].State != "igual" || p.Items[1].State != "igual" {
		t.Fatalf("segunda vista previa: %v", p.Items)
	}
	if a, err = s2.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token}); err != nil || a.Skipped != 2 || a.Created != 0 {
		t.Fatalf("igual: %v %v", a, err)
	}
	if au := d2.AuditText(); !strings.Contains(au, "hosts.importar") || strings.Contains(au, "nota privada") {
		t.Fatalf("auditoría: %s", au)
	}

	// sin la etiqueta en la bóveda: se avisa y el host queda sin credencial
	s3, _ := nuevoSvc(t)
	p, err = s3.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	faltan := 0
	for _, it := range p.Items {
		if it.CredentialMissing {
			faltan++
		}
	}
	if faltan != 1 || len(p.Warnings) == 0 {
		t.Fatalf("faltan = %d avisos = %v", faltan, p.Warnings)
	}
	if _, err = s3.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token}); err != nil {
		t.Fatal(err)
	}
	for _, x := range lista(t, s3, &v1.ListDevicesRequest{}) {
		if x.CredentialId != "" {
			t.Fatalf("no debía quedar credencial: %v", x)
		}
	}
	// una etiqueta repetida en la bóveda es ambigua: tampoco se asigna
	s4, d4 := nuevoSvc(t)
	cred(t, d4, "admin lab")
	cred(t, d4, "admin lab")
	p, _ = s4.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
	if !p.Items[0].CredentialMissing && !p.Items[1].CredentialMissing {
		t.Fatal("etiqueta repetida: debe avisar")
	}
}

func TestImportEstadosYDecisiones(t *testing.T) {
	path, _, _ := exportado(t)
	s, _ := nuevoSvc(t)
	idCore := poner(t, s, &v1.Device{Name: "SW-CORE", Target: &v1.Target{Address: "10.0.0.1"}, Platform: "ios-xe", Folder: "Lab", Tags: []string{"core"}, Notes: "otras notas"}) // misma dirección, otros datos
	poner(t, s, host("sw-acc", "10.0.0.50"))                                                                                                                                     // mismo nombre, otra dirección
	p, err := s.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]*v1.ImportHostItem{}
	for _, it := range p.Items {
		by[it.Key] = it
	}
	core, acc := by["10.0.0.1:22"], by["10.0.0.2:2222"]
	if core == nil || acc == nil || core.State != "conflicto" || core.Reason != "direccion" || core.ConflictsWith != idCore || acc.State != "conflicto" || acc.Reason != "nombre" {
		t.Fatalf("items = %v", p.Items)
	}
	// sin decisión para los conflictos: se rechaza y el token sigue sirviendo
	_, err = s.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token})
	codigo(t, err, codes.InvalidArgument)
	_, err = s.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token, Decisions: []*v1.ImportHostDecision{{Key: "10.0.0.1:22", Action: "reemplazar"}, {Key: "10.0.0.1:22", Action: "omitir"}}})
	codigo(t, err, codes.InvalidArgument) // repetida
	_, err = s.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token, Decisions: []*v1.ImportHostDecision{{Key: "10.0.0.1:22", Action: "renombrar"}, {Key: "10.0.0.2:2222", Action: "omitir"}}})
	codigo(t, err, codes.InvalidArgument) // renombrar un choque de dirección
	if got := lista(t, s, &v1.ListDevicesRequest{}); len(got) != 2 {
		t.Fatalf("no debía escribir nada: %v", got)
	}
	a, err := s.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token, Decisions: []*v1.ImportHostDecision{{Key: "10.0.0.1:22", Action: "reemplazar"}, {Key: "10.0.0.2:2222", Action: "renombrar"}}})
	if err != nil || a.Replaced != 1 || a.Renamed != 1 {
		t.Fatalf("apply: %v %v", a, err)
	}
	var nombres []string
	for _, x := range lista(t, s, &v1.ListDevicesRequest{}) {
		nombres = append(nombres, x.Name+"/"+x.Notes)
		if x.Name == "SW-CORE" && x.Id != idCore {
			t.Fatal("reemplazar conserva el id")
		}
	}
	if got := strings.Join(nombres, ","); got != "SW-CORE/nota privada,SW-ACC (importado)/,sw-acc/" {
		t.Fatalf("hosts = %s", got)
	}
}

func TestImportRechazaArchivoDañadoYTokenVencido(t *testing.T) {
	path, _, _ := exportado(t)
	s, _ := nuevoSvc(t)
	b, _ := os.ReadFile(path)
	mal := filepath.Join(t.TempDir(), "mal.json")
	os.WriteFile(mal, []byte(strings.Replace(string(b), "10.0.0.2", "10.0.0.3", 1)), 0o600)
	_, err := s.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: mal})
	if codigo(t, err, codes.InvalidArgument); !strings.Contains(err.Error(), "suma") {
		t.Fatalf("err = %v", err)
	}
	_, err = s.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: "hosts.json"})
	codigo(t, err, codes.InvalidArgument)
	_, err = s.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: filepath.Join(t.TempDir(), "no-existe.json")})
	codigo(t, err, codes.FailedPrecondition)
	// un symlink o una carpeta no son un archivo de import
	dir := t.TempDir()
	_, err = s.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: dir, Format: "json"})
	codigo(t, err, codes.FailedPrecondition)

	ahora := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return ahora }
	p, err := s.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return ahora.Add(10*time.Minute + time.Second) }
	_, err = s.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token})
	codigo(t, err, codes.FailedPrecondition)
	_, err = s.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token})
	codigo(t, err, codes.NotFound) // el vencido se consumió
	if got := lista(t, s, &v1.ListDevicesRequest{}); len(got) != 0 {
		t.Fatalf("con el token vencido no se escribe: %v", got)
	}
	// en el límite todavía vale
	s.now = func() time.Time { return ahora }
	p, _ = s.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
	s.now = func() time.Time { return ahora.Add(10 * time.Minute) }
	if _, err = s.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token}); err != nil {
		t.Fatalf("en el límite: %v", err)
	}
}

func TestImportEnParaleloSoloAplicaUnaVez(t *testing.T) {
	path, _, _ := exportado(t)
	s, _ := nuevoSvc(t)
	p, err := s.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token}); err == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 || len(lista(t, s, &v1.ListDevicesRequest{})) != 2 {
		t.Fatalf("aplicó %d veces", ok.Load())
	}
}

// ---- CSV, errores por línea, suma opcional y plantilla ----

func TestExportaYImportaCSV(t *testing.T) {
	_, s, d := exportado(t)
	dir := t.TempDir()
	csv := filepath.Join(dir, "hosts.csv")
	r, err := s.ExportHosts(bg, &v1.ExportHostsRequest{Path: csv})
	if err != nil || r.Count != 2 {
		t.Fatalf("export csv: %v %v", r, err)
	}
	b, _ := os.ReadFile(csv)
	txt := string(b)
	if !strings.HasPrefix(txt, "\xef\xbb\xbfname,address,port,platform,folder,tags,credential_label,notes\n") || !strings.Contains(txt, "admin lab") || strings.Contains(txt, "sha256") || strings.Contains(txt, "hunter2") {
		t.Fatalf("csv:\n%s", txt)
	}
	cid := ""
	for _, x := range lista(t, s, &v1.ListDevicesRequest{}) {
		cid += x.CredentialId
	}
	if strings.Contains(txt, cid) {
		t.Fatal("el id de la credencial no debe viajar")
	}
	if fi, _ := os.Stat(csv); fi.Mode().Perm() != 0o600 {
		t.Fatalf("modo = %v", fi.Mode())
	}
	// el formato sale de la extensión o del campo format; sin ninguno de los dos es un error
	_, err = s.ExportHosts(bg, &v1.ExportHostsRequest{Path: filepath.Join(dir, "hosts.txt")})
	codigo(t, err, codes.InvalidArgument)
	txtCSV := filepath.Join(dir, "hosts.txt")
	if _, err = s.ExportHosts(bg, &v1.ExportHostsRequest{Path: txtCSV, Format: "csv"}); err != nil {
		t.Fatal(err)
	}
	// otra instalación con la misma etiqueta: el CSV se importa igual que el JSON
	s2, d2 := nuevoSvc(t)
	otro := cred(t, d2, "admin lab")
	for _, ruta := range []string{csv, txtCSV} {
		p, err := s2.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: ruta, Format: formatoPara(ruta)})
		if err != nil || len(p.Items) != 2 || len(p.Errors) != 0 || p.Format != "csv" || len(p.Warnings) != 0 {
			t.Fatalf("preview %s: %v %v", ruta, p, err)
		}
		a, err := s2.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token})
		if ruta == csv && (err != nil || a.Created != 2) || ruta == txtCSV && (err != nil || a.Skipped != 2) {
			t.Fatalf("apply %s: %v %v", ruta, a, err)
		}
	}
	for _, x := range lista(t, s2, &v1.ListDevicesRequest{}) {
		if x.Name == "SW-CORE" && x.CredentialId != otro {
			t.Fatalf("credencial = %q", x.CredentialId)
		}
	}
	_ = d
}

func formatoPara(ruta string) string {
	if strings.HasSuffix(ruta, ".txt") {
		return "csv"
	}
	return ""
}

func TestExportNoPasaDeLosHostsQueElImportAcepta(t *testing.T) {
	s, d := nuevoSvc(t)
	now := time.Now()
	for i := 0; i <= 1000; i++ {
		h := devicesHost(i, now)
		if err := putHost(d.DB(), h); err != nil {
			t.Fatal(err)
		}
	}
	_, err := s.ExportHosts(bg, &v1.ExportHostsRequest{Path: filepath.Join(t.TempDir(), "x.json")})
	codigo(t, err, codes.InvalidArgument)
	// el mensaje dice cómo partirlo: por ids, por ejemplo los de cada carpeta
	if !strings.Contains(err.Error(), "ids") || !strings.Contains(err.Error(), "carpeta") || !strings.Contains(err.Error(), "varios archivos") {
		t.Fatalf("mensaje = %v", err)
	}
	// con ids que caben, sí se exporta
	var ids []string
	hs, _ := loadHosts(d.DB())
	for _, h := range hs[:10] {
		ids = append(ids, h.ID)
	}
	if r, err := s.ExportHosts(bg, &v1.ExportHostsRequest{Path: filepath.Join(t.TempDir(), "p.json"), Ids: ids}); err != nil || r.Count != 10 {
		t.Fatalf("por ids: %v %v", r, err)
	}
}

func TestVistaPreviaConErroresPorLinea(t *testing.T) {
	s, _ := nuevoSvc(t)
	poner(t, s, host("ya", "10.0.0.1"))
	csv := "name,address,port,platform,folder,tags,credential_label,notes\n" +
		"nuevo,10.0.0.5,22,ios,,,,\n" + // 2
		"mala,admin@10.0.0.6,22,ios,,,,\n" + // 3
		"ya,10.0.0.1,22,ios-xe,,,,\n" + // 4 igual
		"corta,10.0.0.7\n" + // 5
		"otro,10.0.0.8,x,ios,,,,\n" + // 6
		"choca,10.0.0.1,22,nx-os,,,,\n" // 7 misma dirección con otros datos
	ruta := filepath.Join(t.TempDir(), "h.csv")
	os.WriteFile(ruta, []byte(csv), 0o600)
	p, err := s.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: ruta})
	if err != nil {
		t.Fatal(err)
	}
	var estados []string
	for _, it := range p.Items {
		estados = append(estados, it.Host.Name+"="+it.State)
	}
	if got := strings.Join(estados, ","); got != "nuevo=nuevo,ya=igual" {
		t.Fatalf("items = %s", got)
	}
	var lineas []string
	for _, e := range p.Errors {
		lineas = append(lineas, fmt.Sprintf("%d:%s", e.Line, e.Field))
		if e.Reason == "" {
			t.Fatalf("sin motivo: %+v", e)
		}
	}
	if got := strings.Join(lineas, ","); got != "3:address,5:,6:port,7:address" {
		t.Fatalf("errores = %s", got)
	}
}

func TestApplyAplicaSoloLasValidasYCuentaLasInvalidas(t *testing.T) {
	s, _ := nuevoSvc(t)
	idYa := poner(t, s, host("ya", "10.0.0.1"))
	csv := "name,address,port,platform,folder,tags,credential_label,notes\n" +
		"nuevo,10.0.0.5,22,ios,,,,\n" +
		"mala,admin@10.0.0.6,22,ios,,,,\n" +
		"ya,10.0.0.1,22,nx-os,,,,\n" + // conflicto de dirección con otros datos
		"otro,10.0.0.8,x,ios,,,,\n"
	ruta := filepath.Join(t.TempDir(), "h.csv")
	os.WriteFile(ruta, []byte(csv), 0o600)
	p, err := s.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: ruta})
	if err != nil || len(p.Items) != 2 || len(p.Errors) != 2 {
		t.Fatalf("preview: %v %v", p, err)
	}
	// las inválidas no necesitan decisión; el conflicto sí
	_, err = s.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token})
	codigo(t, err, codes.InvalidArgument)
	a, err := s.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token, Decisions: []*v1.ImportHostDecision{{Key: "10.0.0.1:22", Action: "reemplazar"}}})
	if err != nil || a.Created != 1 || a.Replaced != 1 || a.Invalid != 2 || a.Skipped != 2 {
		t.Fatalf("apply: %v %v", a, err)
	}
	var nombres []string
	for _, x := range lista(t, s, &v1.ListDevicesRequest{}) {
		nombres = append(nombres, x.Name+":"+x.Platform)
		if x.Name == "ya" && x.Id != idYa {
			t.Fatal("reemplazar conserva el id")
		}
	}
	if got := strings.Join(nombres, ","); got != "ya:nx-os,nuevo:ios" {
		t.Fatalf("hosts = %s", got)
	}
}

func TestJSONSinSumaAvisaYValidaCampoPorCampo(t *testing.T) {
	s, _ := nuevoSvc(t)
	raw := `{"formato":"macuahuitl-hosts","version":1,"exportado":"x","hosts":[` +
		`{"name":"a","address":"10.0.0.1","port":22,"platform":"ios","folder":"","tags":[],"credential_label":"","notes":""},` +
		`{"name":"b","address":"no es dir","port":22,"platform":"ios","folder":"","tags":[],"credential_label":"","notes":""}]}`
	ruta := filepath.Join(t.TempDir(), "h.json")
	os.WriteFile(ruta, []byte(raw), 0o600)
	p, err := s.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: ruta})
	if err != nil || len(p.Items) != 1 || len(p.Errors) != 1 || p.Errors[0].Line != 2 || p.Errors[0].Field != "address" || p.Format != "json" {
		t.Fatalf("preview: %v %v", p, err)
	}
	sin := false
	for _, w := range p.Warnings {
		sin = sin || strings.Contains(w, "sin suma de verificación")
	}
	if !sin {
		t.Fatalf("falta el aviso de suma: %v", p.Warnings)
	}
	// con suma, un archivo bueno no avisa
	path, _, _ := exportado(t)
	p, _ = s.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
	for _, w := range p.Warnings {
		if strings.Contains(w, "suma") {
			t.Fatalf("aviso de más: %v", w)
		}
	}
}

func TestPlantillaYDescripcionDeCampos(t *testing.T) {
	s, _ := nuevoSvc(t)
	f, err := s.HostsImportFormat(bg, &v1.HostsImportFormatRequest{})
	if err != nil || len(f.Fields) != 8 || f.MaxRows != 1000 || f.MaxBytes != 5<<20 {
		t.Fatalf("formato: %v %v", f, err)
	}
	if n := f.Fields[0]; n.Name != "name" || n.Type != "texto" || !n.Required || n.Example != "SW-CORE" || n.Description == "" {
		t.Fatalf("campo = %v", n)
	}
	if f.Fields[2].Name != "port" || f.Fields[2].Required || f.Fields[2].Type != "entero" || f.Fields[5].Type != "lista" {
		t.Fatalf("campos = %v", f.Fields)
	}
	for _, fmtName := range []string{"csv", "json"} {
		tp, err := s.HostsImportTemplate(bg, &v1.HostsImportTemplateRequest{Format: fmtName})
		if err != nil || tp.Format != fmtName || tp.Content == "" || !strings.HasSuffix(tp.Filename, "."+fmtName) {
			t.Fatalf("plantilla %s: %v %v", fmtName, tp, err)
		}
		// la plantilla pasa por la vista previa sin errores y todos sus hosts son nuevos
		ruta := filepath.Join(t.TempDir(), "plantilla."+fmtName)
		os.WriteFile(ruta, []byte(tp.Content), 0o600)
		p, err := s.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: ruta})
		if err != nil || len(p.Errors) != 0 || len(p.Items) != 3 {
			t.Fatalf("preview de la plantilla %s: %v %v", fmtName, p, err)
		}
		for _, it := range p.Items {
			if it.State != "nuevo" {
				t.Errorf("%s: %s es %s", fmtName, it.Host.Name, it.State)
			}
		}
		if fmtName == "json" && strings.Contains(tp.Content, "sha256") {
			t.Error("la plantilla JSON va sin suma")
		}
	}
	_, err = s.HostsImportTemplate(bg, &v1.HostsImportTemplateRequest{})
	codigo(t, err, codes.InvalidArgument)
	_, err = s.HostsImportTemplate(bg, &v1.HostsImportTemplateRequest{Format: "xml"})
	codigo(t, err, codes.InvalidArgument)
}

func devicesHost(i int, now time.Time) devices.Host {
	return devices.Host{ID: devices.NewID(), Name: fmt.Sprintf("h%04d", i), Address: fmt.Sprintf("h%04d.lab", i), Port: 22, Tags: []string{}, CreatedAt: now, UpdatedAt: now}
}

// Las credenciales se resuelven en la vista previa y se aplican tal cual: cerrar la bóveda entre los dos pasos
// no deja hosts sin credencial, ni borra la que ya tenía un reemplazado, ni vuelve conflicto a un «igual».
func TestApplyUsaLasCredencialesDeLaVistaPrevia(t *testing.T) {
	path, _, _ := exportado(t)
	s2, d2 := nuevoSvc(t)
	otro := cred(t, d2, "admin lab")
	p, err := s2.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	d2.V.LockAll()
	if a, err := s2.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token}); err != nil || a.Created != 2 {
		t.Fatalf("apply: %v %v", a, err)
	}
	cid := func(name string) string {
		for _, x := range lista(t, s2, &v1.ListDevicesRequest{}) {
			if x.Name == name {
				return x.CredentialId
			}
		}
		t.Fatalf("no hay %s", name)
		return ""
	}
	if cid("SW-CORE") != otro {
		t.Fatalf("SW-CORE quedó con credencial %q, quería %q", cid("SW-CORE"), otro)
	}

	// con la bóveda abierta otra vez: el mismo archivo es «igual»; se cierra y al aplicar sigue siendo «igual»
	if err := d2.V.Unlock([]byte("maestra")); err != nil {
		t.Fatal(err)
	}
	p, _ = s2.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
	if p.Items[0].State != "igual" && p.Items[1].State != "igual" {
		t.Fatalf("estados: %v", p.Items)
	}
	d2.V.LockAll()
	if a, err := s2.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token}); err != nil || a.Skipped != 2 || a.Created != 0 {
		t.Fatalf("igual con la bóveda cerrada: %v %v", a, err)
	}

	// un reemplazo conserva la credencial resuelta aunque la bóveda se cierre
	if err := d2.V.Unlock([]byte("maestra")); err != nil {
		t.Fatal(err)
	}
	for _, x := range lista(t, s2, &v1.ListDevicesRequest{}) {
		if x.Name == "SW-CORE" {
			x.Notes = "cambiadas"
			x.Profile = &v1.DeviceProfile{Port: 22}
			if _, err := s2.PutDevice(bg, &v1.PutDeviceRequest{Device: x}); err != nil {
				t.Fatal(err)
			}
		}
	}
	p, _ = s2.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
	d2.V.LockAll()
	if _, err := s2.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token, Decisions: []*v1.ImportHostDecision{{Key: "10.0.0.1:22", Action: "reemplazar"}}}); err != nil {
		t.Fatal(err)
	}
	if cid("SW-CORE") != otro {
		t.Fatalf("el reemplazo perdió la credencial: %q", cid("SW-CORE"))
	}

	// si la bóveda estaba cerrada en la vista previa, ya hubo aviso y los hosts quedan sin credencial aunque se abra después
	s3, d3 := nuevoSvc(t)
	cred(t, d3, "admin lab")
	d3.V.LockAll()
	p, _ = s3.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
	if len(p.Warnings) == 0 {
		t.Fatal("falta el aviso de la bóveda cerrada")
	}
	if err := d3.V.Unlock([]byte("maestra")); err != nil {
		t.Fatal(err)
	}
	if _, err := s3.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token}); err != nil {
		t.Fatal(err)
	}
	for _, x := range lista(t, s3, &v1.ListDevicesRequest{}) {
		if x.CredentialId != "" {
			t.Fatalf("se respeta lo avisado en la vista previa: %v", x)
		}
	}
}
