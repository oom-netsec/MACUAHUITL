package inventory

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
	"github.com/oom-netsec/MACUAHUITL/internal/store"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

func TestListDevices(t *testing.T) {
	d := servicetest.New(t)
	dd := filepath.Join(d.Out, "j1", "SW1_10.0.0.1")
	os.MkdirAll(dd, 0o700)
	os.WriteFile(filepath.Join(dd, "r001.txt"), []byte("===== x ====="), 0o600)
	os.MkdirAll(filepath.Join(d.Out, "respaldos", "SW9"), 0o700)
	os.WriteFile(filepath.Join(d.Out, "respaldos", "SW9", "20261105T080000Z-running.cfg"), []byte("x"), 0o600)
	s := &svc{d: d}
	r, err := s.ListDevices(context.Background(), &v1.ListDevicesRequest{})
	if err != nil || len(r.Devices) != 2 {
		t.Fatalf("r = %v err = %v", r, err)
	}
	if a := r.Devices[0]; a.Target.Address != "10.0.0.1" || a.Id != "10.0.0.1" || a.Hostname != "SW1" || a.LastSeenMs == 0 || len(a.Sources) != 1 || a.Sources[0] != "flota" {
		t.Fatalf("SW1 = %v", a)
	}
	if b := r.Devices[1]; b.Target.Address != "" || b.Id != "nombre:SW9" || b.Hostname != "SW9" || b.LastSeenMs != time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC).UnixMilli() {
		t.Fatalf("SW9 = %v", b)
	}
	if r, _ = s.ListDevices(context.Background(), &v1.ListDevicesRequest{Query: "sw9"}); len(r.Devices) != 1 {
		t.Fatalf("filtro = %v", r)
	}
	// outputs/ aún no existe: error claro, no una lista vacía que parezca «no hay equipos»
	if _, err := (&svc{d: servicetest.New(t)}).ListDevices(context.Background(), &v1.ListDevicesRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v", err)
	}
}

// Un trabajo con output_dir fuera de outputs/ también aporta sus equipos (QA 3560CX: la lista salía vacía).
func TestListDevicesDescubreOutputDirDeLosTrabajos(t *testing.T) {
	d := servicetest.New(t)
	os.MkdirAll(d.Out, 0o700) // outputs/ por defecto existe pero está vacío
	raiz := t.TempDir()
	dd := filepath.Join(raiz, "ronda_20261106-100000", "SW2_10.0.0.2")
	os.MkdirAll(dd, 0o700)
	os.WriteFile(filepath.Join(dd, "r001.txt"), []byte("===== x ====="), 0o600)
	if _, err := d.DB().Exec(`INSERT INTO jobs(id,name,spec_json,state,created_at) VALUES('j1','ronda',?,'completed','2026-11-06T10:00:00Z')`,
		`{"Name":"ronda","OutputDir":"`+raiz+`"}`); err != nil {
		t.Fatal(err)
	}
	r, err := (&svc{d: d}).ListDevices(context.Background(), &v1.ListDevicesRequest{})
	if err != nil || len(r.Devices) != 1 || r.Devices[0].Id != "10.0.0.2" {
		t.Fatalf("r = %v err = %v", r, err)
	}
	// Las carpetas de lote de respaldo (dentro de outputs/) no son raíces aparte.
	lote := filepath.Join(d.Out, "respaldos", ".trabajos", "lote-1")
	if _, err := d.DB().Exec(`INSERT INTO jobs(id,name,spec_json,state,created_at) VALUES('j2','lote',?,'completed','2026-11-06T11:00:00Z')`,
		`{"Name":"lote","OutputDir":"`+lote+`"}`); err != nil {
		t.Fatal(err)
	}
	if roots := service.JobOutputRoots(d); len(roots) != 1 || roots[0] != raiz {
		t.Fatalf("raíces = %v", roots)
	}
}

// ---- Libreta de hosts (fase 29b) ----

var bg = context.Background()

func codigo(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("código = %v (%v), quiero %v", status.Code(err), err, want)
	}
}

func host(name, addr string) *v1.Device {
	return &v1.Device{Name: name, Target: &v1.Target{Address: addr}, Platform: "ios-xe"}
}

func poner(t *testing.T, s *svc, d *v1.Device) string {
	t.Helper()
	r, err := s.PutDevice(bg, &v1.PutDeviceRequest{Device: d})
	if err != nil {
		t.Fatalf("PutDevice(%q): %v", d.Name, err)
	}
	return r.Id
}

func cred(t *testing.T, d *servicetest.Deps, label string) string {
	t.Helper()
	if d.V == nil {
		d.CreateVault()
	}
	id, err := d.V.Put(vault.Credential{Label: label, Username: "admin", Password: secret.New([]byte("hunter2-secreto")), Enable: secret.New([]byte("enable-secreto"))})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func lista(t *testing.T, s *svc, r *v1.ListDevicesRequest) []*v1.Device {
	t.Helper()
	res, err := s.ListDevices(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	return res.Devices
}

func TestPutCreaEditaYBorra(t *testing.T) {
	d := servicetest.New(t)
	s := &svc{d: d}
	os.MkdirAll(d.Out, 0o700)
	t0 := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return t0 }
	id := poner(t, s, &v1.Device{Name: "SW-CORE", Target: &v1.Target{Address: "10.0.0.1"}, Platform: "ios-xe", Folder: "Lab", Tags: []string{"core"}, Notes: "piso 2",
		Profile: &v1.DeviceProfile{Port: 2222}})
	if len(id) != 32 {
		t.Fatalf("id = %q", id)
	}
	got := lista(t, s, &v1.ListDevicesRequest{})
	if len(got) != 1 {
		t.Fatalf("lista = %v", got)
	}
	g := got[0]
	if g.Id != id || g.Name != "SW-CORE" || g.Hostname != "SW-CORE" || g.Target.Address != "10.0.0.1" || g.Profile.Port != 2222 || g.Folder != "Lab" ||
		g.Notes != "piso 2" || len(g.Tags) != 1 || strings.Join(g.Sources, ",") != "manual" || g.Platform != "ios-xe" {
		t.Fatalf("host = %v", g)
	}
	// el puerto por defecto es 22
	id2 := poner(t, s, host("SW-2", "10.0.0.2"))
	for _, x := range lista(t, s, &v1.ListDevicesRequest{}) {
		if x.Id == id2 && x.Profile.Port != 22 {
			t.Fatalf("puerto = %d", x.Profile.Port)
		}
	}
	// editar conserva el id y la fecha de creación, cambia los datos; la dirección canónica
	s.now = func() time.Time { return t0.Add(time.Hour) }
	if _, err := s.PutDevice(bg, &v1.PutDeviceRequest{Device: &v1.Device{Id: id, Name: "SW-CORE-1", Target: &v1.Target{Address: "SW1.Lab"}, Platform: "nx-os"}}); err != nil {
		t.Fatal(err)
	}
	var ed *v1.Device
	for _, x := range lista(t, s, &v1.ListDevicesRequest{}) {
		if x.Id == id {
			ed = x
		}
	}
	if ed == nil || ed.Name != "SW-CORE-1" || ed.Target.Address != "sw1.lab" || ed.Platform != "nx-os" || ed.Folder != "" || len(ed.Tags) != 0 {
		t.Fatalf("editado = %v", ed)
	}
	if hs, _ := loadHosts(d.DB()); len(hs) != 2 {
		t.Fatalf("hosts = %v", hs)
	} else if x := hs[1]; x.ID != id || !x.CreatedAt.Equal(t0) || !x.UpdatedAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("fechas = %v %v %v", x.ID == id, x.CreatedAt, x.UpdatedAt)
	}
	// editar uno que no existe (o con id de dirección) es NotFound
	_, err := s.PutDevice(bg, &v1.PutDeviceRequest{Device: &v1.Device{Id: "10.0.0.1", Name: "x", Target: &v1.Target{Address: "10.0.0.9"}}})
	codigo(t, err, codes.NotFound)
	// borrar
	if _, err := s.DeleteDevice(bg, &v1.DeleteDeviceRequest{Id: id}); err != nil {
		t.Fatal(err)
	}
	_, err = s.DeleteDevice(bg, &v1.DeleteDeviceRequest{Id: id})
	codigo(t, err, codes.NotFound)
	if got := lista(t, s, &v1.ListDevicesRequest{}); len(got) != 1 || got[0].Id != id2 {
		t.Fatalf("tras borrar = %v", got)
	}
	// auditoría de crear, editar y borrar, sin notas
	a := d.AuditText()
	for _, w := range []string{"hosts.crear", "hosts.editar", "hosts.borrar", "SW-CORE-1"} {
		if !strings.Contains(a, w) {
			t.Errorf("la bitácora no tiene %q", w)
		}
	}
	if strings.Contains(a, "piso 2") {
		t.Error("las notas no deben ir a la bitácora")
	}
}

func TestPutValidaYNoRepite(t *testing.T) {
	d := servicetest.New(t)
	s := &svc{d: d}
	os.MkdirAll(d.Out, 0o700)
	poner(t, s, host("uno", "10.0.0.1"))
	malos := []*v1.Device{
		nil,
		host("", "10.0.0.5"),
		host("x", "admin@10.0.0.5"),
		{Name: "x", Target: &v1.Target{Address: "10.0.0.5"}, Profile: &v1.DeviceProfile{Port: 70000}},
		{Name: "x", Target: &v1.Target{Address: "10.0.0.5"}, Platform: "junos"},
		{Name: "x", Target: &v1.Target{Address: "10.0.0.5"}, Folder: "a/b"},
		{Name: "x", Target: &v1.Target{Address: "10.0.0.5"}, Tags: []string{"MAYUS"}},
		{Name: "x", Target: &v1.Target{Address: "10.0.0.5"}, CredentialId: "no-es-id"},
	}
	for i, m := range malos {
		_, err := s.PutDevice(bg, &v1.PutDeviceRequest{Device: m})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("malo %d: %v", i, err)
		}
	}
	// misma dirección y puerto (aunque cambie el nombre o las mayúsculas del DNS) o mismo nombre: AlreadyExists
	poner(t, s, host("dns", "SW9.lab"))
	for _, m := range []*v1.Device{host("otro", "10.0.0.1"), host("dos", "sw9.LAB"), host("UNO", "10.0.0.7")} {
		_, err := s.PutDevice(bg, &v1.PutDeviceRequest{Device: m})
		codigo(t, err, codes.AlreadyExists)
	}
	// el mismo host en otro puerto sí
	poner(t, s, &v1.Device{Name: "uno-p2", Target: &v1.Target{Address: "10.0.0.1"}, Profile: &v1.DeviceProfile{Port: 2222}})
	// editar a un nombre o destino de otro host también choca; editarse a sí mismo no
	id := poner(t, s, host("tres", "10.0.0.3"))
	_, err := s.PutDevice(bg, &v1.PutDeviceRequest{Device: &v1.Device{Id: id, Name: "uno", Target: &v1.Target{Address: "10.0.0.3"}}})
	codigo(t, err, codes.AlreadyExists)
	_, err = s.PutDevice(bg, &v1.PutDeviceRequest{Device: &v1.Device{Id: id, Name: "tres", Target: &v1.Target{Address: "10.0.0.1"}}})
	codigo(t, err, codes.AlreadyExists)
	if _, err = s.PutDevice(bg, &v1.PutDeviceRequest{Device: &v1.Device{Id: id, Name: "TRES", Target: &v1.Target{Address: "10.0.0.3"}}}); err != nil {
		t.Fatalf("editarse a sí mismo: %v", err)
	}
}

func TestPersisteTrasReabrirElStore(t *testing.T) {
	d := servicetest.New(t)
	os.MkdirAll(d.Out, 0o700)
	id := poner(t, &svc{d: d}, &v1.Device{Name: "persistente", Target: &v1.Target{Address: "10.0.0.1"}, Tags: []string{"a", "b"}, Notes: "n"})
	path := filepath.Join(t.TempDir(), "otra.db")
	// copia de la base vía VACUUM INTO y reapertura con el store real
	if _, err := d.DB().Exec(`VACUUM INTO ?`, path); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hs, err := loadHosts(db)
	if err != nil || len(hs) != 1 || hs[0].ID != id || hs[0].Name != "persistente" || strings.Join(hs[0].Tags, ",") != "a,b" || hs[0].Notes != "n" || hs[0].CreatedAt.IsZero() {
		t.Fatalf("hosts = %+v err = %v", hs, err)
	}
}

func TestDedupeConLasFuentesDescubiertas(t *testing.T) {
	d := servicetest.New(t)
	s := &svc{d: d}
	dd := filepath.Join(d.Out, "j1", "SW1_10.0.0.1")
	os.MkdirAll(dd, 0o700)
	os.WriteFile(filepath.Join(dd, "r001.txt"), []byte("===== x ====="), 0o600)
	id := poner(t, s, host("CORE", "10.0.0.1"))
	poner(t, s, host("nuevo", "10.0.0.9"))
	got := lista(t, s, &v1.ListDevicesRequest{})
	if len(got) != 2 {
		t.Fatalf("una sola fila por dirección: %v", got)
	}
	f := got[0]
	if f.Id != id || f.Hostname != "CORE" || f.Name != "CORE" || f.LastSeenMs == 0 || strings.Join(f.Sources, ",") != "flota,manual" {
		t.Fatalf("fusionado = %v", f)
	}
	// borrar el manual no borra la evidencia: vuelve la fila descubierta, sin datos de la libreta
	if _, err := s.DeleteDevice(bg, &v1.DeleteDeviceRequest{Id: id}); err != nil {
		t.Fatal(err)
	}
	got = lista(t, s, &v1.ListDevicesRequest{})
	if len(got) != 2 || got[0].Id != "10.0.0.1" || got[0].Hostname != "SW1" || got[0].Name != "" || strings.Join(got[0].Sources, ",") != "flota" {
		t.Fatalf("tras borrar = %v", got)
	}
	// sin outputs/ la libreta se ve igual, con un aviso; sin libreta sigue siendo el error de siempre
	d2 := servicetest.New(t)
	s2 := &svc{d: d2}
	poner(t, s2, host("solo", "10.0.0.2"))
	r, err := s2.ListDevices(bg, &v1.ListDevicesRequest{})
	if err != nil || len(r.Devices) != 1 || len(r.Warnings) == 0 {
		t.Fatalf("sin outputs: %v %v", r, err)
	}
}

func TestListaFiltraPorCarpetaYEtiqueta(t *testing.T) {
	d := servicetest.New(t)
	s := &svc{d: d}
	os.MkdirAll(d.Out, 0o700)
	poner(t, s, &v1.Device{Name: "a", Target: &v1.Target{Address: "10.0.0.1"}, Folder: "Lab", Tags: []string{"core", "dc-1"}})
	poner(t, s, &v1.Device{Name: "b", Target: &v1.Target{Address: "10.0.0.2"}, Folder: "Oficina", Tags: []string{"acceso"}})
	n := func(r *v1.ListDevicesRequest) int { return len(lista(t, s, r)) }
	if n(&v1.ListDevicesRequest{Folder: "lab"}) != 1 || n(&v1.ListDevicesRequest{Tag: "acceso"}) != 1 || n(&v1.ListDevicesRequest{Folder: "Lab", Tag: "acceso"}) != 0 ||
		n(&v1.ListDevicesRequest{Query: "oficina"}) != 1 || n(&v1.ListDevicesRequest{}) != 2 {
		t.Fatal("filtros")
	}
}

func TestCredencialSoloComoReferencia(t *testing.T) {
	d := servicetest.New(t)
	s := &svc{d: d}
	os.MkdirAll(d.Out, 0o700)
	ok := cred(t, d, "admin lab")
	reservada, err := d.V.Put(vault.Credential{Label: vault.ReservedPrefix + "llave", Username: "x", Password: secret.New([]byte("zzz"))})
	if err != nil {
		t.Fatal(err)
	}
	mk := func(name, id string) *v1.Device {
		h := host(name, "10.0.1."+fmt.Sprint(len(name)))
		h.CredentialId = id
		return h
	}
	// inexistente y reservada se rechazan
	for _, id := range []string{strings.Repeat("0", 32), reservada} {
		_, err := s.PutDevice(bg, &v1.PutDeviceRequest{Device: mk("aa", id)})
		codigo(t, err, codes.InvalidArgument)
	}
	hid := poner(t, s, mk("bbb", ok))
	got := lista(t, s, &v1.ListDevicesRequest{})
	if len(got) != 1 || got[0].CredentialId != ok || got[0].CredentialLabel != "admin lab" {
		t.Fatalf("credencial = %v", got)
	}
	// ningún secreto en la libreta (base) ni en la bitácora
	var todo string
	rows, _ := d.DB().Query(`SELECT id||name||address||platform||folder||tags_json||credential_id||notes FROM hosts`)
	for rows.Next() {
		var l string
		rows.Scan(&l)
		todo += l
	}
	rows.Close()
	todo += d.AuditText()
	for _, sec := range []string{"hunter2-secreto", "enable-secreto", "admin"} {
		if strings.Contains(todo, sec) {
			t.Errorf("aparece %q fuera de la bóveda", sec)
		}
	}
	// con la bóveda cerrada se guarda la referencia sin validar y se avisa; no hay etiqueta que mostrar
	d.V.LockAll()
	r, err := s.PutDevice(bg, &v1.PutDeviceRequest{Device: mk("cccc", strings.Repeat("0", 32))})
	if err != nil || len(r.Warnings) != 1 {
		t.Fatalf("cerrada: %v %v", r, err)
	}
	for _, x := range lista(t, s, &v1.ListDevicesRequest{}) {
		if x.CredentialLabel != "" {
			t.Fatalf("etiqueta con la bóveda cerrada: %v", x)
		}
	}
	// sin bóveda también
	s3 := &svc{d: servicetest.New(t)}
	os.MkdirAll(s3.d.Outputs(), 0o700)
	if r, err := s3.PutDevice(bg, &v1.PutDeviceRequest{Device: mk("dd", strings.Repeat("0", 32))}); err != nil || len(r.Warnings) != 1 {
		t.Fatalf("sin bóveda: %v %v", r, err)
	}
	_ = hid
}

// manual_only devuelve los hosts con sus propios valores: lo descubierto no se cuela (editar no fija la plataforma de Patrol).
func TestManualOnlyNoFusionaConLoDescubierto(t *testing.T) {
	d := servicetest.New(t)
	s := &svc{d: d}
	job := filepath.Join(d.Out, "j1")
	os.MkdirAll(filepath.Join(job, "SW1_10.0.0.1"), 0o700)
	os.WriteFile(filepath.Join(job, "SW1_10.0.0.1", "r001.txt"), []byte("===== x ====="), 0o600)
	os.WriteFile(filepath.Join(job, "manifest.json"), []byte(`{"started_at":"2026-11-06T09:00:00Z","ended_at":"2026-11-06T09:00:00Z","devices":[{"Target":{"Address":"10.0.0.1"},"Hostname":"SW1","Platform":"ios-xe","State":"completed"}]}`), 0o600)
	id := poner(t, s, &v1.Device{Name: "ñandú", Target: &v1.Target{Address: "10.0.0.1"}, Notes: "uno"})
	poner(t, s, &v1.Device{Name: "Ñu", Target: &v1.Target{Address: "10.0.0.7"}, Platform: "nx-os", Tags: []string{"a"}})

	merged := lista(t, s, &v1.ListDevicesRequest{})
	if merged[0].Platform != "ios-xe" || merged[0].LastSeenMs == 0 {
		t.Fatalf("la lista fusionada sigue igual: %v", merged[0])
	}
	got := lista(t, s, &v1.ListDevicesRequest{ManualOnly: true})
	if len(got) != 2 {
		t.Fatalf("manual_only = %v", got)
	}
	// orden por nombre sin importar mayúsculas de Unicode (el de SQLite no junta «ñ» y «Ñ»)
	if got[0].Name != "ñandú" || got[1].Name != "Ñu" {
		t.Fatalf("orden = %s, %s", got[0].Name, got[1].Name)
	}
	if h := got[0]; h.Id != id || h.Platform != "" || h.LastSeenMs != 0 || strings.Join(h.Sources, ",") != "manual" || h.Target.Address != "10.0.0.1" || h.Profile.Port != 22 || h.Notes != "uno" {
		t.Fatalf("host = %v (nada de lo descubierto)", h)
	}
	// editar otra cosa a partir de esa lectura no fija la plataforma descubierta
	h := got[0]
	h.Notes = "dos"
	if _, err := s.PutDevice(bg, &v1.PutDeviceRequest{Device: h}); err != nil {
		t.Fatal(err)
	}
	if g, err := getHost(d.DB(), id); err != nil || g.Platform != "" || g.Notes != "dos" {
		t.Fatalf("guardado = %+v err = %v", g, err)
	}
	// el texto busca solo en los valores del host: «ios-xe» es de Patrol, «nx-os» del host
	n := func(r *v1.ListDevicesRequest) int { r.ManualOnly = true; return len(lista(t, s, r)) }
	if n(&v1.ListDevicesRequest{Query: "ios-xe"}) != 0 || n(&v1.ListDevicesRequest{Query: "nx-os"}) != 1 || n(&v1.ListDevicesRequest{Query: "sw1"}) != 0 || n(&v1.ListDevicesRequest{Tag: "a"}) != 1 {
		t.Fatal("filtros de manual_only")
	}
	// sin outputs/ también funciona y no avisa
	d2 := servicetest.New(t)
	s2 := &svc{d: d2}
	poner(t, s2, host("solo", "10.0.0.2"))
	if r, err := s2.ListDevices(bg, &v1.ListDevicesRequest{ManualOnly: true}); err != nil || len(r.Devices) != 1 || len(r.Warnings) != 0 {
		t.Fatalf("sin outputs: %v %v", r, err)
	}
	if r, err := (&svc{d: servicetest.New(t)}).ListDevices(bg, &v1.ListDevicesRequest{ManualOnly: true}); err != nil || len(r.Devices) != 0 {
		t.Fatalf("libreta vacía sin outputs: %v %v", r, err)
	}
}
