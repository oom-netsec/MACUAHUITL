package inventory

import (
	"database/sql"
	"fmt"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// invariante: todo hosts.folder no vacío existe en host_folders con el mismo texto exacto.
func invariante(t *testing.T, d interface{ DB() *sql.DB }) {
	t.Helper()
	var bad string
	err := d.DB().QueryRow(`SELECT COALESCE(group_concat(h.name || ':' || h.folder), '') FROM hosts h
		WHERE h.folder <> '' AND NOT EXISTS (SELECT 1 FROM host_folders f WHERE f.name = h.folder AND CAST(f.name AS BLOB) = CAST(h.folder AS BLOB))`).Scan(&bad)
	if err != nil || bad != "" {
		t.Fatalf("invariante roto: %q %v", bad, err)
	}
}

func carpetas(t *testing.T, s *svc) map[string]int32 {
	t.Helper()
	r, err := s.ListHostFolders(bg, &v1.ListHostFoldersRequest{})
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]int32{}
	for _, f := range r.Folders {
		m[f.Name] = f.HostCount
	}
	return m
}

func carpetaDe(t *testing.T, s *svc, id string) string {
	t.Helper()
	for _, x := range lista(t, s, &v1.ListDevicesRequest{ManualOnly: true}) {
		if x.Id == id {
			return x.Folder
		}
	}
	t.Fatalf("no hay host %s", id)
	return ""
}

func TestCarpetasCrearListarYRechazos(t *testing.T) {
	s, d := nuevoSvc(t)
	r, err := s.CreateHostFolder(bg, &v1.CreateHostFolderRequest{Name: "Lab"})
	if err != nil || r.Folder.Name != "Lab" || r.Folder.HostCount != 0 {
		t.Fatalf("create: %v %v", r, err)
	}
	_, err = s.CreateHostFolder(bg, &v1.CreateHostFolderRequest{Name: "lab"})
	codigo(t, err, codes.AlreadyExists)
	for _, n := range []string{"", " x", "a/b", strings.Repeat("a", 49)} {
		_, err = s.CreateHostFolder(bg, &v1.CreateHostFolderRequest{Name: n})
		codigo(t, err, codes.InvalidArgument)
	}
	poner(t, s, &v1.Device{Name: "a", Target: &v1.Target{Address: "10.0.0.1"}, Folder: "lab"})
	if m := carpetas(t, s); len(m) != 1 || m["Lab"] != 1 {
		t.Fatalf("carpetas = %v", m)
	}
	if !strings.Contains(d.AuditText(), "hostfolder.create") || !strings.Contains(d.AuditText(), "origin=user") {
		t.Fatalf("auditoría:\n%s", d.AuditText())
	}
	invariante(t, d)
}

func TestCarpetasTopeDe1000(t *testing.T) {
	s, d := nuevoSvc(t)
	for i := 0; i < maxFolders; i++ {
		if _, err := d.DB().Exec(`INSERT INTO host_folders VALUES(?, 't')`, fmt.Sprint("f", i)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := s.CreateHostFolder(bg, &v1.CreateHostFolderRequest{Name: "una mas"})
	codigo(t, err, codes.ResourceExhausted)
	_, err = s.PutDevice(bg, &v1.PutDeviceRequest{Device: &v1.Device{Name: "a", Target: &v1.Target{Address: "10.0.0.1"}, Folder: "otra"}})
	codigo(t, err, codes.ResourceExhausted)
	// una existente no cuenta contra el tope
	if _, err = s.PutDevice(bg, &v1.PutDeviceRequest{Device: &v1.Device{Name: "a", Target: &v1.Target{Address: "10.0.0.1"}, Folder: "F7"}}); err != nil {
		t.Fatal(err)
	}
}

func TestRenombrarMueveHostsYRechazaOtraExistente(t *testing.T) {
	s, d := nuevoSvc(t)
	a := poner(t, s, &v1.Device{Name: "a", Target: &v1.Target{Address: "10.0.0.1"}, Folder: "Lab"})
	b := poner(t, s, &v1.Device{Name: "b", Target: &v1.Target{Address: "10.0.0.2"}, Folder: "Lab"})
	c := poner(t, s, &v1.Device{Name: "c", Target: &v1.Target{Address: "10.0.0.3"}, Folder: "Otra"})
	r, err := s.RenameHostFolder(bg, &v1.RenameHostFolderRequest{Name: "LAB", NewName: "Core"})
	if err != nil || r.Folder.Name != "Core" || r.Folder.HostCount != 2 {
		t.Fatalf("rename: %v %v", r, err)
	}
	if carpetaDe(t, s, a) != "Core" || carpetaDe(t, s, b) != "Core" || carpetaDe(t, s, c) != "Otra" {
		t.Fatal("los hosts no se movieron con la carpeta")
	}
	invariante(t, d)
	// a otra que existe (aunque sea con otras mayúsculas): no se fusiona
	_, err = s.RenameHostFolder(bg, &v1.RenameHostFolderRequest{Name: "Core", NewName: "otra"})
	codigo(t, err, codes.AlreadyExists)
	if m := carpetas(t, s); m["Core"] != 2 || m["Otra"] != 1 || len(m) != 2 {
		t.Fatalf("nada debía cambiar: %v", m)
	}
	_, err = s.RenameHostFolder(bg, &v1.RenameHostFolderRequest{Name: "nada", NewName: "x"})
	codigo(t, err, codes.NotFound)
	_, err = s.RenameHostFolder(bg, &v1.RenameHostFolderRequest{Name: "Core", NewName: " mal"})
	codigo(t, err, codes.InvalidArgument)
	// solo mayúsculas
	if r, err = s.RenameHostFolder(bg, &v1.RenameHostFolderRequest{Name: "Core", NewName: "CORE"}); err != nil || r.Folder.Name != "CORE" || r.Folder.HostCount != 2 {
		t.Fatalf("solo mayúsculas: %v %v", r, err)
	}
	if carpetaDe(t, s, a) != "CORE" {
		t.Fatalf("host = %q", carpetaDe(t, s, a))
	}
	invariante(t, d)
	if !strings.Contains(d.AuditText(), "hostfolder.rename") || !strings.Contains(d.AuditText(), `to=\"Core\" hosts=2`) {
		t.Fatalf("auditoría:\n%s", d.AuditText())
	}
}

func TestBorrarCarpetaPideConfirmSiTieneHosts(t *testing.T) {
	s, d := nuevoSvc(t)
	a := poner(t, s, &v1.Device{Name: "a", Target: &v1.Target{Address: "10.0.0.1"}, Folder: "Lab"})
	poner(t, s, &v1.Device{Name: "b", Target: &v1.Target{Address: "10.0.0.2"}, Folder: "lab"})
	_, err := s.DeleteHostFolder(bg, &v1.DeleteHostFolderRequest{Name: "lab"})
	codigo(t, err, codes.FailedPrecondition)
	if i := infoOf(err); i == nil || i.Reason != "hosts.err.folder_not_empty" || i.Metadata["host_count"] != "2" || i.Metadata["name"] != "Lab" {
		t.Fatalf("info = %+v", i)
	}
	if m := carpetas(t, s); m["Lab"] != 2 || carpetaDe(t, s, a) != "Lab" {
		t.Fatalf("nada debía cambiar: %v", m)
	}
	r, err := s.DeleteHostFolder(bg, &v1.DeleteHostFolderRequest{Name: "lab", Confirm: true})
	if err != nil || r.HostsUnfiled != 2 {
		t.Fatalf("delete: %v %v", r, err)
	}
	if len(carpetas(t, s)) != 0 || carpetaDe(t, s, a) != "" || len(lista(t, s, &v1.ListDevicesRequest{ManualOnly: true})) != 2 {
		t.Fatal("los hosts debían seguir, sin carpeta")
	}
	invariante(t, d)
	// vacía: sin confirm basta
	s.CreateHostFolder(bg, &v1.CreateHostFolderRequest{Name: "vacia"})
	if r, err = s.DeleteHostFolder(bg, &v1.DeleteHostFolderRequest{Name: "VACIA"}); err != nil || r.HostsUnfiled != 0 {
		t.Fatalf("vacía: %v %v", r, err)
	}
	_, err = s.DeleteHostFolder(bg, &v1.DeleteHostFolderRequest{Name: "vacia"})
	codigo(t, err, codes.NotFound)
	if !strings.Contains(d.AuditText(), "hostfolder.delete") || !strings.Contains(d.AuditText(), "unfiled=2") {
		t.Fatalf("auditoría:\n%s", d.AuditText())
	}
}

func TestMoveHostsTodoONadaYCreaLaCarpeta(t *testing.T) {
	s, d := nuevoSvc(t)
	a := poner(t, s, &v1.Device{Name: "a", Target: &v1.Target{Address: "10.0.0.1"}})
	b := poner(t, s, &v1.Device{Name: "b", Target: &v1.Target{Address: "10.0.0.2"}, Folder: "Nueva"})
	_, err := s.MoveHosts(bg, &v1.MoveHostsRequest{Ids: []string{a, "falso"}, Folder: "Destino"})
	codigo(t, err, codes.NotFound)
	if carpetaDe(t, s, a) != "" || len(carpetas(t, s)) != 1 {
		t.Fatalf("un id falso no debía mover ni crear nada: %v", carpetas(t, s))
	}
	for _, ids := range [][]string{nil, make([]string, 5001)} {
		_, err = s.MoveHosts(bg, &v1.MoveHostsRequest{Ids: ids, Folder: "x"})
		codigo(t, err, codes.InvalidArgument)
	}
	_, err = s.MoveHosts(bg, &v1.MoveHostsRequest{Ids: []string{a}, Folder: "mal/"})
	codigo(t, err, codes.InvalidArgument)
	r, err := s.MoveHosts(bg, &v1.MoveHostsRequest{Ids: []string{a, b, a}, Folder: "nueva"})
	if err != nil || r.Moved != 1 || r.FolderCreated || carpetaDe(t, s, a) != "Nueva" {
		t.Fatalf("a una existente con otras mayúsculas: %v %v", r, err)
	}
	if r, err = s.MoveHosts(bg, &v1.MoveHostsRequest{Ids: []string{a, b}, Folder: "Destino"}); err != nil || r.Moved != 2 || !r.FolderCreated {
		t.Fatalf("a una nueva: %v %v", r, err)
	}
	if r, err = s.MoveHosts(bg, &v1.MoveHostsRequest{Ids: []string{a}, Folder: ""}); err != nil || r.Moved != 1 || carpetaDe(t, s, a) != "" {
		t.Fatalf("sin carpeta: %v %v", r, err)
	}
	if m := carpetas(t, s); m["Nueva"] != 0 || m["Destino"] != 1 {
		t.Fatalf("carpetas = %v", m)
	}
	invariante(t, d)
	if au := d.AuditText(); !strings.Contains(au, "hosts.move") || !strings.Contains(au, "origin=move") || !strings.Contains(au, "n=2 ids=") {
		t.Fatalf("auditoría:\n%s", au)
	}
}

func TestPutDeviceCreaLaCarpetaYTomaElNombreGuardado(t *testing.T) {
	s, d := nuevoSvc(t)
	a := poner(t, s, &v1.Device{Name: "a", Target: &v1.Target{Address: "10.0.0.1"}, Folder: "Lab"})
	b := poner(t, s, &v1.Device{Name: "b", Target: &v1.Target{Address: "10.0.0.2"}, Folder: "LAB"})
	if carpetaDe(t, s, a) != "Lab" || carpetaDe(t, s, b) != "Lab" || len(carpetas(t, s)) != 1 {
		t.Fatalf("carpetas = %v", carpetas(t, s))
	}
	invariante(t, d)
	if n := strings.Count(d.AuditText(), "origin=put"); n != 1 {
		t.Fatalf("hostfolder.create origin=put x%d", n)
	}
}

func TestImportConCarpetaNuevaLaCreaUnaVez(t *testing.T) {
	s, _ := nuevoSvc(t)
	poner(t, s, &v1.Device{Name: "a", Target: &v1.Target{Address: "10.0.0.1"}, Folder: "Nueva"})
	poner(t, s, &v1.Device{Name: "b", Target: &v1.Target{Address: "10.0.0.2"}, Folder: "nueva"})
	poner(t, s, &v1.Device{Name: "c", Target: &v1.Target{Address: "10.0.0.3"}})
	path := filepath.Join(t.TempDir(), "h.json")
	if _, err := s.ExportHosts(bg, &v1.ExportHostsRequest{Path: path}); err != nil {
		t.Fatal(err)
	}
	s2, d2 := nuevoSvc(t)
	p, err := s2.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	a, err := s2.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token})
	if err != nil || a.Created != 3 || a.FoldersCreated != 1 {
		t.Fatalf("apply: %v %v", a, err)
	}
	if m := carpetas(t, s2); len(m) != 1 || m["Nueva"] != 2 {
		t.Fatalf("carpetas = %v", m)
	}
	invariante(t, d2)
	if n := strings.Count(d2.AuditText(), "origin=import"); n != 1 {
		t.Fatalf("hostfolder.create origin=import x%d", n)
	}
	// otra vez el mismo archivo: la carpeta ya existe, no se crea de nuevo
	p, _ = s2.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
	if a, err = s2.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token}); err != nil || a.FoldersCreated != 0 {
		t.Fatalf("segunda vez: %v %v", a, err)
	}
}

// Secuencias al azar (semilla fija) de todas las operaciones: tras cada una vale el invariante y la cuenta de
// cada carpeta es la de los hosts que la nombran.
func TestCarpetasInvarianteConSecuenciasAlAzar(t *testing.T) {
	nombres := []string{"Lab", "lab", "LAB", "Core", "core", "Edge", "A b", "x.y"}
	for seed := int64(1); seed <= 5; seed++ {
		s, d := nuevoSvc(t)
		rng := rand.New(rand.NewSource(seed))
		var ids []string
		next := 0
		pick := func() string { return nombres[rng.Intn(len(nombres))] }
		for step := 0; step < 120; step++ {
			switch rng.Intn(7) {
			case 0:
				n := next
				next++
				r, err := s.PutDevice(bg, &v1.PutDeviceRequest{Device: &v1.Device{Name: fmt.Sprint("h", seed, "-", step), Target: &v1.Target{Address: fmt.Sprintf("10.%d.%d.1", n/250, n%250)}, Folder: []string{"", pick()}[rng.Intn(2)]}})
				if err != nil {
					t.Fatal(err)
				}
				ids = append(ids, r.Id)
			case 1:
				s.CreateHostFolder(bg, &v1.CreateHostFolderRequest{Name: pick()})
			case 2:
				s.RenameHostFolder(bg, &v1.RenameHostFolderRequest{Name: pick(), NewName: pick()})
			case 3:
				s.DeleteHostFolder(bg, &v1.DeleteHostFolderRequest{Name: pick(), Confirm: rng.Intn(2) == 0})
			case 4:
				if len(ids) > 0 {
					sel := []string{ids[rng.Intn(len(ids))], ids[rng.Intn(len(ids))]}
					if rng.Intn(6) == 0 {
						sel = append(sel, "falso")
					}
					s.MoveHosts(bg, &v1.MoveHostsRequest{Ids: sel, Folder: []string{"", pick()}[rng.Intn(2)]})
				}
			case 5:
				if len(ids) > 0 {
					i := rng.Intn(len(ids))
					s.DeleteDevice(bg, &v1.DeleteDeviceRequest{Id: ids[i]})
					ids = append(ids[:i], ids[i+1:]...)
				}
			case 6:
				if len(ids) > 0 { // editar un host existente cambiando su carpeta
					id := ids[rng.Intn(len(ids))]
					for _, x := range lista(t, s, &v1.ListDevicesRequest{ManualOnly: true}) {
						if x.Id == id {
							x.Folder = pick()
							if _, err := s.PutDevice(bg, &v1.PutDeviceRequest{Device: x}); err != nil {
								t.Fatal(err)
							}
						}
					}
				}
			}
			invariante(t, d)
			cuenta := map[string]int32{}
			for _, x := range lista(t, s, &v1.ListDevicesRequest{ManualOnly: true}) {
				if x.Folder != "" {
					cuenta[x.Folder]++
				}
			}
			for n, c := range carpetas(t, s) {
				if cuenta[n] != c {
					t.Fatalf("semilla %d paso %d: %q cuenta %d, hosts %d", seed, step, n, c, cuenta[n])
				}
				delete(cuenta, n)
			}
			if len(cuenta) != 0 {
				t.Fatalf("semilla %d paso %d: hosts en carpetas que no existen: %v", seed, step, cuenta)
			}
		}
	}
}
