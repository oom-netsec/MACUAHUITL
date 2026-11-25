package inventory

import (
	"context"
	"database/sql"
	"errors"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

func generico(name, addr, plat, orden string) *v1.Device {
	return &v1.Device{Name: name, Target: &v1.Target{Address: addr}, Platform: plat, StartupCommand: orden}
}

func llave(t *testing.T, d *servicetest.Deps, label string) string {
	t.Helper()
	if d.V == nil {
		d.CreateVault()
	}
	id, _, err := d.V.GenerateKey(label, "zylant-ai")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestOrdenDeInicioIdaYVueltaYAuditoria(t *testing.T) {
	s, d := nuevoSvc(t)
	id := poner(t, s, generico("zylant-box", "192.168.3.69", "windows", "wsl -d Ubuntu-26.04 --cd ~"))
	poner(t, s, generico("pi-panel", "192.168.3.61", "linux", ""))
	var got *v1.Device
	for _, x := range lista(t, s, &v1.ListDevicesRequest{}) {
		if x.Name == "zylant-box" {
			got = x
		}
	}
	if got == nil || got.StartupCommand != "wsl -d Ubuntu-26.04 --cd ~" || got.Platform != "windows" {
		t.Fatalf("host = %v", got)
	}
	// editar conserva y cambia la orden
	e := generico("zylant-box", "192.168.3.69", "windows", "cmd")
	e.Id = id
	poner(t, s, e)
	au := d.AuditText()
	if !strings.Contains(au, "platform=windows") || !strings.Contains(au, "startup=set") || strings.Contains(au, "Ubuntu-26.04") || strings.Contains(au, `startup=\"`) {
		t.Fatalf("auditoría:\n%s", au)
	}
	if strings.Contains(au, "pi-panel 192.168.3.61:22 platform=linux startup") {
		t.Fatal("sin orden no hay startup=")
	}
}

func TestPutDeviceOrdenInvalidaTrae(t *testing.T) {
	s, _ := nuevoSvc(t)
	ctx := i18n.WithLocale(context.Background(), "en")
	for nombre, d := range map[string]*v1.Device{
		"control":        generico("a", "10.0.0.1", "linux", "ls\nid"),
		"bidi":           generico("a", "10.0.0.1", "linux", "ls \u202e"),
		"largo":          generico("a", "10.0.0.1", "linux", strings.Repeat("é", 257)),
		"en un cisco":    generico("a", "10.0.0.1", "ios-xe", "show version"),
		"sin plataforma": generico("a", "10.0.0.1", "", "id"),
	} {
		_, err := s.PutDevice(ctx, &v1.PutDeviceRequest{Device: d})
		codigo(t, err, codes.InvalidArgument)
		if i := infoOf(err); i == nil || i.Metadata["field"] != "startup_command" {
			t.Errorf("%s: %v -> %+v", nombre, err, i)
		}
	}
	_, err := s.PutDevice(ctx, &v1.PutDeviceRequest{Device: generico(" x", "10.0.0.1", "linux", "")})
	if i := infoOf(err); i == nil || i.Metadata["field"] != "name" {
		t.Errorf("name: %v", err)
	}
}

func TestCredencialKeySoloEnGenericos(t *testing.T) {
	s, d := nuevoSvc(t)
	k := llave(t, d, "mi llave")
	pw := cred(t, d, "clave")
	ctx := i18n.WithLocale(context.Background(), "en")
	con := func(plat, id string) *v1.Device {
		x := generico("h", "10.0.0.5", plat, "")
		x.CredentialId = id
		return x
	}
	for _, plat := range []string{"ios-xe", "", "ios"} {
		_, err := s.PutDevice(ctx, &v1.PutDeviceRequest{Device: con(plat, k)})
		codigo(t, err, codes.InvalidArgument)
		if i := infoOf(err); i == nil || i.Reason != "hosts.key_credential_platform" || i.Metadata["field"] != "credential_id" {
			t.Errorf("plataforma %q: %v -> %+v", plat, err, i)
		}
	}
	// con contraseña, en un Cisco: como siempre
	poner(t, s, con("ios-xe", pw))
	// una key en linux/windows entra
	id1 := poner(t, s, func() *v1.Device { x := con("linux", k); x.Name, x.Target.Address = "l", "10.0.0.6"; return x }())
	// cambiar a Cisco el host linux con key falla
	x := con("ios-xe", k)
	x.Id, x.Name, x.Target.Address = id1, "l", "10.0.0.6"
	_, err := s.PutDevice(ctx, &v1.PutDeviceRequest{Device: x})
	codigo(t, err, codes.InvalidArgument)
	// con la bóveda cerrada no se sabe el tipo: entra con el aviso de hoy
	d.V.LockAll()
	r, err := s.PutDevice(ctx, &v1.PutDeviceRequest{Device: func() *v1.Device { y := con("ios-xe", k); y.Name, y.Target.Address = "c", "10.0.0.7"; return y }()})
	if err != nil || len(r.Warnings) != 1 {
		t.Fatalf("bóveda cerrada: %v %v", r, err)
	}
}

func TestImportaConOrdenYViejoSigueEntrando(t *testing.T) {
	s, _ := nuevoSvc(t)
	poner(t, s, generico("box", "10.0.0.2", "windows", "wsl -d Ubuntu-26.04 --cd ~"))
	poner(t, s, host("sw", "10.0.0.3"))
	dir := t.TempDir()
	for _, ext := range []string{"json", "csv"} {
		path := filepath.Join(dir, "h."+ext)
		if _, err := s.ExportHosts(bg, &v1.ExportHostsRequest{Path: path}); err != nil {
			t.Fatal(err)
		}
		s2, _ := nuevoSvc(t)
		p, err := s2.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
		if err != nil || len(p.Items) != 2 || len(p.Errors) != 0 {
			t.Fatalf("%s preview: %v %v", ext, p, err)
		}
		for _, it := range p.Items {
			con := it.Host.Name == "box"
			if it.HasStartupCommand != con || (con && it.Host.StartupCommand != "wsl -d Ubuntu-26.04 --cd ~") {
				t.Errorf("%s: %v", ext, it)
			}
		}
		if _, err := s2.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token}); err != nil {
			t.Fatal(err)
		}
		for _, x := range lista(t, s2, &v1.ListDevicesRequest{}) {
			if x.Name == "box" && x.StartupCommand == "" {
				t.Errorf("%s: la orden no llegó", ext)
			}
		}
		// «igual» compara la orden: la misma libreta es igual; con otra orden es conflicto
		s2.PutDevice(bg, &v1.PutDeviceRequest{Device: func() *v1.Device {
			for _, x := range lista(t, s2, &v1.ListDevicesRequest{}) {
				if x.Name == "box" {
					x.StartupCommand = "cmd"
					return x
				}
			}
			return nil
		}()})
		p2, _ := s2.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
		for _, it := range p2.Items {
			if it.Host.Name == "box" && it.State != "conflicto" {
				t.Errorf("%s: orden distinta debe ser conflicto: %v", ext, it)
			}
		}
	}
	// un CSV de antes (8 columnas) entra
	viejo := filepath.Join(dir, "viejo.csv")
	os.WriteFile(viejo, []byte("name,address,port,platform,folder,tags,credential_label,notes\nsw9,10.0.0.9,22,ios,,,,\n"), 0o600)
	s3, _ := nuevoSvc(t)
	p, err := s3.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: viejo})
	if err != nil || len(p.Items) != 1 || len(p.Errors) != 0 {
		t.Fatalf("viejo: %v %v", p, err)
	}
	// una fila con orden inválida sale en errors con su campo
	malo := filepath.Join(dir, "malo.csv")
	os.WriteFile(malo, []byte("name,address,port,platform,folder,tags,credential_label,notes,startup_command\nx,10.0.0.9,22,ios-xe,,,,,show version\n"), 0o600)
	p, err = s3.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: malo})
	if err != nil || len(p.Errors) != 1 || p.Errors[0].Field != "startup_command" {
		t.Fatalf("malo: %v %v", p, err)
	}
}

func TestImportRechazaKeyEnCisco(t *testing.T) {
	s, d := nuevoSvc(t)
	llave(t, d, "mi llave")
	dir := t.TempDir()
	path := filepath.Join(dir, "h.csv")
	os.WriteFile(path, []byte("name,address,port,platform,folder,tags,credential_label,notes,startup_command\nsw,10.0.0.9,22,ios-xe,,,mi llave,,\nlin,10.0.0.8,22,linux,,,mi llave,,\n"), 0o600)
	p, err := s.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token})
	codigo(t, err, codes.InvalidArgument)
	if i := infoOf(err); i == nil || i.Reason != "hosts.key_credential_platform" || i.Metadata["field"] != "credential_id" {
		t.Fatalf("%v -> %+v", err, i)
	}
	if n := len(lista(t, s, &v1.ListDevicesRequest{})); n != 0 {
		t.Fatalf("no debía quedar nada, hay %d", n)
	}
	// el token se devuelve para corregir; con la plataforma bien, entra
	os.WriteFile(path, []byte("name,address,port,platform,folder,tags,credential_label,notes,startup_command\nlin,10.0.0.8,22,linux,,,mi llave,,\n"), 0o600)
	p, _ = s.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: path})
	if a, err := s.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token}); err != nil || a.Created != 1 {
		t.Fatalf("%v %v", a, err)
	}
}

func TestGenericHostAtYSavedHost(t *testing.T) {
	s, d := nuevoSvc(t)
	id := poner(t, s, generico("Box", "192.168.3.69", "windows", "cmd"))
	poner(t, s, &v1.Device{Name: "v6", Target: &v1.Target{Address: "2001:DB8::1"}, Platform: "linux"})
	poner(t, s, host("sw", "10.0.0.3"))
	for _, c := range []struct {
		addr  string
		port  int
		name  string
		platf string
		ok    bool
	}{
		{"192.168.3.69", 0, "Box", "windows", true},
		{"192.168.3.69", 22, "Box", "windows", true},
		{"::ffff:192.168.3.69", 22, "Box", "windows", true}, // IPv4 mapeada
		{"2001:db8::1", 22, "v6", "linux", true},
		{"2001:DB8:0::1", 22, "v6", "linux", true},
		{"10.0.0.3", 22, "sw", "ios-xe", false}, // existe pero es Cisco
		{"192.168.3.69", 2222, "", "", false},
		{"10.9.9.9", 22, "", "", false},
	} {
		name, plat, ok, err := service.GenericHostAt(d.DB(), c.addr, c.port)
		if err != nil || name != c.name || plat != c.platf || ok != c.ok {
			t.Errorf("%s:%d -> %q %q %v %v", c.addr, c.port, name, plat, ok, err)
		}
	}
	h, err := service.SavedHost(d.DB(), id)
	if err != nil || h.Name != "Box" || h.StartupCommand != "cmd" || h.Port != 22 || h.Address != "192.168.3.69" {
		t.Fatalf("%+v %v", h, err)
	}
	if _, err := service.SavedHost(d.DB(), "nope"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("err = %v", err)
	}
}
