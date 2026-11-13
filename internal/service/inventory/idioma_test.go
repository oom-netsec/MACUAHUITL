package inventory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Fase 30e: la libreta, los import y los avisos salen en el idioma pedido; con es, el texto de siempre.
func TestLibretaIdiomaCierre(t *testing.T) {
	s, _ := nuevoSvc(t)
	poner(t, s, &v1.Device{Name: "SW-1", Target: &v1.Target{Address: "10.0.0.1"}})
	dir := t.TempDir()
	csvMalo := filepath.Join(dir, "m.csv")
	os.WriteFile(csvMalo, []byte("name,address,port,platform,folder,tags,credential_label,notes\nSW-X,10.0.0.9,x,,,,,\nSW-Y,10.0.0.8,1,,,,,\n"), 0o600)
	jsonSinSuma := filepath.Join(dir, "s.json")
	os.WriteFile(jsonSinSuma, []byte(`{"formato":"macuahuitl-hosts","version":1,"exportado":"x","hosts":[{"name":"a","address":"10.0.0.7"}]}`), 0o600)
	raro := filepath.Join(dir, "r.txt")
	os.WriteFile(raro, []byte("x"), 0o600)
	noHosts := filepath.Join(dir, "n.json")
	os.WriteFile(noHosts, []byte(`{"formato":"otro","version":1}`), 0o600)

	cases := []struct {
		name, es, en string
		call         func(ctx context.Context) string
	}{
		{"nombre repetido", `ya hay un host llamado "SW-1"`, `there is already a host named "SW-1"`, func(ctx context.Context) string {
			_, err := s.PutDevice(ctx, &v1.PutDeviceRequest{Device: &v1.Device{Name: "sw-1", Target: &v1.Target{Address: "10.0.0.5"}}})
			return status.Convert(err).Message()
		}},
		{"destino repetido", `"10.0.0.1:22" ya está en la libreta como "SW-1"`, `"10.0.0.1:22" is already in the address book as "SW-1"`, func(ctx context.Context) string {
			_, err := s.PutDevice(ctx, &v1.PutDeviceRequest{Device: &v1.Device{Name: "otro", Target: &v1.Target{Address: "10.0.0.1"}}})
			return status.Convert(err).Message()
		}},
		{"campo inválido", "el puerto va de 1 a 65535", "the port must be between 1 and 65535", func(ctx context.Context) string {
			_, err := s.PutDevice(ctx, &v1.PutDeviceRequest{Device: &v1.Device{Name: "z", Target: &v1.Target{Address: "10.0.0.6"}, Profile: &v1.DeviceProfile{Port: 70000}}})
			return status.Convert(err).Message()
		}},
		{"dirección inválida", `dirección "a@b": use una IP o un nombre DNS (letras, números y guiones), sin espacios, @, esquema, puerto ni ruta`,
			`address "a@b": use an IP or a DNS name (letters, digits and hyphens), without spaces, @, scheme, port or path`, func(ctx context.Context) string {
				_, err := s.PutDevice(ctx, &v1.PutDeviceRequest{Device: &v1.Device{Name: "z", Target: &v1.Target{Address: "a@b"}}})
				return status.Convert(err).Message()
			}},
		{"id inexistente", `no hay un host de la libreta con id "zz"`, `there is no address-book host with id "zz"`, func(ctx context.Context) string {
			_, err := s.DeleteDevice(ctx, &v1.DeleteDeviceRequest{Id: "zz"})
			return status.Convert(err).Message()
		}},
		{"formato no reconocido", `formato no reconocido para "` + raro + `": use la extensión .csv o .json, o pida el formato csv o json`,
			`unrecognized format for "` + raro + `": use the .csv or .json extension, or ask for the csv or json format`, func(ctx context.Context) string {
				_, err := s.PreviewImportHosts(ctx, &v1.PreviewImportHostsRequest{Path: raro})
				return status.Convert(err).Message()
			}},
		{"archivo ajeno", `formato "otro": se esperaba "macuahuitl-hosts"`, `format "otro": expected "macuahuitl-hosts"`, func(ctx context.Context) string {
			_, err := s.PreviewImportHosts(ctx, &v1.PreviewImportHostsRequest{Path: noHosts})
			return status.Convert(err).Message()
		}},
		{"errores por fila", `"x" no es un número entero`, `"x" is not an integer`, func(ctx context.Context) string {
			p, err := s.PreviewImportHosts(ctx, &v1.PreviewImportHostsRequest{Path: csvMalo})
			if err != nil || len(p.Errors) != 1 {
				t.Fatalf("%v %v", p, err)
			}
			return p.Errors[0].Reason
		}},
		{"aviso sin suma", "archivo sin suma de verificación: nada comprueba que no esté dañado o modificado; revisa su contenido",
			"file without a checksum: nothing verifies that it is not damaged or modified; review its contents", func(ctx context.Context) string {
				p, err := s.PreviewImportHosts(ctx, &v1.PreviewImportHostsRequest{Path: jsonSinSuma})
				if err != nil || len(p.Warnings) == 0 {
					t.Fatalf("%v %v", p, err)
				}
				return p.Warnings[0]
			}},
		{"decisión repetida", "decisión repetida para 10.0.0.7:22", "repeated decision for 10.0.0.7:22", func(ctx context.Context) string {
			p, _ := s.PreviewImportHosts(ctx, &v1.PreviewImportHostsRequest{Path: jsonSinSuma})
			_, err := s.ApplyImportHosts(ctx, &v1.ApplyImportHostsRequest{Token: p.Token, Decisions: []*v1.ImportHostDecision{{Key: "10.0.0.7:22", Action: "omitir"}, {Key: "10.0.0.7:22", Action: "omitir"}}})
			return status.Convert(err).Message()
		}},
		{"decisión desconocida", `decisión "x" desconocida para 10.0.0.7:22`, `unknown decision "x" for 10.0.0.7:22`, func(ctx context.Context) string {
			p, _ := s.PreviewImportHosts(ctx, &v1.PreviewImportHostsRequest{Path: jsonSinSuma})
			_, err := s.ApplyImportHosts(ctx, &v1.ApplyImportHostsRequest{Token: p.Token, Decisions: []*v1.ImportHostDecision{{Key: "10.0.0.7:22", Action: "x"}}})
			return status.Convert(err).Message()
		}},
	}
	for _, c := range cases {
		for loc, want := range map[string]string{"es": c.es, "en": c.en} {
			if got := c.call(i18n.WithLocale(context.Background(), loc)); got != want {
				t.Errorf("%s %s: %q, quería %q", c.name, loc, got, want)
			}
		}
	}
}

// Los avisos de la lista de equipos (carpeta ilegible) también siguen el idioma.
func TestListaDeEquiposAvisosEnIngles(t *testing.T) {
	s, d := nuevoSvc(t)
	os.MkdirAll(filepath.Join(d.Out, "job1"), 0o700)
	os.WriteFile(filepath.Join(d.Out, "job1", "manifest.json"), []byte("{no"), 0o600)
	for loc, want := range map[string]string{"es": "job1/manifest.json ilegible: ", "en": "job1/manifest.json unreadable: "} {
		r, err := s.ListDevices(i18n.WithLocale(context.Background(), loc), &v1.ListDevicesRequest{})
		if err != nil || len(r.Warnings) != 1 || !strings.HasPrefix(r.Warnings[0], want) {
			t.Errorf("%s: %v %v", loc, r, err)
		}
	}
}
