package inventory

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

func infoOf(err error) *errdetails.ErrorInfo {
	for _, d := range status.Convert(err).Details() {
		if i, ok := d.(*errdetails.ErrorInfo); ok {
			return i
		}
	}
	return nil
}

func dev(name, addr string) *v1.Device {
	return &v1.Device{Name: name, Target: &v1.Target{Address: addr}}
}

// Contrato para front: cada rechazo trae reason estable y metadata.field (nombre del formulario); en duplicados, el id del existente.
func TestPutDeviceRechazosConReasonYCampo(t *testing.T) {
	s := &svc{d: servicetest.New(t)}
	ctx := i18n.WithLocale(context.Background(), "en")
	first, err := s.PutDevice(ctx, &v1.PutDeviceRequest{Device: dev("sw1", "10.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	long := dev("sw2", "10.0.0.2")
	long.Notes = string(make([]byte, 5000))
	bad := func(d *v1.Device, f func(*v1.Device)) *v1.Device { f(d); return d }
	cases := []struct {
		name          string
		d             *v1.Device
		reason, field string
		id            string
	}{
		{"dup name", dev("SW1", "10.0.0.9"), "hosts.duplicate_name", "name", first.Id},
		{"dup addr", dev("otro", "10.0.0.1"), "hosts.duplicate_address", "address", first.Id},
		{"name", dev(" x", "10.0.0.3"), "hosts.invalid_name", "name", ""},
		{"address", dev("a", "bad addr"), "hosts.invalid_address", "address", ""},
		{"port", bad(dev("a", "10.0.0.3"), func(d *v1.Device) { d.Profile = &v1.DeviceProfile{Port: 70000} }), "hosts.invalid_port", "port", ""},
		{"tags", bad(dev("a", "10.0.0.3"), func(d *v1.Device) { d.Tags = []string{"A B"} }), "hosts.invalid_tags", "tags", ""},
		{"notes", long, "hosts.invalid_notes", "notes", ""},
		{"cred", bad(dev("a", "10.0.0.3"), func(d *v1.Device) { d.CredentialId = "../x" }), "hosts.invalid_credential_id", "credential_id", ""},
		{"protocol", bad(dev("a", "10.0.0.3"), func(d *v1.Device) { d.Protocol = "rlogin" }), "hosts.invalid_protocol", "protocol", ""},
		{"telnet con orden de inicio", bad(dev("a", "10.0.0.3"), func(d *v1.Device) { d.Protocol, d.Platform, d.StartupCommand = "telnet", "linux", "tmux" }),
			"hosts.invalid_startup_command", "startup_command", ""},
	}
	for _, c := range cases {
		_, err := s.PutDevice(ctx, &v1.PutDeviceRequest{Device: c.d})
		i := infoOf(err)
		if i == nil || i.Reason != c.reason || i.Metadata["field"] != c.field || i.Metadata["id"] != c.id {
			t.Errorf("%s: %v -> %+v", c.name, err, i)
		}
	}
}

// Fase 48-4: un host telnet se guarda con su protocolo y el puerto 23 por omisión, vuelve igual en la lista y la
// auditoría lo dice; una credencial de solo llave no vale con telnet (ni en un host linux).
func TestHostTelnet(t *testing.T) {
	s, d := nuevoSvc(t)
	r, err := s.PutDevice(bg, &v1.PutDeviceRequest{Device: &v1.Device{Name: "viejo", Target: &v1.Target{Address: "10.0.0.7"}, Platform: "ios", Protocol: "telnet"}})
	if err != nil {
		t.Fatal(err)
	}
	l, err := s.ListDevices(bg, &v1.ListDevicesRequest{ManualOnly: true})
	if err != nil || len(l.Devices) != 1 || l.Devices[0].Protocol != "telnet" || l.Devices[0].Profile.GetPort() != 23 {
		t.Fatalf("lista = %v %v", l, err)
	}
	if a := d.AuditText(); !strings.Contains(a, "10.0.0.7:23 platform=ios protocol=telnet") {
		t.Errorf("auditoría:\n%s", a)
	}
	keyID, _, err := d.CreateVault().GenerateKey("k", "k")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.PutDevice(bg, &v1.PutDeviceRequest{Device: &v1.Device{Name: "box", Target: &v1.Target{Address: "10.0.0.8"}, Platform: "linux", Protocol: "telnet", CredentialId: keyID}})
	if err == nil {
		t.Error("aceptó una credencial de llave en un host telnet")
	}
	_ = r.Id
}
