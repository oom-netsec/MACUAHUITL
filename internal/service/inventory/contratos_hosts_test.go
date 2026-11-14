package inventory

import (
	"context"
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
		{"cred", bad(dev("a", "10.0.0.3"), func(d *v1.Device) { d.CredentialId = "../x" }), "hosts.invalid_credential_id", "credentialId", ""},
	}
	for _, c := range cases {
		_, err := s.PutDevice(ctx, &v1.PutDeviceRequest{Device: c.d})
		i := infoOf(err)
		if i == nil || i.Reason != c.reason || i.Metadata["field"] != c.field || i.Metadata["id"] != c.id {
			t.Errorf("%s: %v -> %+v", c.name, err, i)
		}
	}
}
