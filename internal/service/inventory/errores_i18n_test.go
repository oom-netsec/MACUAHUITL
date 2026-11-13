package inventory

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// Fase 30d: los rechazos de la libreta (host, token, formato) salen en el idioma pedido; con es, el de siempre.
func TestLibretaRechazosEsYEn(t *testing.T) {
	s := &svc{d: servicetest.New(t)}
	for loc, want := range map[string][3]string{
		"es": {"falta el host", "token de importación desconocido; abre el archivo de nuevo", "pida el formato csv o json"},
		"en": {"the host is missing", "unknown import token; open the file again", "ask for the csv or json format"},
	} {
		c := i18n.WithLocale(context.Background(), loc)
		_, e0 := s.PutDevice(c, &v1.PutDeviceRequest{})
		_, e1 := s.ApplyImportHosts(c, &v1.ApplyImportHostsRequest{Token: "nada"})
		_, e2 := s.HostsImportTemplate(c, &v1.HostsImportTemplateRequest{Format: "xml"})
		for i, err := range []error{e0, e1, e2} {
			if m := status.Convert(err).Message(); m != want[i] || status.Code(err) == codes.OK {
				t.Errorf("%s %d: %v, quería %q", loc, i, err, want[i])
			}
		}
	}
}
