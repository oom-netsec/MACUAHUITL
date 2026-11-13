package field

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

type serveStream struct {
	v1.FieldService_ServeFilesServer
	ctx context.Context
}

func (s serveStream) Context() context.Context { return s.ctx }

// Fase 30e: el protocolo no soportado y la carpeta de salida salen en el idioma pedido; con es, el de siempre.
func TestErroresPropiosEsYEn(t *testing.T) {
	s := &fieldSvc{d: servicetest.New(t)}
	for loc, want := range map[string]string{"es": `protocolo "ftp" no soportado (tftp o http)`, "en": `protocol "ftp" not supported (tftp or http)`} {
		err := s.ServeFiles(&v1.ServeFilesRequest{Protocol: "ftp"}, serveStream{ctx: i18n.WithLocale(context.Background(), loc)})
		if got := status.Convert(err).Message(); got != want {
			t.Errorf("%s: %q, quería %q", loc, got, want)
		}
	}
	// outputs/console es un archivo: no se puede crear la carpeta
	os.MkdirAll(s.d.Outputs(), 0o700)
	os.WriteFile(filepath.Join(s.d.Outputs(), "console"), nil, 0o600)
	_, err := s.outFile("console", "x")
	if err == nil || !strings.HasPrefix(err.Error(), "carpeta de salida: ") || !strings.HasPrefix(i18n.In("en", err), "output folder: ") {
		t.Errorf("carpeta: %v / %s", err, i18n.In("en", err))
	}
}
