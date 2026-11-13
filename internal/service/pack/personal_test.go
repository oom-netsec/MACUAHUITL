package pack

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// Las columnas de la tabla scripts se repiten aquí (un servicio no importa a otro): no deben divergir de las del servicio de scripts.
func TestColumnasIgualesALasDelServicioDeScripts(t *testing.T) {
	b, err := os.ReadFile("../scripts/store.go")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("const columnas = `([^`]+)`").FindSubmatch(b)
	if m == nil || string(m[1]) != columns {
		t.Fatalf("columnas de scripts %q, aquí %q", m, columns)
	}
}

// Sin carpeta de configuración, el import no escribe en «./playbooks»: responde Unavailable.
func TestImportSinConfigDirEsUnavailable(t *testing.T) {
	s := &svc{d: &servicetest.Deps{}}
	_, err := s.Import(context.Background(), &v1.PackServiceImportRequest{Path: "/x.mpack", Confirm: true})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "configuración") {
		t.Fatalf("%v", err)
	}
}
