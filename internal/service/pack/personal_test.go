package pack

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// Sin carpeta de configuración, el import no escribe en «./playbooks»: responde Unavailable.
func TestImportSinConfigDirEsUnavailable(t *testing.T) {
	s := &svc{d: &servicetest.Deps{}}
	_, err := s.Import(i18n.WithLocale(context.Background(), i18n.Es), &v1.PackServiceImportRequest{Path: "/x.mpack", Confirm: true})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "configuración") {
		t.Fatalf("%v", err)
	}
}
