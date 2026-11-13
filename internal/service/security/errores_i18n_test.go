package security

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

// Fase 30d: los rechazos de validación salen en el idioma pedido; con es, el texto de siempre.
func TestSeguridadRechazosEsYEn(t *testing.T) {
	s := &securitySvc{d: servicetest.New(t)}
	for loc, want := range map[string][]string{
		"es": {"servidor inválido", "puerto inválido", "contraseña de la llave incorrecta", "exportar la llave en claro requiere marcar include_plain_key", "entrada demasiado grande", "entrada demasiado grande: el máximo es 1 MiB de texto de debug"},
		"en": {"invalid server", "invalid port", "wrong key password", "exporting the key in the clear requires include_plain_key", "input too large", "input too large: the maximum is 1 MiB of debug text"},
	} {
		c := i18n.WithLocale(context.Background(), loc)
		_, e1 := port16(c, 70000)
		_, e5 := s.PkiDecode(c, &v1.PkiDecodeRequest{Data: make([]byte, maxPaste+1)})
		_, e6 := s.IkeDecode(c, &v1.IkeDecodeRequest{Text: strings.Repeat("x", maxIkePaste+1)})
		_, e4 := s.PkiExport(c, &v1.PkiExportRequest{Format: "pem", SealedKeyPem: "x"})
		got := []error{validHost(c, "-x"), e1, pkiErr(c, vault.ErrWrongPassword), e4, e5, e6}
		for i, err := range got {
			if status.Code(err) == codes.OK || status.Convert(err).Message() != want[i] {
				t.Errorf("%s %d: %v, quería %q", loc, i, err, want[i])
			}
		}
	}
}
