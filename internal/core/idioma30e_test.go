package core

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// Fase 30e: «trabajo X no existe» sale en el idioma pedido; con es, el de siempre.
func TestTrabajoInexistenteEsYEn(t *testing.T) {
	h := newHarness(t, nil)
	for loc, want := range map[string]string{"": "trabajo zz no existe", "es": "trabajo zz no existe", "en": "job zz does not exist"} {
		_, err := h.patrol.CancelJob(con(t, loc), &v1.CancelJobRequest{JobId: "zz"})
		if status.Code(err) != codes.NotFound || status.Convert(err).Message() != want {
			t.Errorf("%q: %v, quería %q", loc, err, want)
		}
	}
}
