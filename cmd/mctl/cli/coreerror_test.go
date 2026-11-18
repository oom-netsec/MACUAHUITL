package cli

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestStatusSinPrefijoRPC(t *testing.T) {
	got := CoreError(status.Error(codes.NotFound, "x")).Error()
	if got != "x" {
		t.Fatalf("got %q", got)
	}
	if CoreError(errors.New("plano")).Error() != "plano" || CoreError(nil) != nil {
		t.Fatal("un error que no es status pasa igual")
	}
	// Unavailable de un servicio (no de la conexión) conserva su texto.
	if got := CoreError(status.Error(codes.Unavailable, "cerrándose")).Error(); got != "cerrándose" {
		t.Fatalf("got %q", got)
	}
	// El código de salida se conserva.
	e := CoreError(ExitError{Code: 7, Err: status.Error(codes.FailedPrecondition, "ocupado")})
	if ExitCode(e) != 7 || strings.Contains(e.Error(), "rpc error") {
		t.Fatalf("e = %v, código %d", e, ExitCode(e))
	}
}
