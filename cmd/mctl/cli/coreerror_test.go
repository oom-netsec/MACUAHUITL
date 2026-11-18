package cli

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
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

// Un Unavailable de un servicio, o uno de conexión con el núcleo vivo (alerta de seguridad), no se vuelve «arráncalo».
func TestCoreErrorNoTapaUnavailableReal(t *testing.T) {
	defer func(f func() (bool, error)) { coreRunning = f }(coreRunning)
	textos := []string{
		`transport: resolving "sw1": no such host`,
		`net/http: HTTP/1.x transport connection broken`,
		`connection error: desc = "transport: Error while dialing: the pipe server does not belong to this user"`,
	}
	for _, vivo := range []bool{true, false} {
		coreRunning = func() (bool, error) { return vivo, nil }
		for i, m := range textos {
			if i == 2 && !vivo {
				continue // sin núcleo y con prefijo de conexión: ese sí es core_down
			}
			if got := CoreError(status.Error(codes.Unavailable, m)).Error(); got != m {
				t.Errorf("vivo=%v: %q se convirtió en %q", vivo, m, got)
			}
		}
	}
	// Error al comprobar (p. ej. pipe de otro usuario): tampoco es «arráncalo».
	coreRunning = func() (bool, error) { return false, errors.New("ipc: pipe de otro usuario") }
	if got := CoreError(status.Error(codes.Unavailable, textos[2])).Error(); got != textos[2] {
		t.Errorf("got %q", got)
	}
	// Caído de verdad: sí.
	coreRunning = func() (bool, error) { return false, nil }
	if got := CoreError(status.Error(codes.Unavailable, textos[2])); !strings.Contains(got.Error(), "macuahuitld") {
		t.Errorf("got %q", got)
	}
	// Con ErrorInfo y marcador de conexión, el texto del servicio pasa.
	st, _ := status.New(codes.Unavailable, `connection error: x`).WithDetails(&errdetails.ErrorInfo{Reason: "r"})
	if got := CoreError(st.Err()).Error(); got != "connection error: x" {
		t.Errorf("got %q", got)
	}
}

func TestCoreErrorMensajeVacio(t *testing.T) {
	got := CoreError(status.Error(codes.Internal, "")).Error()
	if strings.Contains(got, "rpc error") || got == "" {
		t.Fatalf("got %q", got)
	}
}

// La ayuda de llave de host envuelve el status sin su prefijo «rpc error: code = … desc = ».
func TestHostKeyHelpSinPrefijoRPC(t *testing.T) {
	err := HostKeyHelp(status.Error(codes.FailedPrecondition, "host key desconocida SHA256:abcd efgh"))
	if err == nil || strings.Contains(err.Error(), "rpc error") || !strings.Contains(err.Error(), "SHA256:abcd") {
		t.Fatalf("got %v", err)
	}
	if got := HostKeyHelp(status.Error(codes.Internal, "otra cosa")).Error(); got != "otra cosa" {
		t.Fatalf("got %q", got)
	}
}
