package cli

import (
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// connMarkers son los textos con que gRPC dice que no hubo conexión (socket o pipe inexistente, núcleo caído).
var connMarkers = []string{"connection error", "transport", "error reading from server", "name resolver", "dialing"}

// CoreError es lo que ve el usuario cuando falla una llamada al núcleo: sin núcleo, la frase del catálogo; para
// cualquier otro status, solo su mensaje (sin «rpc error: code = … desc = »). Un error que no es status pasa igual,
// y se conservan el ExitError y los motivos (el texto del núcleo ya viene localizado).
func CoreError(err error) error {
	if err == nil {
		return nil
	}
	var x ExitError
	if errors.As(err, &x) {
		return ExitError{Code: x.Code, Err: CoreError(x.Err)}
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	if st.Code() == codes.Unavailable && len(st.Details()) == 0 {
		for _, m := range connMarkers {
			if strings.Contains(st.Message(), m) {
				return Err("mctl.err.core_down")
			}
		}
	}
	if st.Message() == "" {
		return err
	}
	return errors.New(st.Message())
}
