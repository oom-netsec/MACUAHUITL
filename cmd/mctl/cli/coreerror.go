package cli

import (
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// coreRunning es variable para las pruebas.
var coreRunning = ipc.CoreRunning

// connPrefixes son los comienzos de texto con que gRPC dice que no hubo conexión (socket o pipe inexistente, núcleo caído).
var connPrefixes = []string{"connection error:", "error reading from server", "name resolver error"}

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
		for _, m := range connPrefixes {
			// Solo si el canal de verdad no tiene núcleo: con el núcleo vivo, o sin poder comprobarlo (pipe de otro
			// usuario: alerta de seguridad), el texto del status pasa tal cual.
			if up, cerr := coreRunning(); strings.HasPrefix(st.Message(), m) && !up && cerr == nil {
				return Err("mctl.err.core_down")
			}
		}
	}
	if st.Message() == "" {
		return errors.New(st.Code().String())
	}
	return errors.New(st.Message())
}
