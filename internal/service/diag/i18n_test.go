package diag

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

type fakeRun struct {
	v1.DiagService_RunServer
	ctx context.Context
}

func (f fakeRun) Context() context.Context { return f.ctx }

// Una petición inválida sale con el texto en el idioma pedido; sin idioma, el de siempre.
func TestRunErrorEsEn(t *testing.T) {
	s := &diagSvc{d: servicetest.New(t)}
	req := &v1.RunRequest{Tool: v1.DiagTool_DIAG_TOOL_PING, Targets: []*v1.Target{{Address: "-x"}}}
	for _, c := range []struct {
		ctx  context.Context
		want string
	}{
		{context.Background(), `destino "-x" inválido`},
		{i18n.WithLocale(context.Background(), "en"), `invalid target "-x"`},
	} {
		if got := status.Convert(s.Run(req, fakeRun{ctx: c.ctx})).Message(); got != c.want {
			t.Errorf("got %q want %q", got, c.want)
		}
	}
}

// Mientras no exista el barrido (200-4), pedirlo se rechaza en vez de correr un solo ping.
func TestRunRechazaBarrido(t *testing.T) {
	s := &diagSvc{d: servicetest.New(t)}
	req := &v1.RunRequest{Tool: v1.DiagTool_DIAG_TOOL_PING, Targets: []*v1.Target{{Address: "192.0.2.1"}},
		Options: map[string]string{"sweep_start": "0", "sweep_end": "10", "sweep_step": "5"}}
	for _, c := range []struct {
		ctx  context.Context
		want string
	}{
		{context.Background(), "el barrido de tamaños todavía no está disponible"},
		{i18n.WithLocale(context.Background(), "en"), "the size sweep is not available yet"},
	} {
		err := s.Run(req, fakeRun{ctx: c.ctx})
		if st := status.Convert(err); st.Code() != codes.InvalidArgument || st.Message() != c.want {
			t.Errorf("got %v %q want %q", st.Code(), st.Message(), c.want)
		}
	}
}
