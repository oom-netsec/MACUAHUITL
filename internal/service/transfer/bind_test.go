package transfer

import (
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/listen/listentest"
)

// ADR 0004 (enmienda 2026-11-16): un puerto ocupado es el ERROR del RPC con su reason y metadata.port, y ninguna
// respuesta Ready llega antes.
func TestStartServerPuertoOcupadoEsErrorDelRPC(t *testing.T) {
	for proto, network := range map[string]string{"ftp": "tcp", "tftp": "udp"} {
		addr := listentest.Busy(t, network)
		port := addr[strings.LastIndex(addr, ":")+1:]
		s, _ := newTest(t)
		st := &fakeStream{ctx: t.Context(), out: make(chan *v1.StartServerResponse, 8)}
		e := s.StartServer(&v1.StartServerRequest{Protocol: proto, Listen: addr, FromDir: t.TempDir()}, st)
		if status.Code(e) != codes.Unavailable {
			t.Fatalf("%s: err = %v", proto, e)
		}
		for len(st.out) > 0 {
			if _, ok := (<-st.out).Event.(*v1.StartServerResponse_Ready); ok {
				t.Errorf("%s: Ready antes del error", proto)
			}
		}
		found := false
		for _, d := range status.Convert(e).Details() {
			if ei, ok := d.(*errdetails.ErrorInfo); ok {
				found = true
				if ei.Reason != "fileserve.err.port_in_use" || ei.Metadata["port"] != port || strings.Contains(status.Convert(e).Message(), "sysctl") {
					t.Errorf("%s: %v", proto, ei)
				}
			}
		}
		if !found {
			t.Errorf("%s: sin ErrorInfo: %v", proto, e)
		}
	}
}
