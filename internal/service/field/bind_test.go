package field

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/listen/listentest"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// ADR 0004 (enmienda 2026-11-16): un puerto ocupado es el ERROR del RPC (reason y metadata), antes de la primera respuesta.
func TestServeFilesPuertoOcupadoEsErrorDelRPC(t *testing.T) {
	addr := listentest.Busy(t, "tcp")
	port := addr[strings.LastIndex(addr, ":")+1:]
	f := filepath.Join(t.TempDir(), "a.bin")
	os.WriteFile(f, []byte("x"), 0o600)
	s := &fieldSvc{d: servicetest.New(t)}
	st := &fakeServe{ctx: context.Background()}
	e := s.ServeFiles(&v1.ServeFilesRequest{Protocol: "http", Addr: "127.0.0.1:" + port, Files: []string{f}, DurationSeconds: 5}, st)
	if status.Code(e) != codes.Unavailable {
		t.Fatalf("err = %v", e)
	}
	for _, d := range status.Convert(e).Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			if ei.Reason != "fileserve.err.port_in_use" || ei.Metadata["port"] != port || strings.Contains(status.Convert(e).Message(), "sysctl") {
				t.Errorf("%v", ei)
			}
			return
		}
	}
	t.Fatalf("sin ErrorInfo: %v", e)
}

// Un archivo dentro de la carpeta de datos de la app no se publica.
func TestServeFilesRechazaCarpetaDeLaApp(t *testing.T) {
	d := servicetest.New(t)
	datos := t.TempDir()
	d.Deny = []string{datos}
	f := filepath.Join(datos, "vault.bin")
	os.WriteFile(f, []byte("x"), 0o600)
	s := &fieldSvc{d: d}
	e := s.ServeFiles(&v1.ServeFilesRequest{Protocol: "http", Addr: "127.0.0.1:0", Files: []string{f}, DurationSeconds: 5}, &fakeServe{ctx: context.Background()})
	if status.Code(e) != codes.InvalidArgument {
		t.Fatalf("err = %v", e)
	}
}
