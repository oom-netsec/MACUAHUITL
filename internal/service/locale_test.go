package service_test

import (
	"context"
	"path/filepath"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

type fakePrefs struct {
	v1.UnimplementedPrefsServiceServer
	v1.UnimplementedVisibilityServiceServer
}

func (fakePrefs) GetPreference(ctx context.Context, _ *v1.GetPreferenceRequest) (*v1.GetPreferenceResponse, error) {
	return nil, service.Err(ctx, codes.AlreadyExists, "file.exists", i18n.A("path", "/x/a.txt", "secreto", "hunter2"))
}

func (fakePrefs) Flows(_ *v1.FlowsRequest, s v1.VisibilityService_FlowsServer) error {
	return service.Err(s.Context(), codes.AlreadyExists, "file.exists", i18n.A("path", "/x/a.txt"))
}

func conn(t *testing.T) *ipc.ClientConn {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "s.sock")
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ipc.Serve(ctx, l, func(r ipc.Registrar) {
		v1.RegisterPrefsServiceServer(r, fakePrefs{})
		v1.RegisterVisibilityServiceServer(r, fakePrefs{})
	}, ipc.LocaleOptions()...)
	c, err := ipc.DialPath(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func info(t *testing.T, err error) (*errdetails.ErrorInfo, *errdetails.LocalizedMessage) {
	t.Helper()
	var ei *errdetails.ErrorInfo
	var lm *errdetails.LocalizedMessage
	for _, d := range status.Convert(err).Details() {
		switch x := d.(type) {
		case *errdetails.ErrorInfo:
			ei = x
		case *errdetails.LocalizedMessage:
			lm = x
		}
	}
	if ei == nil || lm == nil {
		t.Fatalf("faltan detalles: %v", err)
	}
	return ei, lm
}

// Sin metadato o con es, el mensaje es el de siempre; con en sale en inglés; un idioma desconocido da es.
func TestInterceptorIdioma(t *testing.T) {
	c := conn(t)
	for _, tc := range []struct{ md, want, loc string }{
		{"", "el archivo ya existe", "es"}, {"es", "el archivo ya existe", "es"}, {"es-MX", "el archivo ya existe", "es"},
		{"fr", "el archivo ya existe", "es"}, {"en", "the file already exists", "en"}, {"en-US,en;q=0.9", "the file already exists", "en"},
		{"fr;q=0.9, en;q=0.5", "the file already exists", "en"},
	} {
		ctx := context.Background()
		if tc.md != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "accept-language", tc.md)
		}
		_, err := v1.NewPrefsServiceClient(c).GetPreference(ctx, &v1.GetPreferenceRequest{Key: "terminal"})
		if got := status.Convert(err).Message(); got != tc.want {
			t.Errorf("%q: mensaje %q, quiero %q", tc.md, got, tc.want)
		}
		if want := "rpc error: code = AlreadyExists desc = " + tc.want; err.Error() != want {
			t.Errorf("%q: Error() = %q", tc.md, err.Error())
		}
		ei, lm := info(t, err)
		if ei.Reason != "file.exists" || ei.Domain != "macuahuitl" || ei.Metadata["path"] != "/x/a.txt" || lm.Locale != tc.loc || lm.Message != tc.want {
			t.Errorf("%q: detalles %v %v", tc.md, ei, lm)
		}
		if _, leaked := ei.Metadata["secreto"]; leaked || len(ei.Metadata) != 1 {
			t.Errorf("la metadata solo lleva lo declarado: %v", ei.Metadata)
		}
	}
}

func TestInterceptorStream(t *testing.T) {
	c := conn(t)
	ctx := metadata.AppendToOutgoingContext(context.Background(), "accept-language", "en")
	s, err := v1.NewVisibilityServiceClient(c).Flows(ctx, &v1.FlowsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Recv()
	if got := status.Convert(err).Message(); got != "the file already exists" {
		t.Fatalf("stream en: %q", got)
	}
}

// Un error sin código sale como siempre, sin detalles.
func TestErrFromSinCodigo(t *testing.T) {
	err := service.ErrFrom(context.Background(), codes.Internal, context.Canceled)
	if status.Convert(err).Message() != "context canceled" || len(status.Convert(err).Details()) != 0 {
		t.Fatal(err)
	}
}
