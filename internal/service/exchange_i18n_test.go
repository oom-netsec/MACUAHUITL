package service

import (
	"context"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func razon(t *testing.T, err error) string {
	t.Helper()
	if ei, _ := status.Convert(err).Details()[0].(*errdetails.ErrorInfo); ei != nil {
		return ei.Reason
	}
	return ""
}

// Fase 30d: los errores de export/import llevan reason y salen en el idioma pedido; con es, el texto de siempre.
func TestIntercambioErroresEsYEn(t *testing.T) {
	fifo := t.TempDir() // un directorio tampoco es archivo regular (noegress no deja usar syscall.Mkfifo aquí)
	cases := []struct {
		name, reason, es, en string
		call                 func(ctx context.Context) error
	}{
		{"ruta relativa", "file.err.path_abs", "la ruta debe ser absoluta", "the path must be absolute",
			func(ctx context.Context) error { _, err := AbsPath(ctx, "rel"); return err }},
		{"destino no regular", "file.err.export_not_regular", "la ruta existe y no es un archivo regular", "the path exists and is not a regular file",
			func(ctx context.Context) error { return WriteExport(ctx, fifo, []byte("x"), true) }},
		{"importar FIFO", "sys.err.not_regular", "la ruta no es un archivo regular", "the path is not a regular file",
			func(ctx context.Context) error { _, err := ReadImport(ctx, fifo, 10); return err }},
	}
	for _, c := range cases {
		for loc, want := range map[string]string{"es": c.es, "en": c.en} {
			err := c.call(i18n.WithLocale(context.Background(), loc))
			if got := status.Convert(err).Message(); got != want {
				t.Errorf("%s %s: %q, quería %q", c.name, loc, got, want)
			}
			if r := razon(t, err); r != c.reason {
				t.Errorf("%s %s: reason %q, quería %q", c.name, loc, r, c.reason)
			}
		}
	}
}
