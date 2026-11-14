package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Contrato para front: cada rechazo de la carpeta de salidas trae reason prefs.outputs.<motivo>, metadata.code (el
// motivo) y metadata.path (la ruta), y el texto sale en el idioma pedido.
func TestRechazosDeSalidasConReasonCodeYPath(t *testing.T) {
	st := NewCoreSettings("fabrica", t.TempDir())
	old := AncestorInfo
	AncestorInfo = func(string) (os.FileMode, uint32, error) { return 0o755, uint32(os.Getuid()), nil }
	t.Cleanup(func() { AncestorInfo = old })
	d := t.TempDir()
	abierta := filepath.Join(d, "abierta")
	os.Mkdir(abierta, 0o700)
	os.Chmod(abierta, 0o755)
	conEspacio := filepath.Join(d, "con espacio")
	os.Mkdir(conEspacio, 0o700)
	os.Chmod(conEspacio, 0o755)
	archivo := filepath.Join(d, "f")
	os.WriteFile(archivo, nil, 0o600)
	cases := []struct{ name, dir, code, path string }{
		{"relativa", "rel/x", "relativa", "rel/x"},
		{"no existe", filepath.Join(d, "nada"), "no_existe", filepath.Join(d, "nada")},
		{"no es carpeta", archivo, "no_directorio", archivo},
		{"permisos con orden", abierta, "permisos", abierta},
		{"permisos sin orden", conEspacio, "permisos", conEspacio},
	}
	for _, loc := range []string{"es", "en"} {
		ctx := i18n.WithLocale(context.Background(), loc)
		for _, c := range cases {
			_, err := CheckOutputs(c.dir, st, false)
			if err == nil {
				t.Fatalf("%s: sin error", c.name)
			}
			e := ErrFrom(ctx, codes.InvalidArgument, err)
			var info *errdetails.ErrorInfo
			for _, x := range status.Convert(e).Details() {
				if i, ok := x.(*errdetails.ErrorInfo); ok {
					info = i
				}
			}
			if info == nil || info.Reason != "prefs.outputs."+c.code || info.Metadata["code"] != c.code || info.Metadata["path"] != c.path {
				t.Errorf("%s/%s: %+v", loc, c.name, info)
			}
		}
		_, err := CheckOutputs(abierta, st, false)
		msg := status.Convert(ErrFrom(ctx, codes.InvalidArgument, err)).Message()
		want := map[string]string{"es": "corrígelo con: chmod 700 " + abierta, "en": "fix it with: chmod 700 " + abierta}[loc]
		if !strings.Contains(msg, want) {
			t.Errorf("%s: %q sin %q", loc, msg, want)
		}
	}
}

// Un motivo que no es de salidas sale como «unknown» en la auditoría, sin tocar el motivo estable.
func TestAuditoriaDeSalidasMotivoDesconocido(t *testing.T) {
	got := OutputsIssueAudit("/x", os.ErrPermission)
	if !strings.Contains(got, "reason=unknown") {
		t.Fatal(got)
	}
}
