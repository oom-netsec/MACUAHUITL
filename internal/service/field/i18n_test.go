package field

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/imgverify"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

var palabrasEs = regexp.MustCompile(`(?i)[áéíóúñ]|\b(archivo|carpeta|salida|puerto|protocolo|coincide|equipo|copiarla|inválid|debe ser|no soportad)`)

func TestErroresDelServicioDeCampo(t *testing.T) {
	d := servicetest.New(t)
	s := &fieldSvc{d: d}
	es, en := context.Background(), i18n.WithLocale(context.Background(), "en")

	// la carpeta de salida es un archivo: no se puede crear
	os.MkdirAll(d.Outputs(), 0o700)
	os.WriteFile(filepath.Join(d.Outputs(), "console"), nil, 0o600)
	_, err := s.outFile("console", "x")
	if err == nil || !strings.HasPrefix(err.Error(), "carpeta de salida: ") {
		t.Fatalf("es: %v", err)
	}
	if got := service.ErrFrom(en, codes.Internal, err); strings.HasPrefix(status.Convert(got).Message(), "carpeta") || !strings.HasPrefix(status.Convert(got).Message(), "output folder: ") {
		t.Errorf("en: %v", got)
	}

	// hash: ruta relativa y valor esperado inválido
	for _, c := range []struct{ req *v1.HashFileRequest }{{&v1.HashFileRequest{Path: "rel"}}, {&v1.HashFileRequest{Path: "/x", Md5: "zz"}}} {
		_, e1 := s.HashFile(es, c.req)
		_, e2 := s.HashFile(en, c.req)
		if !strings.Contains(status.Convert(e1).Message(), "imgverify: ") || palabrasEs.MatchString(status.Convert(e2).Message()) {
			t.Errorf("hash: %v / %v", e1, e2)
		}
	}
	if _, e := s.HashFile(es, &v1.HashFileRequest{Path: "rel"}); status.Convert(e).Message() != "imgverify: la ruta debe ser absoluta" {
		t.Errorf("es: %v", e)
	}

	// protocolo no soportado
	st := &fakeServe{ctx: en}
	if e := s.ServeFiles(&v1.ServeFilesRequest{Protocol: "ftp"}, st); status.Convert(e).Message() != `protocol "ftp" not supported (tftp or http)` {
		t.Errorf("proto en: %v", e)
	}
	st = &fakeServe{ctx: es}
	if e := s.ServeFiles(&v1.ServeFilesRequest{Protocol: "ftp"}, st); status.Convert(e).Message() != `protocolo "ftp" no soportado (tftp o http)` {
		t.Errorf("proto es: %v", e)
	}
}

type fakeServe struct {
	v1.FieldService_ServeFilesServer
	ctx context.Context
}

func (f *fakeServe) Context() context.Context { return f.ctx }

func TestInformeDeHashEsEn(t *testing.T) {
	res := imgverify.Result{File: "a.bin", Size: 3, MD5: "m", SHA512: "s", MD5Match: "ok", SHA512Match: "distinto", VerifyCommand: "verify /md5 flash:a.bin m"}
	want := "archivo  a.bin (3 bytes)\nMD5      m  coincide\nSHA-512  s  NO COINCIDE\nen el equipo, tras copiarla:\n  verify /md5 flash:a.bin m"
	if got := hashText("es", res); got != want {
		t.Errorf("es:\n%s", got)
	}
	if got := hashText("en", res); palabrasEs.MatchString(got) || !strings.Contains(got, "DOES NOT MATCH") {
		t.Errorf("en:\n%s", got)
	}
}
