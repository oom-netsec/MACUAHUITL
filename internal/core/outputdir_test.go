package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// El output_dir de un trabajo pasa por la misma validación que la carpeta de salidas de Ajustes (fase 29e).
func TestCreateJobValidaOutputDirComoAjustes(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	crear := func(dir string) (string, error) {
		sp := h.spec(cred)
		sp.OutputDir = dir
		r, err := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: sp})
		if err != nil {
			return "", err
		}
		return r.JobId, nil
	}
	quiero := func(err error, codigo string) {
		t.Helper()
		if status.Code(err) != codes.InvalidArgument || !strings.HasPrefix(status.Convert(err).Message(), "prefs.outputs."+codigo+":") {
			t.Fatalf("esperaba InvalidArgument prefs.outputs.%s, salió: %v", codigo, err)
		}
	}
	_, err := crear("/tmp")
	quiero(err, "reservada")
	_, err = crear("/tmp/no-existe-fase31")
	quiero(err, "no_existe")
	_, err = crear("relativa")
	quiero(err, "relativa")

	laxa := filepath.Join(h.out, "laxa")
	os.Mkdir(laxa, 0o700)
	os.Chmod(laxa, 0o755)
	_, err = crear(laxa)
	quiero(err, "permisos")
	if !strings.Contains(err.Error(), "chmod 700 "+laxa) {
		t.Fatalf("falta el chmod sugerido: %v", err)
	}

	propia := filepath.Join(h.out, "propia")
	os.Mkdir(propia, 0o700)
	if _, err := crear(propia); err != nil {
		t.Fatalf("0700 propia debía aceptarse: %v", err)
	}
	// vacío: la carpeta de salidas vigente
	job, err := crear("")
	if err != nil {
		t.Fatalf("vacío debía aceptarse: %v", err)
	}
	if s := h.summary(t, job); s.OutputDir != h.out {
		t.Fatalf("output_dir = %q, quería %q", s.OutputDir, h.out)
	}
}
