package core

import (
	"context"
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

// El tipo de trabajo es un valor cerrado: vacío = patrol; otro valor se rechaza; el tipo se persiste con el trabajo.
func TestCreateJobTipoDeTrabajo(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	crear := func(kind string) (string, error) {
		sp := h.spec(cred)
		sp.Kind = kind
		r, err := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: sp})
		if err != nil {
			return "", err
		}
		return r.JobId, nil
	}
	if _, err := crear("otro"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("kind inválido debía rechazarse: %v", err)
	}
	vacio, err := crear("")
	if err != nil {
		t.Fatal(err)
	}
	if k := h.summary(t, vacio).Kind; k != "patrol" {
		t.Fatalf("vacío = %q, quería patrol", k)
	}
	for _, k := range []string{"patrol", "adhoc", "backup", "change"} {
		id, err := crear(k)
		if err != nil || h.summary(t, id).Kind != k {
			t.Fatalf("kind %s: %v", k, err)
		}
	}
	adhoc, _ := crear("adhoc")
	// un trabajo guardado antes de esta fase: su spec_json no trae la llave Kind
	p := h.core.p
	h.core.Close()
	db := openDB(t, p)
	if _, err := db.Exec(`INSERT INTO jobs(id,name,spec_json,state,created_at) VALUES('previo','p','{"Name":"p"}','completed','2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	c, err := New(p, Options{Actor: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, err := (&patrolSvc{c: c}).ListJobs(context.Background(), &v1.ListJobsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, j := range r.Jobs {
		got[j.JobId] = j.Kind
	}
	if got[adhoc] != "adhoc" || got["previo"] != "patrol" {
		t.Fatalf("kinds recargados = %v (adhoc=%s)", got, adhoc)
	}
}
