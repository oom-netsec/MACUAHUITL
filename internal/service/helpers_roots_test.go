package service_test

import (
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

func TestJobOutputRootsSobreviveSinLaFilaDeJobs(t *testing.T) {
	d := servicetest.New(t)
	raiz := t.TempDir()
	if err := service.RecordJobRoot(d.DB(), raiz); err != nil {
		t.Fatal(err)
	}
	if got := service.JobOutputRoots(d); !slices.Equal(got, []string{raiz}) {
		t.Fatalf("raíces = %v, quiero [%s]", got, raiz)
	}
}

func TestJobOutputRootsFiltraAlLeerLoQueCaeEnOutputs(t *testing.T) {
	d := servicetest.New(t)
	dentro := filepath.Join(d.Out, "respaldos", ".trabajos", "lote-1")
	if err := service.RecordJobRoot(d.DB(), dentro); err != nil {
		t.Fatal(err)
	}
	if got := service.JobOutputRoots(d); len(got) != 0 {
		t.Fatalf("raíces = %v, quiero vacío", got)
	}
}

func TestRecordJobRootEsIdempotenteYNoDuplicaConJobs(t *testing.T) {
	d := servicetest.New(t)
	raiz := t.TempDir()
	if _, err := d.DB().Exec(`INSERT INTO jobs(id,name,spec_json,state,created_at) VALUES('j1','r',?,'completed','2026-11-06T10:00:00Z')`,
		`{"OutputDir":`+strconv.Quote(raiz)+`}`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := service.RecordJobRoot(d.DB(), raiz); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := d.DB().QueryRow(`SELECT count(*) FROM job_roots`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("filas = %d err = %v", n, err)
	}
	if got := service.JobOutputRoots(d); !slices.Equal(got, []string{raiz}) {
		t.Fatalf("raíces = %v (la unión no debe repetir)", got)
	}
}
