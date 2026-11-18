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

// Los trabajos van del más nuevo al más viejo (los topes de fleet e inventory cortan la evidencia vieja, no la
// reciente) y las raíces de los quitados al final. Un spec_json ilegible no corta la lectura.
func TestJobOutputRootsOrdenYJSONIlegible(t *testing.T) {
	d := servicetest.New(t)
	vieja, nueva, quitada := t.TempDir(), t.TempDir(), t.TempDir()
	for _, f := range [][3]string{{"j1", vieja, "2026-11-01T10:00:00Z"}, {"j2", "{", "2026-11-03T10:00:00Z"}, {"j3", nueva, "2026-11-05T10:00:00Z"}} {
		spec := `{"OutputDir":` + strconv.Quote(f[1]) + `}`
		if f[1] == "{" {
			spec = "{"
		}
		if _, err := d.DB().Exec(`INSERT INTO jobs(id,name,spec_json,state,created_at) VALUES(?,'r',?,'completed',?)`, f[0], spec, f[2]); err != nil {
			t.Fatal(err)
		}
	}
	if err := service.RecordJobRoot(d.DB(), quitada); err != nil {
		t.Fatal(err)
	}
	if got := service.JobOutputRoots(d); !slices.Equal(got, []string{nueva, vieja, quitada}) {
		t.Fatalf("raíces = %v, quiero [%s %s %s]", got, nueva, vieja, quitada)
	}
}

// RecordJobRoot guarda la ruta limpia y no guarda vacías ni relativas (un trabajo sin carpeta propia).
func TestRecordJobRootLimpiaYDescartaRelativas(t *testing.T) {
	d := servicetest.New(t)
	raiz := t.TempDir()
	for _, p := range []string{"", "rel/x", raiz + string(filepath.Separator), raiz} {
		if err := service.RecordJobRoot(d.DB(), p); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := d.DB().QueryRow(`SELECT count(*) FROM job_roots`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("filas = %d err = %v", n, err)
	}
}
