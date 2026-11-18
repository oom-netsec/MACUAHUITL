package patrol

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// El manifest lleva el id del trabajo: así una corrida cuyo trabajo se quitó del historial se sigue rotulando (respaldo por carpeta).
func TestManifestLlevaElIdDelTrabajo(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.d.JobID = "j-42"
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	if _, err := Finish(context.Background(), e.d, w, e.spec, 1, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(w.dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		JobID string `json:"job_id"`
	}
	if json.Unmarshal(b, &got) != nil || got.JobID != "j-42" {
		t.Errorf("job_id = %q: %s", got.JobID, b)
	}
}
