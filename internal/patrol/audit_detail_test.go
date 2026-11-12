package patrol

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/store"
)

// El Detail del equipo llega a la pantalla y a mctl (no es el detalle de auditoría): sigue en español.
func TestAuditResultFallaConDetalleEnEspanol(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.Close() // la bitácora ya no se puede escribir
	res := auditResult(context.Background(), Deps{Audit: audit.New(db, time.Now)}, "j1", DeviceResult{State: "completed"})
	if res.State != "failed" || !strings.HasPrefix(res.Detail, "auditoría: ") {
		t.Fatalf("res = %+v", res)
	}
}
