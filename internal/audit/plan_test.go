package audit

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/store"
)

// La consulta que ubica el inicio del rango de Export usa idx_audit_log_at (la de página, con seq > ?, recorre por seq).
func TestExportRangoUsaIndice(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`EXPLAIN QUERY PLAN SELECT min(seq) FROM audit_log WHERE at >= ? AND at < ?`, "a", "b")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, nu int
		var d string
		if err := rows.Scan(&id, &parent, &nu, &d); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, d)
	}
	t.Log(plan)
	if !strings.Contains(strings.Join(plan, "|"), "idx_audit_log_at") {
		t.Fatalf("el plan no usa el índice: %v", plan)
	}
}
