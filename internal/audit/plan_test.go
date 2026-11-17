package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/store"
)

// La consulta que acota el rango de Export usa idx_audit_log_at (la de página, con seq > ?, recorre por seq).
func TestExportRangoUsaIndice(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`EXPLAIN QUERY PLAN SELECT min(seq), max(seq) FROM audit_log WHERE at >= ? AND at < ?`, "a", "b")
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

// Con el reloj hacia atrás el rango no es contiguo en seq: Export devuelve exactamente lo que cae en [from, to), en orden de seq.
func TestExportConRelojHaciaAtras(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := func(m int) time.Time { return base.Add(time.Duration(m) * time.Minute) }
	db, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var now time.Time
	l := New(db, func() time.Time { return now })
	for _, m := range []int{5, 1, 3, 2, 4, 9} { // seq 1..6
		now = at(m)
		if _, err := l.Append(context.Background(), Entry{Actor: "u", Action: "a"}); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := l.Export(context.Background(), &buf, at(2), at(4)); err != nil {
		t.Fatal(err)
	}
	var seqs []uint64
	for dec := json.NewDecoder(&buf); dec.More(); {
		var r Record
		if err := dec.Decode(&r); err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, r.Seq)
	}
	if len(seqs) != 2 || seqs[0] != 3 || seqs[1] != 4 {
		t.Fatalf("seq exportados = %v, quiero [3 4]", seqs)
	}
}
