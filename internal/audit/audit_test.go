package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/store"
)

func newLog(t *testing.T) (*Log, func(string)) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	exec := func(q string) {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	return New(db, time.Now), exec
}

func appendN(t *testing.T, l *Log, n int) []Record {
	t.Helper()
	var rs []Record
	for i := 0; i < n; i++ {
		r, err := l.Append(context.Background(), Entry{Actor: "u", Action: "a", Target: fmt.Sprint(i), Detail: "d"})
		if err != nil {
			t.Fatal(err)
		}
		rs = append(rs, r)
	}
	return rs
}

func TestChainIntact(t *testing.T) {
	l, _ := newLog(t)
	rs := appendN(t, l, 3)
	if rs[0].Prev != Genesis {
		t.Fatalf("first prev = %s", rs[0].Prev)
	}
	v, err := l.Verify(context.Background())
	if err != nil || !v.Intact || v.Head != rs[2].Hash {
		t.Fatalf("verify = %+v, %v", v, err)
	}
	h, _ := l.Head(context.Background())
	if h != rs[2].Hash {
		t.Fatalf("head = %s", h)
	}
}

func TestHeadEmptyIsGenesis(t *testing.T) {
	l, _ := newLog(t)
	if h, err := l.Head(context.Background()); err != nil || h != Genesis {
		t.Fatalf("head = %s, %v", h, err)
	}
}

func TestDetectsEditedRow(t *testing.T) {
	l, exec := newLog(t)
	appendN(t, l, 5)
	exec(`DROP TRIGGER audit_log_no_update`)
	exec(`UPDATE audit_log SET detail='x' WHERE seq=3`)
	v, err := l.Verify(context.Background())
	if err != nil || v.Intact || v.FirstBroken != 3 {
		t.Fatalf("verify = %+v, %v", v, err)
	}
}

func TestDetectsDeletedRow(t *testing.T) {
	l, exec := newLog(t)
	appendN(t, l, 5)
	exec(`DROP TRIGGER audit_log_no_delete`)
	exec(`DELETE FROM audit_log WHERE seq=2`)
	v, err := l.Verify(context.Background())
	if err != nil || v.Intact || v.FirstBroken != 3 {
		t.Fatalf("verify = %+v, %v", v, err)
	}
}

func TestConcurrentAppend(t *testing.T) {
	l, _ := newLog(t)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := l.Append(context.Background(), Entry{Actor: "u", Action: "a"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	v, err := l.Verify(context.Background())
	if err != nil || !v.Intact {
		t.Fatalf("verify = %+v, %v", v, err)
	}
	var buf bytes.Buffer
	if err := l.Export(context.Background(), &buf, time.Time{}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var seqs []uint64
	sc := bufio.NewScanner(&buf)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, r.Seq)
	}
	for i, s := range seqs {
		if s != uint64(i+1) {
			t.Fatalf("seq[%d] = %d", i, s)
		}
	}
	if len(seqs) != 100 {
		t.Fatalf("len = %d", len(seqs))
	}
}

func TestSecretInDetailIsRedacted(t *testing.T) {
	l, _ := newLog(t)
	s := secret.New([]byte("MARKER-AUD"))
	defer s.Destroy()
	if _, err := l.Append(context.Background(), Entry{Detail: fmt.Sprint(s)}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := l.Export(context.Background(), &buf, time.Time{}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("MARKER-AUD")) {
		t.Fatal("secret leaked into audit export")
	}
}

func TestExportJSONLines(t *testing.T) {
	l, _ := newLog(t)
	appendN(t, l, 2)
	var buf bytes.Buffer
	if err := l.Export(context.Background(), &buf, time.Time{}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("lines = %d", len(lines))
	}
	for _, ln := range lines {
		if !json.Valid(ln) {
			t.Fatalf("invalid json: %s", ln)
		}
	}
}

func TestExportRangeSubSecond(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	base := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	// base cae en el segundo exacto: con RFC3339Nano se guarda sin decimales y
	// como texto ordena después de "…00.2Z", aunque es anterior.
	times := []time.Time{base, base.Add(500 * time.Millisecond), base.Add(time.Second)}
	i := 0
	l := New(db, func() time.Time { t := times[i]; i++; return t })
	appendN(t, l, 3)
	var buf bytes.Buffer
	if err := l.Export(context.Background(), &buf, base.Add(200*time.Millisecond), base.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(buf.Bytes(), []byte("\n")); n != 2 {
		t.Fatalf("exported %d records, want 2: %s", n, buf.String())
	}
}

func TestVerifyRequiresContiguousSeq(t *testing.T) {
	l, exec := newLog(t)
	rs := appendN(t, l, 3)
	// Un registro bien encadenado pero con seq saltado (borrado y reinserción) debe detectarse.
	e := Entry{Actor: "u", Action: "a", Target: "x", Detail: "d"}
	at := "2026-11-03T12:00:00.000000000Z"
	h := hashOf(rs[2].Hash, 10, at, e)
	exec(fmt.Sprintf(`INSERT INTO audit_log(seq,at,actor,action,target,detail,prev,hash) VALUES(10,'%s','u','a','x','d','%s','%s')`, at, rs[2].Hash, h))
	v, err := l.Verify(context.Background())
	if err != nil || v.Intact || v.FirstBroken != 10 {
		t.Fatalf("verify = %+v, %v", v, err)
	}
}

// Otra conexión escribe en otra tabla mientras varias goroutines auditan:
// ningún Append puede fallar con SQLITE_BUSY ni perder su entrada.
func TestAppendConEscritorConcurrente(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	other, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { other.Close() })
	l := New(db, time.Now)

	stop := make(chan struct{})
	var wdone sync.WaitGroup
	wdone.Add(1)
	go func() {
		defer wdone.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			other.Exec(`INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)`, fmt.Sprint(i%5), "v")
		}
	}()

	const workers, each = 8, 25
	var wg sync.WaitGroup
	errs := make(chan error, workers*each)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if _, err := l.Append(context.Background(), Entry{Actor: "u", Action: "a", Target: "t", Detail: "d"}); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	wdone.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("Append: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM audit_log`).Scan(&n); err != nil || n != workers*each {
		t.Fatalf("entradas = %d (err %v), quiero %d", n, err, workers*each)
	}
	if res, err := l.Verify(context.Background()); err != nil || !res.Intact {
		t.Fatalf("cadena rota: %+v %v", res, err)
	}
}

// Fase 30a-2: los registros viejos (detalle en español) no se reescriben; la cadena sigue íntegra con
// registros viejos en español y nuevos en inglés en la misma base.
func TestVerifyConRegistrosMixtosEspanolEIngles(t *testing.T) {
	l, _ := newLog(t)
	ctx := context.Background()
	for _, e := range []Entry{
		{Actor: "u", Action: "job.logintest", Target: "j1", Detail: "pasaron=1 de 2"},
		{Actor: "u", Action: "job.logintest", Target: "j2", Detail: "passed=1 of 2"},
		{Actor: "u", Action: "vault.lock", Detail: "usuario"},
		{Actor: "u", Action: "vault.lock", Detail: "reason=user"},
	} {
		if _, err := l.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	v, err := l.Verify(ctx)
	if err != nil || !v.Intact {
		t.Fatalf("verify = %+v, %v", v, err)
	}
	var b bytes.Buffer
	if err := l.Export(ctx, &b, time.Time{}, time.Now().Add(time.Hour)); err != nil || !bytes.Contains(b.Bytes(), []byte("pasaron=1 de 2")) || !bytes.Contains(b.Bytes(), []byte("passed=1 of 2")) {
		t.Fatalf("export: %v\n%s", err, b.String())
	}
}
