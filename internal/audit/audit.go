// Package audit lleva el log de auditoría encadenado por hashes, su
// verificación y su exportación a JSON Lines (spec §11).
//
// No hace: registrar secretos ni contenido de outputs.
package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// tsFormat tiene ancho fijo para que el orden de texto en SQLite sea el orden temporal.
const tsFormat = "2006-01-02T15:04:05.000000000Z"

// Genesis es el "hash previo" del primer registro.
var Genesis = strings.Repeat("0", 64)

// Entry es lo que registra quien llama.
type Entry struct {
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target"`
	Detail string `json:"detail"`
}

// Record es un registro ya encadenado.
type Record struct {
	Seq uint64    `json:"seq"`
	At  time.Time `json:"at"`
	Entry
	Prev string `json:"prev"`
	Hash string `json:"hash"`
}

// VerifyResult resume la verificación de la cadena.
type VerifyResult struct {
	Intact      bool
	FirstBroken uint64
	Head        string
}

// Log escribe sobre la tabla audit_log de store.
type Log struct {
	db  *sql.DB
	now func() time.Time
	mu  sync.Mutex
}

func New(db *sql.DB, now func() time.Time) *Log { return &Log{db: db, now: now} }

func hashOf(prev string, seq uint64, at string, e Entry) string {
	body, _ := json.Marshal(struct {
		Seq                           uint64
		At                            string
		Actor, Action, Target, Detail string
	}{seq, at, e.Actor, e.Action, e.Target, e.Detail})
	sum := sha256.Sum256(append([]byte(prev+"\n"), body...))
	return hex.EncodeToString(sum[:])
}

// Append agrega un registro encadenado al anterior.
func (l *Log) Append(ctx context.Context, e Entry) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// store.Open usa una sola conexión: dentro del proceso no hay BUSY. Solo un proceso externo (p. ej. alguien con
	// sqlite3 abierto) que retenga el bloqueo más que busy_timeout lo da; una entrada de auditoría no se pierde por eso:
	// se reintenta (cada intento rehace la transacción completa, seq y hash incluidos).
	for try := 1; ; try++ {
		r, err := l.appendOnce(ctx, e)
		if err == nil || !busy(err) || try == appendTries {
			return r, err
		}
		select {
		case <-ctx.Done():
			return r, err
		case <-time.After(time.Duration(try) * 50 * time.Millisecond):
		}
	}
}

// appendTries: con busy_timeout de 5 s por intento, una entrada espera hasta ~25 s antes de fallar.
const appendTries = 5

// busy: SQLITE_BUSY o una de sus variantes extendidas (el código primario va en el byte bajo).
func busy(err error) bool {
	var c interface{ Code() int }
	return errors.As(err, &c) && c.Code()&0xff == 5
}

func (l *Log) appendOnce(ctx context.Context, e Entry) (Record, error) {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, fmt.Errorf("audit: %w", err)
	}
	defer tx.Rollback()
	prev, seq := Genesis, uint64(1)
	var last uint64
	var lastHash string
	switch err := tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&last, &lastHash); err {
	case nil:
		prev, seq = lastHash, last+1
	case sql.ErrNoRows:
	default:
		return Record{}, fmt.Errorf("audit: %w", err)
	}
	at := l.now().UTC()
	atS := at.Format(tsFormat)
	r := Record{Seq: seq, At: at, Entry: e, Prev: prev, Hash: hashOf(prev, seq, atS, e)}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_log(seq,at,actor,action,target,detail,prev,hash) VALUES(?,?,?,?,?,?,?,?)`,
		r.Seq, atS, e.Actor, e.Action, e.Target, e.Detail, r.Prev, r.Hash); err != nil {
		return Record{}, fmt.Errorf("audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Record{}, fmt.Errorf("audit: %w", err)
	}
	return r, nil
}

// scanPage son las filas por consulta: la base tiene una sola conexión, así que cada página se lee entera y se
// cierra antes de llamar a fn (que puede ser lento, p. ej. escribir a un stream); la conexión queda libre entre páginas.
const scanPage = 1000

type scanned struct {
	r  Record
	at string
}

// scan recorre en orden de seq los registros que cumplen cond (un AND extra, sin WHERE) hasta que fn devuelva false.
func (l *Log) scan(ctx context.Context, after uint64, cond string, args []any, fn func(Record, string) bool) error {
	for {
		page, err := l.page(ctx, after, cond, args)
		if err != nil {
			return err
		}
		for _, x := range page {
			if !fn(x.r, x.at) {
				return nil
			}
		}
		if len(page) < scanPage {
			return nil
		}
		after = page[len(page)-1].r.Seq
	}
}

func (l *Log) page(ctx context.Context, after uint64, cond string, args []any) ([]scanned, error) {
	q := `SELECT seq,at,actor,action,target,detail,prev,hash FROM audit_log WHERE seq > ?`
	if cond != "" {
		q += " AND " + cond
	}
	rows, err := l.db.QueryContext(ctx, q+` ORDER BY seq LIMIT `+fmt.Sprint(scanPage), append([]any{after}, args...)...)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	defer rows.Close()
	var out []scanned
	for rows.Next() {
		var x scanned
		if err := rows.Scan(&x.r.Seq, &x.at, &x.r.Actor, &x.r.Action, &x.r.Target, &x.r.Detail, &x.r.Prev, &x.r.Hash); err != nil {
			return nil, fmt.Errorf("audit: %w", err)
		}
		x.r.At, _ = time.Parse(tsFormat, x.at)
		out = append(out, x)
	}
	return out, rows.Err()
}

// Verify recorre la cadena completa y reporta el primer registro roto.
func (l *Log) Verify(ctx context.Context) (VerifyResult, error) {
	res := VerifyResult{Intact: true, Head: Genesis}
	expected := Genesis
	var next uint64 = 1
	err := l.scan(ctx, 0, "", nil, func(r Record, at string) bool {
		if r.Seq != next || r.Prev != expected || hashOf(r.Prev, r.Seq, at, r.Entry) != r.Hash {
			res.Intact, res.FirstBroken = false, r.Seq
			return false
		}
		expected, res.Head = r.Hash, r.Hash
		next++
		return true
	})
	return res, err
}

// Head devuelve el hash del último registro, o Genesis si está vacío.
func (l *Log) Head(ctx context.Context) (string, error) {
	var h string
	err := l.db.QueryRowContext(ctx, `SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&h)
	if err == sql.ErrNoRows {
		return Genesis, nil
	}
	if err != nil {
		return "", fmt.Errorf("audit: %w", err)
	}
	return h, nil
}

// Export escribe en JSON Lines los registros con from <= at < to.
func (l *Log) Export(ctx context.Context, w io.Writer, from, to time.Time) error {
	enc := json.NewEncoder(w)
	var werr error
	f, t := from.UTC().Format(tsFormat), to.UTC().Format(tsFormat)
	// Con seq > ? el plan recorre por seq y no usa idx_audit_log_at: se arranca en el primer registro del rango (min(seq) con at acotado, que sí usa el índice; exacto aunque el reloj retroceda).
	var first sql.NullInt64
	if err := l.db.QueryRowContext(ctx, `SELECT min(seq) FROM audit_log WHERE at >= ? AND at < ?`, f, t).Scan(&first); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	if !first.Valid {
		return nil
	}
	err := l.scan(ctx, uint64(first.Int64)-1, "at >= ? AND at < ?", []any{f, t}, func(r Record, _ string) bool {
		werr = enc.Encode(r)
		return werr == nil
	})
	if err != nil {
		return err
	}
	return werr
}
