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

func (l *Log) scan(ctx context.Context, where string, args []any, fn func(Record, string) bool) error {
	rows, err := l.db.QueryContext(ctx, `SELECT seq,at,actor,action,target,detail,prev,hash FROM audit_log `+where+` ORDER BY seq`, args...)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var r Record
		var at string
		if err := rows.Scan(&r.Seq, &at, &r.Actor, &r.Action, &r.Target, &r.Detail, &r.Prev, &r.Hash); err != nil {
			return fmt.Errorf("audit: %w", err)
		}
		r.At, _ = time.Parse(tsFormat, at)
		if !fn(r, at) {
			break
		}
	}
	return rows.Err()
}

// Verify recorre la cadena completa y reporta el primer registro roto.
func (l *Log) Verify(ctx context.Context) (VerifyResult, error) {
	res := VerifyResult{Intact: true, Head: Genesis}
	expected := Genesis
	var next uint64 = 1
	err := l.scan(ctx, "", nil, func(r Record, at string) bool {
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
	err := l.scan(ctx, "WHERE at >= ? AND at < ?", []any{from.UTC().Format(tsFormat), to.UTC().Format(tsFormat)}, func(r Record, _ string) bool {
		werr = enc.Encode(r)
		return werr == nil
	})
	if err != nil {
		return err
	}
	return werr
}
