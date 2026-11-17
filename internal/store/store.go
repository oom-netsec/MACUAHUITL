// Package store maneja SQLite (modernc.org/sqlite, WAL), migraciones
// versionadas y el esquema compartido por los demás paquetes.
//
// No hace: guardar secretos; solo IDs opacos de credenciales.
package store

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Open abre (o crea con permisos 0600) la base y aplica las migraciones pendientes.
// SQLite crea los archivos -wal y -shm con los mismos permisos que la base.
func Open(path string) (*sql.DB, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	f.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	// _txlock=immediate: las transacciones toman el bloqueo de escritura al empezar, así busy_timeout aplica (con BEGIN diferido, SELECT+INSERT falla al instante con BUSY_SNAPSHOT).
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	// Una sola conexión: el bloqueo de escritura de SQLite no es justo (en Windows un escritor insistente deja sin turno al que sondea) y el núcleo es el único proceso que abre la base, así que se serializa aquí en vez de competir.
	// Con una sola conexión, no se usa db mientras una tx o unas rows abiertas la tengan tomada: se interbloquea.
	db.SetMaxOpenConns(1)
	if testing.Testing() {
		go watch(db, watchLimit, watchEvery, onStuck)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// legacy: migraciones renumeradas. La fase 8 la llamó 0002 y chocó con las preferencias.
var legacy = map[string]string{"migrations/0003_job_history.sql": "migrations/0002_job_history.sql"}

func migrationApplied(db *sql.DB, name string) (bool, error) {
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version = ?`, name).Scan(&n); err != nil {
		return false, fmt.Errorf("store: %s: %w", name, err)
	}
	return n > 0, nil
}

func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations(version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("store: migraciones: %w", err)
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		done, err := migrationApplied(db, name)
		if err != nil {
			return err
		}
		if !done && legacy[name] != "" {
			// La base ya aplicó esta migración con su nombre anterior: se registra sin repetirla.
			if done, err = migrationApplied(db, legacy[name]); err != nil {
				return err
			}
			if done {
				if _, err := db.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`, name, time.Now().UTC().Format(time.RFC3339)); err != nil {
					return fmt.Errorf("store: %s: %w", name, err)
				}
			}
		}
		if done {
			continue
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`, name, time.Now().UTC().Format(time.RFC3339)); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: %s: %w", name, err)
		}
	}
	return nil
}

// Vigía solo de pruebas: con una sola conexión, un interbloqueo (usar db con una tx abierta en la misma goroutine) se cuelga mudo; aquí se vuelve un panic con todos los stacks.
// Variables para que las pruebas usen valores chicos.
var (
	watchLimit = 2 * time.Second
	watchEvery = 100 * time.Millisecond
	onStuck    = func(stacks []byte) {
		panic("store: espera de conexión colgada, posible interbloqueo\n\n" + string(stacks))
	}
)

func allStacks() []byte {
	for n := 1 << 20; ; n *= 2 {
		buf := make([]byte, n)
		if k := runtime.Stack(buf, true); k < n {
			return buf[:k]
		}
	}
}

// watch usa WaitCount (sube al empezar una espera), WaitDuration (sube al terminarla) e InUse (0 = nadie tiene la
// conexión, luego nadie espera). Las estadísticas no distinguen al dueño que trabaja del que espera y pueden contar de
// más (esperas que empiezan y terminan en un muestreo, o que miden 0 con el reloj grueso de Windows): antes de disparar
// se confirma en los stacks que alguien espera en este DB.
func watch(db *sql.DB, limit, every time.Duration, stuck func([]byte)) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	var lastWC, lastWD, pending int64
	var since time.Time
	tk := time.NewTicker(every)
	defer tk.Stop()
	for range tk.C {
		// Con el contexto cancelado, Ping no espera la conexión (no cuenta como espera) y solo falla distinto si el DB se cerró.
		// database/sql no exporta errDBClosed: su texto es la única señal pública (estable desde Go 1.0).
		if err := db.PingContext(canceled); err != nil && err.Error() == "sql: database is closed" {
			return
		}
		st := db.Stats()
		wc, wd := st.WaitCount, int64(st.WaitDuration)
		switch {
		case st.InUse == 0: // nadie tiene la conexión: nadie espera
			pending, since = 0, time.Time{}
		case wd != lastWD: // terminó alguna espera; las que empezaron en este muestreo quizá sigan
			pending, since = wc-lastWC, time.Time{}
		default:
			pending += wc - lastWC
		}
		if pending > 0 && since.IsZero() {
			since = time.Now()
		}
		lastWC, lastWD = wc, wd
		if pending > 0 && time.Since(since) > limit {
			if s := allStacks(); bytes.Contains(s, fmt.Appendf(nil, "database/sql.(*DB).conn(%p,", db)) {
				stuck(s)
			}
			pending, since = 0, time.Time{}
		}
	}
}
