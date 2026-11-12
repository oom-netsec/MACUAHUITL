// Package store maneja SQLite (modernc.org/sqlite, WAL), migraciones
// versionadas y el esquema compartido por los demás paquetes.
//
// No hace: guardar secretos; solo IDs opacos de credenciales.
package store

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"sort"
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
