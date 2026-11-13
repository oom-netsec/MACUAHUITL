package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenCreates0600(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.db")
	db, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %o, want 600", fi.Mode().Perm())
	}
}

func TestMigrateIdempotent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.db")
	files, err := migrations.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		db, err := Open(p)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != len(files) {
			t.Fatalf("migrations = %d, want %d", n, len(files))
		}
		db.Close()
	}
}

func TestAuditLogAppendOnly(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO audit_log(seq,at,actor,action,target,detail,prev,hash) VALUES(1,'t','a','x','y','z','p','h')`); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`UPDATE audit_log SET detail='w'`, `DELETE FROM audit_log`} {
		_, err := db.Exec(q)
		if err == nil || !strings.Contains(err.Error(), "solo inserción") {
			t.Errorf("%s: err = %v, want 'solo inserción'", q, err)
		}
	}
}

func TestTablesExist(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, tbl := range []string{"devices", "device_profiles", "jobs", "job_runs", "run_devices", "credentials_ref", "playbooks_index", "settings", "audit_log"} {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&n); err != nil || n != 1 {
			t.Errorf("table %s missing (err=%v)", tbl, err)
		}
	}
}

// Las dos ramas de origen numeraron "0002": una base migrada por cualquiera de ellas debe abrir
// con el esquema completo y sin volver a aplicar lo ya hecho.
func TestMigrateFromEitherBranch(t *testing.T) {
	cases := map[string][]string{
		"solo preferencias (rama de módulos)":    {"0001_init.sql", "0002_preferences.sql"},
		"historial con el nombre viejo (fase 8)": {"0001_init.sql", "0002_job_history.sql"},
		"base nueva":                             nil,
	}
	for name, applied := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "m.db")
			if applied != nil {
				seed(t, p, applied)
			}
			db, err := Open(p)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(`INSERT INTO jobs(id,name,spec_json,state,created_at,history_json) VALUES('j','n','{}','created','t','{"round":2}')`); err != nil {
				t.Fatalf("jobs sin history_json: %v", err)
			}
			if _, err := db.Exec(`INSERT INTO preferences(key,value,updated_at) VALUES('k','v','t')`); err != nil {
				t.Fatalf("sin preferences: %v", err)
			}
			var n int
			db.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&n)
			if _, err := db.Exec(`INSERT INTO scripts VALUES('i','n','l2','ios-xe','','[]','[]','t','t')`); err != nil {
				t.Fatalf("sin scripts: %v", err)
			}
			if _, err := db.Exec(`INSERT INTO script_collection_items(collection_id, script_id, position) VALUES('favoritos','lib-x',0)`); err != nil {
				t.Fatalf("sin la colección favoritos: %v", err)
			}
			if _, err := db.Exec(`INSERT INTO pack_removed VALUES('ios-xe/x','oom/ios-xe')`); err != nil {
				t.Fatalf("sin pack_removed: %v", err)
			}
			if _, err := db.Exec(`INSERT INTO hosts VALUES('h','n','10.0.0.1',22,'','','[]','','','t','t')`); err != nil {
				t.Fatalf("sin hosts: %v", err)
			}
			if _, err := db.Exec(`INSERT INTO hosts VALUES('h2','N','10.0.0.2',22,'','','[]','','','t','t')`); err == nil {
				t.Fatal("el nombre de un host no se repite aunque cambien las mayúsculas")
			}
			want := 7 // 0001, preferences, historial, scripts, colecciones, hosts, paquetes quitados
			if applied != nil && applied[1] == "0002_job_history.sql" {
				want = 8 // además queda la fila con el nombre viejo
			}
			if n != want {
				t.Fatalf("migraciones registradas = %d, want %d", n, want)
			}
		})
	}
}

// seed deja una base como la habría dejado una versión anterior: aplica solo esos archivos.
func seed(t *testing.T, path string, files []string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Exec(`CREATE TABLE schema_migrations(version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`)
	for _, f := range files {
		body, err := migrations.ReadFile("migrations/" + f)
		if err != nil {
			// el archivo viejo ya no existe: su efecto es esta columna
			body = []byte(`ALTER TABLE jobs ADD COLUMN history_json TEXT NOT NULL DEFAULT '{}';`)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatal(err)
		}
		db.Exec(`INSERT INTO schema_migrations VALUES(?, 't')`, "migrations/"+f)
	}
}

// Un error al consultar el nombre viejo de una migración se devuelve con su nombre, no se ignora.
func TestMigrationAppliedDevuelveElError(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := migrationApplied(db, "migrations/0001_init.sql"); err != nil || !ok {
		t.Fatalf("aplicada = %v %v", ok, err)
	}
	if ok, err := migrationApplied(db, "migrations/no_existe.sql"); err != nil || ok {
		t.Fatalf("no aplicada = %v %v", ok, err)
	}
	db.Close()
	if _, err := migrationApplied(db, "migrations/0001_init.sql"); err == nil || !strings.Contains(err.Error(), "0001_init.sql") {
		t.Fatalf("base cerrada: %v", err)
	}
}

// La base de la fase 28c (hasta 0004) con favoritos de usuario y de biblioteca pasa a la colección «favoritos»
// sin perder ninguno, ordenados por nombre; la tabla vieja desaparece y los fijados arrancan vacíos.
func TestMigracionFavoritosALaColeccion(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.db")
	seed(t, p, []string{"0001_init.sql", "0002_preferences.sql", "0003_job_history.sql", "0004_scripts.sql"})
	raw, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO scripts VALUES('u2','beta','l2','ios','','[]','[]','t','t')`,
		`INSERT INTO scripts VALUES('u1','Zulu','l2','ios','','[]','[]','t','t')`,
		`INSERT INTO scripts VALUES('u3','sin favorito','l2','ios','','[]','[]','t','t')`,
		`INSERT INTO script_favorites(id) VALUES('u2'),('u1'),('lib-l2-stp'),('lib-a'),('u-borrado')`,
	} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	raw.Close()

	db, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var name string
	if err := db.QueryRow(`SELECT name FROM script_collections WHERE id = 'favoritos'`).Scan(&name); err != nil || name != "Favoritos" {
		t.Fatalf("colección favoritos: %q %v", name, err)
	}
	rows, err := db.Query(`SELECT script_id FROM script_collection_items WHERE collection_id = 'favoritos' ORDER BY position`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		got = append(got, id)
	}
	rows.Close()
	// por nombre sin importar mayúsculas; los de biblioteca no tienen nombre en la base y ordenan por su ID
	if want := "u2,lib-a,lib-l2-stp,u1"; strings.Join(got, ",") != want {
		t.Fatalf("favoritos migrados = %v, quiero %s", got, want)
	}
	if _, err := db.Exec(`SELECT 1 FROM script_favorites`); err == nil {
		t.Error("script_favorites debió desaparecer")
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM script_pins`).Scan(&n); err != nil || n != 0 {
		t.Errorf("fijados = %d %v", n, err)
	}
	// una base nueva (sin favoritos) también tiene la colección, vacía
	db2, err := Open(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if err := db2.QueryRow(`SELECT count(*) FROM script_collections WHERE id = 'favoritos' AND position = 0`).Scan(&n); err != nil || n != 1 {
		t.Errorf("base nueva: favoritos = %d %v", n, err)
	}
}
