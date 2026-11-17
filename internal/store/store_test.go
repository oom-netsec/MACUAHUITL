package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/sys/systest"
)

func TestOpenCreates0600(t *testing.T) {
	p := filepath.Join(systest.TempDir(t), "m.db")
	db, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	systest.Inherited(t, p, 0o600) // en Windows hereda la DACL de la carpeta privada
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
			want := 9 // 0001, preferences, historial, scripts, colecciones, hosts, paquetes quitados, ocultos de paquetes, índice de auditoría
			if applied != nil && applied[1] == "0002_job_history.sql" {
				want = 10 // además queda la fila con el nombre viejo
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

// Una sola conexión: nadie debe quitarlo sin darse cuenta (el bloqueo de escritura de SQLite no es justo).
func TestOpenUnaSolaConexion(t *testing.T) {
	db, err := Open(filepath.Join(systest.TempDir(t), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if n := db.Stats().MaxOpenConnections; n != 1 {
		t.Fatalf("MaxOpenConnections = %d, quiero 1", n)
	}
}

// Varias goroutines escriben (Exec y transacciones) y leen a la vez sobre el mismo *sql.DB: ninguna falla con BUSY.
func TestEscrituraConcurrenteSinBusy(t *testing.T) {
	db, err := Open(filepath.Join(systest.TempDir(t), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const workers, each = 8, 50
	errs := make(chan error, workers*each*3)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				k := fmt.Sprintf("k%d-%d", w, i)
				if _, err := db.Exec(`INSERT OR REPLACE INTO preferences(key,value,updated_at) VALUES(?,?,?)`, k, "v", "t"); err != nil {
					errs <- err
				}
				tx, err := db.Begin()
				if err != nil {
					errs <- err
					continue
				}
				if _, err := tx.Exec(`UPDATE preferences SET value = 'w' WHERE key = ?`, k); err != nil {
					errs <- err
				}
				if err := tx.Commit(); err != nil {
					errs <- err
				}
				var n int
				if err := db.QueryRow(`SELECT count(*) FROM preferences`).Scan(&n); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("%v", err)
	}
}

// vigilar baja el umbral del vigía y cambia su acción por un aviso por canal.
func vigilar(t *testing.T) <-chan []byte {
	t.Helper()
	l, e, s := watchLimit, watchEvery, onStuck
	ch := make(chan []byte, 4)
	watchLimit, watchEvery = 300*time.Millisecond, 20*time.Millisecond
	onStuck = func(b []byte) { ch <- b }
	t.Cleanup(func() { watchLimit, watchEvery, onStuck = l, e, s })
	return ch
}

func abrirVigia(t *testing.T) *sql.DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestVigiaInterbloqueo(t *testing.T) {
	ch := vigilar(t)
	db := abrirVigia(t)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		db.Exec(`CREATE TABLE IF NOT EXISTS x(a)`) // espera la conexión que tiene tx
	}()
	select {
	case b := <-ch:
		if !strings.Contains(string(b), "TestVigiaInterbloqueo.func1") {
			t.Fatalf("los stacks no incluyen a la culpable:\n%s", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("el vigía no disparó")
	}
	tx.Rollback()
	<-done
}

func TestVigiaTxLargaSinEsperaNoDispara(t *testing.T) {
	ch := vigilar(t)
	db := abrirVigia(t)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1 * time.Second) // mucho más que el umbral
	tx.Rollback()
	select {
	case <-ch:
		t.Fatal("disparó sin nadie esperando")
	default:
	}
}

func TestVigiaEsperasCortasNoDisparan(t *testing.T) {
	ch := vigilar(t)
	db := abrirVigia(t)
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				tx, err := db.Begin()
				if err != nil {
					return
				}
				time.Sleep(5 * time.Millisecond)
				tx.Rollback()
			}
		}()
	}
	wg.Wait() // ~4 s de esperas continuas que terminan (4×200×5 ms en serie), más que el umbral
	select {
	case <-ch:
		t.Fatal("disparó con esperas que terminan")
	default:
	}
}

// La culpable espera la conexión (Begin), la recibe y enseguida espera otra vez (Exec con su tx abierta):
// fin e inicio de espera caen en el mismo muestreo y aun así el vigía tiene que disparar.
func TestVigiaInterbloqueoTrasUnaEspera(t *testing.T) {
	ch := vigilar(t)
	db := abrirVigia(t)
	hold, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	txc := make(chan *sql.Tx, 1)
	go func() {
		defer close(done)
		tx, err := db.Begin() // espera a hold
		txc <- tx
		if err != nil {
			return
		}
		db.Exec(`CREATE TABLE IF NOT EXISTS x(a)`) // interbloqueo: espera la conexión que tiene su propia tx
	}()
	time.Sleep(50 * time.Millisecond)
	hold.Rollback()
	select {
	case b := <-ch:
		if !strings.Contains(string(b), "TestVigiaInterbloqueoTrasUnaEspera.func1") {
			t.Fatalf("los stacks no incluyen a la culpable:\n%s", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("el vigía no disparó")
	}
	if tx := <-txc; tx != nil {
		tx.Rollback()
	}
	<-done
}

// Una espera corta que termina, seguida de una tx larga sin nadie esperando, no es un interbloqueo.
func TestVigiaEsperaCortaYTxLargaNoDispara(t *testing.T) {
	ch := vigilar(t)
	db := abrirVigia(t)
	hold, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan *sql.Tx)
	go func() {
		tx, _ := db.Begin() // espera corta
		got <- tx
	}()
	time.Sleep(5 * time.Millisecond)
	hold.Rollback()
	tx := <-got
	time.Sleep(time.Second) // tx larga, nadie espera
	tx.Rollback()
	select {
	case <-ch:
		t.Fatal("disparó sin nadie esperando")
	default:
	}
}

func TestIndiceAuditAt(t *testing.T) {
	db := abrirVigia(t)
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM pragma_index_list('audit_log') WHERE name='idx_audit_log_at'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("falta idx_audit_log_at: n=%d err=%v", n, err)
	}
}
