//go:build storewatch

package store

import (
	"database/sql"
	"strings"
	"sync"
	"testing"
	"time"
)

// vigilar baja el umbral del vigía y cambia su acción por un aviso por canal.
func vigilar(t *testing.T) <-chan []byte {
	t.Helper()
	l, sl, e, f, s := watchLimit, watchSlow, watchEvery, driverFrame, onStuck
	ch := make(chan []byte, 4)
	watchLimit, watchSlow, watchEvery = 300*time.Millisecond, 2500*time.Millisecond, 20*time.Millisecond
	driverFrame = "store.ioLenta(" // un marco que la prueba controla, en lugar del de modernc.org/sqlite
	onStuck = func(motivo string, b []byte) { ch <- append([]byte(motivo+"\n\n"), b...) }
	t.Cleanup(func() { watchLimit, watchSlow, watchEvery, driverFrame, onStuck = l, sl, e, f, s })
	return ch
}

// ioLenta retiene la conexión de tx como un fsync lento de Windows (FlushFileBuffers): con su marco en el stack,
// la dueña de la conexión está trabajando dentro del driver.
//
//go:noinline
func ioLenta(tx *sql.Tx, hasta <-chan struct{}) {
	<-hasta
	tx.Rollback()
}

// retenerEnDriver abre una tx, la deja dentro de ioLenta y pone a otra goroutine a esperar la conexión.
func retenerEnDriver(t *testing.T, db *sql.DB) (soltar func()) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	hasta, fin := make(chan struct{}), make(chan struct{})
	go ioLenta(tx, hasta)
	go func() {
		defer close(fin)
		db.Exec(`CREATE TABLE IF NOT EXISTS x(a)`) // espera legítima: la conexión vuelve al terminar la I/O
	}()
	var once sync.Once
	soltar = func() { once.Do(func() { close(hasta); <-fin }) }
	t.Cleanup(soltar)
	return soltar
}

// Hallazgo del CI de Windows (#287): la dueña de la conexión estaba en FlushFileBuffers dentro de Commit y otra
// goroutine esperaba la conexión; no es un interbloqueo y no debe disparar con el umbral corto.
func TestVigiaIOLentaNoEsInterbloqueo(t *testing.T) {
	ch := vigilar(t)
	db := abrirVigia(t)
	soltar := retenerEnDriver(t, db)
	select {
	case b := <-ch:
		t.Fatalf("disparó con la dueña trabajando en el driver:\n%s", b)
	case <-time.After(1 * time.Second): // más de tres veces watchLimit y lejos de watchSlow (margen para un runner cargado)
	}
	soltar()
	select {
	case b := <-ch:
		t.Fatalf("disparó tras terminar la I/O:\n%s", b)
	case <-time.After(300 * time.Millisecond):
	}
}

// Si la I/O no vuelve nunca, el vigía avisa igual pasado watchSlow, con un motivo que no dice interbloqueo.
func TestVigiaIOColgadaDisparaConSuMotivo(t *testing.T) {
	ch := vigilar(t)
	db := abrirVigia(t)
	inicio := time.Now()
	retenerEnDriver(t, db)
	select {
	case b := <-ch:
		if d := time.Since(inicio); d < watchSlow {
			t.Fatalf("disparó a los %s, antes de watchSlow", d)
		}
		if !strings.HasPrefix(string(b), "una espera de conexión lleva ") || !strings.Contains(string(b), "dentro del driver") {
			t.Fatalf("motivo equivocado:\n%.200s", b)
		}
		if !strings.Contains(string(b), "store.ioLenta(") {
			t.Fatalf("los stacks no incluyen a la dueña:\n%s", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("el vigía no disparó")
	}
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
		if !strings.HasPrefix(string(b), "espera de conexión colgada, posible interbloqueo") {
			t.Fatalf("motivo equivocado:\n%.200s", b)
		}
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
