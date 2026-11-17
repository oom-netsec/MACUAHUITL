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
	l, e, s := watchLimit, watchEvery, onStuck
	ch := make(chan []byte, 4)
	watchLimit, watchEvery = 300*time.Millisecond, 20*time.Millisecond
	onStuck = func(b []byte) { ch <- b }
	t.Cleanup(func() { watchLimit, watchEvery, onStuck = l, e, s })
	return ch
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
