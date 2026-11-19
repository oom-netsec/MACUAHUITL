//go:build storewatch

package store

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"runtime"
	"time"
)

// Con -tags storewatch (CI y ./dev.sh test), cada base abierta lleva el vigía de esperas colgadas.
func init() {
	startWatch = func(db *sql.DB) { go watch(db, watchLimit, watchSlow, watchEvery, driverFrame, onStuck) }
}

// Vigía solo de pruebas: con una sola conexión, un interbloqueo (usar db con una tx abierta en la misma goroutine) se cuelga mudo; aquí se vuelve un panic con todos los stacks.
// Variables para que las pruebas usen valores chicos.
// Si alguna goroutine está dentro del driver (driverFrame en su stack), la dueña de la conexión trabaja: un fsync o
// FlushFileBuffers lento del runner de Windows retiene la única conexión segundos. Eso no es un interbloqueo; se espera
// hasta watchSlow y, si no vuelve, se avisa con su propio motivo.
var (
	watchLimit  = 2 * time.Second
	watchSlow   = 30 * time.Second
	watchEvery  = 100 * time.Millisecond
	driverFrame = "modernc.org/sqlite."
	onStuck     = func(motivo string, stacks []byte) {
		panic("store: " + motivo + "\n\n" + string(stacks))
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
//
// Otra goroutine dentro del driver con otra base también cuenta como trabajo: un interbloqueo real en ese momento se
// avisa a los watchSlow en vez de a los limit.
func watch(db *sql.DB, limit, slow, every time.Duration, frame string, stuck func(string, []byte)) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	var lastWC, lastWD, pending int64
	var since, recheck time.Time
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
		if pending > 0 && time.Since(since) > limit && time.Now().After(recheck) {
			s := allStacks()
			switch waited := time.Since(since); {
			case !bytes.Contains(s, fmt.Appendf(nil, "database/sql.(*DB).conn(%p,", db)):
			case !bytes.Contains(s, []byte(frame)):
				stuck("espera de conexión colgada, posible interbloqueo", s)
			case waited <= slow:
				recheck = time.Now().Add(limit) // I/O en curso: se vuelve a mirar sin reiniciar since
				continue
			default:
				stuck(fmt.Sprintf("una espera de conexión lleva %s mientras alguna goroutine sigue dentro del driver: disco lento o colgado, o un interbloqueo en esta base mientras otra trabaja", waited.Round(time.Second)), s)
			}
			pending, since, recheck = 0, time.Time{}, time.Time{}
		}
	}
}
