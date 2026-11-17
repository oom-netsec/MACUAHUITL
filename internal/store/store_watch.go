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
	startWatch = func(db *sql.DB) { go watch(db, watchLimit, watchEvery, onStuck) }
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
