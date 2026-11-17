package ipc

import (
	"net"
	"time"
)

// closeWait acota cuánto espera Close del listener y reenvía el cierre. go-winio v0.6.2 pierde la señal de cierre de dos
// formas: (a) un cliente corta mientras Close aborta un ConnectNamedPipe: makeConnectedServerPipe consume closeCh, el
// error no se traduce a ErrPipeListenerClosed, listenerRoutine vuelve a su select y Close espera doneCh para siempre
// (visto en el job windows de CI, TestDialPipeRechazaDuenoAjeno, 25 min); (b) ERROR_NO_DATA: listenerRoutine reintenta
// tras consumir closeCh y Accept (grpc.Serve) queda sin salida, con grpc.Server.Stop esperando a Serve. En ambos casos un
// Close adicional lo recibe el select que esté esperando y la rutina termina; por eso se repite cada `every` hasta `max`.
// Las goroutines de cierre sobrantes salen solas cuando go-winio cierra doneCh.
type closeWait struct {
	net.Listener
	max   time.Duration
	every time.Duration // cada cuánto se reenvía el cierre (0 = 200 ms)
}

func (l closeWait) Close() error {
	every := l.every
	if every <= 0 {
		every = 200 * time.Millisecond
	}
	done := make(chan error, 1)
	call := func() {
		err := l.Listener.Close()
		select {
		case done <- err:
		default:
		}
	}
	go call()
	tick := time.NewTicker(every)
	defer tick.Stop()
	t := time.NewTimer(l.max)
	defer t.Stop()
	for {
		select {
		case err := <-done:
			return err
		case <-tick.C:
			go call()
		case <-t.C:
			return nil
		}
	}
}
