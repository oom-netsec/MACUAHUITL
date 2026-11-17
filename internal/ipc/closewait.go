package ipc

import (
	"net"
	"time"
)

// closeWait acota cuánto espera Close del listener. go-winio v0.6.2 se cuelga si un cliente corta mientras Close aborta
// un ConnectNamedPipe: makeConnectedServerPipe consume closeCh, el error no se traduce a ErrPipeListenerClosed,
// listenerRoutine sigue vivo y Close espera doneCh para siempre, con grpc.Server.Stop sosteniendo su mutex (el Serve
// queda trabado y el núcleo no termina). Visto en el job windows de CI (TestDialPipeRechazaDuenoAjeno, 25 min).
// shortcut: la rutina de go-winio queda viva hasta que termina el proceso; quitarlo si go-winio corrige el cierre.
type closeWait struct {
	net.Listener
	max time.Duration
}

func (l closeWait) Close() error {
	done := make(chan error, 1)
	go func() { done <- l.Listener.Close() }()
	t := time.NewTimer(l.max)
	defer t.Stop()
	select {
	case err := <-done:
		return err
	case <-t.C:
		return nil
	}
}
