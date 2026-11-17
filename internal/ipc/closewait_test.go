package ipc

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type cierreColgado struct{ net.Listener }

func (cierreColgado) Close() error { select {} }

func TestCloseWaitNoSeCuelga(t *testing.T) {
	l := closeWait{Listener: cierreColgado{}, max: 50 * time.Millisecond}
	done := make(chan struct{})
	go func() { l.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close esperó al listener colgado")
	}
}

// go-winio: el primer Close puede perder la señal (la consume un select que no la traduce) y quedar colgado; un segundo
// Close sí la recibe y destraba a ambos. closeWait debe reenviarla.
type cierreSegundoDestraba struct {
	net.Listener
	n       atomic.Int32
	release chan struct{}
}

func (c *cierreSegundoDestraba) Close() error {
	if c.n.Add(1) == 1 {
		<-c.release
		return nil
	}
	close(c.release)
	return nil
}

func TestCloseWaitReenviaElCierre(t *testing.T) {
	f := &cierreSegundoDestraba{release: make(chan struct{})}
	l := closeWait{Listener: f, max: 5 * time.Second, every: 10 * time.Millisecond}
	done := make(chan struct{})
	go func() { l.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close no volvió con un listener que pierde la primera señal")
	}
	if f.n.Load() < 2 {
		t.Fatalf("Close real llamado %d veces, quería >= 2", f.n.Load())
	}
}
