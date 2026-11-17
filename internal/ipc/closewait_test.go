package ipc

import (
	"net"
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
