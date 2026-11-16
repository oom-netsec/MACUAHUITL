package ipc

import "testing"

func TestCoreRunningSondaReal(t *testing.T) {
	p := sockPath(t)
	if up, err := coreRunning(p); up || err != nil {
		t.Fatalf("sin servidor: coreRunning = %v, %v; quería false, nil", up, err)
	}
	l, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	serve(t, l)
	if up, err := coreRunning(p); !up || err != nil {
		t.Fatalf("con servidor: coreRunning = %v, %v; quería true, nil", up, err)
	}
}
