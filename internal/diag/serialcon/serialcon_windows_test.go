//go:build windows

package serialcon

import (
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// En el runner no hay puertos: basta con que la lectura real del registro no falle ni devuelva basura.
func TestListRegistroReal(t *testing.T) {
	for _, n := range List() {
		if _, ok := comNum(n); !ok {
			t.Errorf("valor inesperado %q", n)
		}
	}
}

func TestOpenAbsentePuertoNoExiste(t *testing.T) {
	if _, err := Open(Config{Path: "COM250"}); err == nil {
		t.Fatal("COM250 no debería abrir")
	}
	if _, err := Open(Config{Path: `C:\x`}); err == nil {
		t.Fatal("ruta arbitraria aceptada")
	}
}

// Un COM abierto por otra app (ACCESS_DENIED o SHARING_VIOLATION) es «en uso», como EBUSY en Linux; no un permiso.
func TestOpenErrEnUso(t *testing.T) {
	for _, e := range []error{windows.ERROR_ACCESS_DENIED, windows.ERROR_SHARING_VIOLATION} {
		var ie *i18n.Error
		if err := openErr(`\\.\COM3`, e); !errors.As(err, &ie) || ie.Code != "serial.err.busy" {
			t.Errorf("%v: %v", e, err)
		}
	}
	var ie *i18n.Error
	if err := openErr(`\\.\COM3`, windows.ERROR_FILE_NOT_FOUND); !errors.As(err, &ie) || ie.Code != "serial.err.missing" {
		t.Errorf("no existe: %v", err)
	}
}

func TestNormalizeDejaCOMn(t *testing.T) {
	c, err := Config{Path: `\\.\com3`}.Normalize()
	if err != nil || c.Path != "COM3" {
		t.Fatalf("Path = %q, %v", c.Path, err)
	}
}

// Varios Read concurrentes sobre un mismo Port comparten el evento rev: rmu los serializa y cada uno recibe su byte.
func TestReadConcurrenteSerializado(t *testing.T) {
	name, _ := windows.UTF16PtrFromString(`\\.\pipe\mctl-serialcon-test-` + t.Name())
	srv, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT, 1, 4096, 4096, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		windows.CloseHandle(srv)
		t.Fatal(err)
	}
	defer windows.CloseHandle(cli)
	rev, _ := windows.CreateEvent(nil, 1, 0, nil)
	wev, _ := windows.CreateEvent(nil, 1, 0, nil)
	p := &Port{h: srv, rev: rev, wev: wev}
	const n = 8
	var wg sync.WaitGroup
	got := make(chan int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := make([]byte, 1)
			k, err := p.Read(b)
			if err != nil {
				t.Error(err)
			}
			got <- k
		}()
	}
	for i := 0; i < n; i++ {
		var w uint32
		if err := windows.WriteFile(cli, []byte{byte(i)}, &w, nil); err != nil {
			t.Fatal(err)
		}
	}
	fin := make(chan struct{})
	go func() { wg.Wait(); close(fin) }()
	select {
	case <-fin:
	case <-time.After(10 * time.Second):
		windows.CancelIoEx(srv, nil)
		t.Fatal("los lectores no terminaron en 10 s")
	}
	close(got)
	tot := 0
	for k := range got {
		tot += k
	}
	if tot != n {
		t.Fatalf("leí %d bytes, quiero %d", tot, n)
	}
	p.free()
}
