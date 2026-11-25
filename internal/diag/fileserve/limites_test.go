package fileserve

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func serveHTTPTest(t *testing.T, size int, on func(Transfer)) string {
	t.Helper()
	p, _ := image(t, "ios.bin", size)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ready := make(chan string, 1)
	go Serve(ctx, Config{Addr: "127.0.0.1:0", Proto: "http", Files: []string{p},
		OnListening: func(a string) { ready <- a }, OnTransfer: on})
	return <-ready
}

// Un cliente que no lee no acapara el servidor: una IP tiene tope propio y el plazo de escritura libera el cupo.
func TestHTTPCupoPorIPYPlazoDeEscritura(t *testing.T) {
	old := httpWriteIdle
	httpWriteIdle = 300 * time.Millisecond
	t.Cleanup(func() { httpWriteIdle = old })
	addr := serveHTTPTest(t, 8<<20, func(Transfer) {})
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for i := 0; i < perClientTCP; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.(*net.TCPConn).SetReadBuffer(4 << 10)
		io.WriteString(c, "GET /ios.bin HTTP/1.1\r\nHost: x\r\n\r\n")
		bufio.NewReader(c).ReadString('\n')
		held = append(held, c)
	}
	r, err := http.Get("http://" + addr + "/ios.bin")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("la IP con %d lecturas detenidas debió recibir 503, recibió %d", len(held), r.StatusCode)
	}
	// Las lecturas detenidas vencen por plazo de escritura y el cupo vuelve.
	deadline := time.Now().Add(10 * time.Second)
	for {
		r, err := http.Head("http://" + addr + "/ios.bin")
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode == http.StatusOK {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("el cupo no volvió tras el plazo de escritura: HTTP %d", r.StatusCode)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Los HEAD repetidos de una IP no llenan la auditoría: el primero se audita y el resto solo se cuenta.
func TestHTTPAuditoriaPrimeraPorIP(t *testing.T) {
	var mu sync.Mutex
	audited, counted := 0, 0
	addr := serveHTTPTest(t, 1<<10, func(x Transfer) {
		mu.Lock()
		defer mu.Unlock()
		if x.Rejected {
			counted++
		} else {
			audited++
		}
	})
	const n = 50
	for i := 0; i < n; i++ {
		r, err := http.Head("http://" + addr + "/ios.bin")
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
	}
	// Serve espera a los handlers al cerrar; aquí basta sondear hasta ver las n entradas.
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		a, c := audited, counted
		mu.Unlock()
		if a+c == n {
			if a != 1 {
				t.Fatalf("auditadas %d, quería 1 (contadas %d)", a, c)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("llegaron %d de %d", a+c, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// El bloqueo por contraseñas erróneas vence con el reloj inyectado.
func TestLimiterBloqueoVence(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(func() time.Time { return now })
	for i := 0; i < maxAuthFails; i++ {
		l.fail("1.2.3.4")
	}
	if !l.blocked("1.2.3.4") {
		t.Fatal("debió quedar bloqueada")
	}
	if _, ok := l.acquire("1.2.3.4"); ok {
		t.Fatal("bloqueada no debe adquirir cupo")
	}
	now = now.Add(lockoutFor - time.Second)
	if !l.blocked("1.2.3.4") {
		t.Fatal("aún no vence")
	}
	now = now.Add(time.Second)
	if l.blocked("1.2.3.4") {
		t.Fatal("debió vencer")
	}
	if rel, ok := l.acquire("1.2.3.4"); !ok {
		t.Fatal("tras el plazo debe dejar intentar")
	} else {
		rel()
	}
	l.fail("1.2.3.4") // empieza de cero
	if l.blocked("1.2.3.4") {
		t.Fatal("un solo fallo tras vencer no bloquea")
	}
}
