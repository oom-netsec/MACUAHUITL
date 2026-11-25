package fileserve

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func serveHTTPTest(t *testing.T, size int, on func(Transfer)) string {
	t.Helper()
	return serveHTTPCfg(t, size, func(c *Config) { c.OnTransfer = on })
}

func serveHTTPCfg(t *testing.T, size int, tune func(*Config)) string {
	t.Helper()
	p, _ := image(t, "ios.bin", size)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ready := make(chan string, 1)
	cfg := Config{Addr: "127.0.0.1:0", Proto: "http", Files: []string{p},
		OnListening: func(a string) { ready <- a }, OnTransfer: func(Transfer) {}}
	tune(&cfg)
	go Serve(ctx, cfg)
	return <-ready
}

// Un cliente que no lee no acapara el servidor: una IP tiene tope propio y el plazo de escritura libera el cupo.
func TestHTTPCupoPorIPYPlazoDeEscritura(t *testing.T) {
	var mu sync.Mutex
	perIPReason := false
	old := httpWriteIdle
	httpWriteIdle = 300 * time.Millisecond
	t.Cleanup(func() { httpWriteIdle = old })
	addr := serveHTTPCfg(t, 64<<20, func(c *Config) {
		c.OnTransfer = func(x Transfer) {
			mu.Lock()
			defer mu.Unlock()
			if x.Rejected && x.Cause == CauseBusy && x.ReasonT.Key == "fileserve.reason.many_from_client" {
				perIPReason = true
			}
		}
	})
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
	mu.Lock()
	if !perIPReason {
		t.Error("el 503 por cupo de IP debe usar many_from_client")
	}
	mu.Unlock()
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
			if a != auditPerWindow {
				t.Fatalf("auditadas %d, quería %d (contadas %d)", a, auditPerWindow, c)
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

func get(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	return r
}

// Toda sesión abierta (OnStart) termina en una transferencia no rechazada; los rechazos no abren sesión.
func TestHTTPSesionNuncaTerminaRechazada(t *testing.T) {
	var mu sync.Mutex
	started := map[*Live]bool{}
	finished := map[*Live]bool{}
	rejected := 0
	addr := serveHTTPCfg(t, 0, func(c *Config) {
		c.OnStart = func(l *Live) { mu.Lock(); started[l] = true; mu.Unlock() }
		c.OnTransfer = func(x Transfer) {
			mu.Lock()
			defer mu.Unlock()
			if x.Rejected {
				rejected++
				if x.Live != nil {
					t.Errorf("rechazo con sesión")
				}
			} else if x.Live != nil {
				finished[x.Live] = true
			}
		}
	})
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("GET", "http://"+addr+"/ios.bin", nil)
		get(t, req)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	for l := range started {
		if !finished[l] {
			t.Fatalf("sesión abierta que no terminó como transferencia: %d abiertas, %d terminadas", len(started), len(finished))
		}
	}
	if len(started) > auditPerWindow {
		t.Fatalf("%d sesiones abiertas, tope %d", len(started), auditPerWindow)
	}
}

// El cupo de auditoría vale para todo resultado: Range de 1 byte no lo esquiva, vuelve al pasar la ventana y
// una transferencia grande se audita aunque el cupo esté agotado.
func TestHTTPCupoDeAuditoria(t *testing.T) {
	var mu sync.Mutex
	now := time.Unix(5000, 0)
	audited, counted, failed := 0, 0, 0
	addr := serveHTTPCfg(t, 2*bigBody, func(c *Config) {
		c.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
		c.OnTransfer = func(x Transfer) {
			mu.Lock()
			defer mu.Unlock()
			if x.Rejected {
				counted++
				if x.Result == "error" {
					failed++
				}
			} else {
				audited++
			}
		}
	})
	rng := func() {
		req, _ := http.NewRequest("GET", "http://"+addr+"/ios.bin", nil)
		req.Header.Set("Range", "bytes=0-0")
		get(t, req)
	}
	wait := func(want int) {
		for i := 0; i < 500; i++ {
			mu.Lock()
			n := audited + counted
			mu.Unlock()
			if n >= want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("no llegaron %d registros", want)
	}
	for i := 0; i < 200; i++ {
		rng()
	}
	wait(200)
	mu.Lock()
	if audited != auditPerWindow || failed != 0 {
		t.Fatalf("auditadas %d (quería %d), contadas como fallo %d", audited, auditPerWindow, failed)
	}
	now = now.Add(auditWindow)
	mu.Unlock()
	rng()
	wait(201)
	mu.Lock()
	if audited != auditPerWindow+1 {
		t.Fatalf("tras la ventana debió auditar otra: %d", audited)
	}
	mu.Unlock()
	// cupo agotado y aun así la imagen entera (>= bigBody) se audita
	req, _ := http.NewRequest("GET", "http://"+addr+"/ios.bin", nil)
	get(t, req)
	wait(202)
	mu.Lock()
	defer mu.Unlock()
	if audited != auditPerWindow+2 {
		t.Fatalf("la transferencia grande debió auditarse: %d", audited)
	}
}

// El mapa de cupos de auditoría no crece sin límite.
func TestAuditQuotaAcotado(t *testing.T) {
	now := time.Unix(1, 0)
	q := newAuditQuota(func() time.Time { return now })
	for i := 0; i < maxSeenIPs+500; i++ {
		q.take(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String())
	}
	if len(q.m) > maxSeenIPs {
		t.Fatalf("mapa de %d entradas", len(q.m))
	}
}

// Los fallos bajo el umbral también vencen.
func TestLimiterFallosVencen(t *testing.T) {
	now := time.Unix(1000, 0)
	l := newLimiter(func() time.Time { return now })
	for i := 0; i < maxAuthFails-1; i++ {
		l.fail("a")
	}
	now = now.Add(lockoutFor)
	l.fail("a")
	if l.blocked("a") {
		t.Fatal("los fallos viejos no cuentan")
	}
}
