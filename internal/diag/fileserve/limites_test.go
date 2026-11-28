package fileserve

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

func serveHTTPCfg(t *testing.T, size int, tune func(*Config)) string {
	t.Helper()
	p, _ := image(t, "ios.bin", size)
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan string, 1), make(chan struct{})
	t.Cleanup(func() { cancel(); <-done }) // la prueba siguiente no corre con este servidor vivo
	cfg := Config{Addr: "127.0.0.1:0", Proto: "http", Files: []string{p},
		OnListening: func(a string) { ready <- a }, OnTransfer: func(Transfer) {}}
	tune(&cfg)
	go func() { Serve(ctx, cfg); close(done) }()
	select {
	case a := <-ready:
		return a
	case <-done:
		t.Fatal("Serve terminó sin escuchar")
		return ""
	}
}

// stalled abre n GET que no leen el cuerpo y espera la línea de estado de cada uno.
func stalled(t *testing.T, addr string, n int) []net.Conn {
	t.Helper()
	var held []net.Conn
	t.Cleanup(func() {
		for _, c := range held {
			c.Close()
		}
	})
	for i := 0; i < n; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.(*net.TCPConn).SetReadBuffer(4 << 10)
		io.WriteString(c, "GET /ios.bin HTTP/1.1\r\nHost: x\r\n\r\n")
		bufio.NewReader(c).ReadString('\n')
		held = append(held, c)
	}
	return held
}

// Una IP con lecturas detenidas topa en su cupo propio y recibe el motivo de cliente.
func TestHTTPCupoPorIP(t *testing.T) {
	var mu sync.Mutex
	perIPReason := false
	addr := serveHTTPCfg(t, 64<<20, func(c *Config) {
		c.OnTransfer = func(x Transfer) {
			mu.Lock()
			defer mu.Unlock()
			if x.Rejected && x.Cause == CauseBusy && x.ReasonT.Key == "fileserve.reason.many_from_client" {
				perIPReason = true
			}
		}
	})
	held := stalled(t, addr, perClientTCP)
	r, err := http.Get("http://" + addr + "/ios.bin")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("la IP con %d lecturas detenidas debió recibir 503, recibió %d", len(held), r.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if !perIPReason {
		t.Error("el 503 por cupo de IP debe usar many_from_client")
	}
}

// El plazo de escritura suelta el cupo de lecturas detenidas.
func TestHTTPPlazoDeEscritura(t *testing.T) {
	old := httpWriteIdle
	httpWriteIdle = 300 * time.Millisecond
	t.Cleanup(func() { httpWriteIdle = old })
	addr := serveHTTPCfg(t, 64<<20, func(c *Config) {})
	stalled(t, addr, perClientTCP)
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

type recorder struct {
	mu                       sync.Mutex
	audited, counted, failed int
	repeatReason             int
	rejectedWithSession      int
	started                  map[*Live]bool
	finished                 map[*Live]bool
	summaries                []Repeats
	now                      time.Time
}

func newRecorder() *recorder {
	return &recorder{started: map[*Live]bool{}, finished: map[*Live]bool{}, now: time.Unix(5000, 0)}
}

func (r *recorder) tune(c *Config) {
	c.Now = func() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now }
	c.OnStart = func(l *Live) { r.mu.Lock(); r.started[l] = true; r.mu.Unlock() }
	c.OnRepeats = func(x Repeats) { r.mu.Lock(); r.summaries = append(r.summaries, x); r.mu.Unlock() }
	c.OnTransfer = func(x Transfer) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if x.Rejected {
			r.counted++
			if x.Live != nil {
				r.rejectedWithSession++
			}
			if x.Result == "error" {
				r.failed++
			}
			if x.Cause == CauseRepeat && x.ReasonT.Key == "fileserve.reason.repeat" {
				r.repeatReason++
			}
			return
		}
		r.audited++
		if x.Live != nil {
			r.finished[x.Live] = true
		}
	}
}

func (r *recorder) wait(t *testing.T, want int) {
	t.Helper()
	for i := 0; i < 1000; i++ {
		r.mu.Lock()
		n := r.audited + r.counted
		r.mu.Unlock()
		if n >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no llegaron %d registros", want)
}

func rangeGet(t *testing.T, addr, name string) {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://"+addr+"/"+name, nil)
	req.Header.Set("Range", "bytes=0-0")
	get(t, req)
}

func mustReq(t *testing.T, u string) *http.Request {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// Lo que no entrega el archivo (Range de 1 byte, HEAD) comparte un cupo por IP: las primeras auditPerWindow se
// auditan y el resto se cuenta con motivo propio, sin sesión.
func TestHTTPCupoPorIPDeLoQueNoEntrega(t *testing.T) {
	r := newRecorder()
	addr := serveHTTPCfg(t, 1<<10, r.tune)
	for i := 0; i < 200; i++ {
		rangeGet(t, addr, "ios.bin")
	}
	r.wait(t, 200)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.audited != auditPerWindow || r.counted != 200-auditPerWindow || r.failed != 0 || r.repeatReason != 200-auditPerWindow || len(r.started) != 0 {
		t.Fatalf("auditadas %d contadas %d fallos %d motivo %d sesiones %d", r.audited, r.counted, r.failed, r.repeatReason, len(r.started))
	}
}

// Un HEAD, o muchos, no le quita la auditoría a una descarga completa del mismo archivo.
func TestHTTPDescargaCompletaSiempreSeAudita(t *testing.T) {
	r := newRecorder()
	addr := serveHTTPCfg(t, 1<<10, r.tune)
	for i := 0; i < 20; i++ {
		resp, err := http.Head("http://" + addr + "/ios.bin")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	r.wait(t, 20)
	get(t, mustReq(t, "http://"+addr+"/ios.bin"))
	r.wait(t, 21)
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.started) != 1 || len(r.finished) != 1 || r.rejectedWithSession != 0 {
		t.Fatalf("la descarga completa debió auditarse con su sesión: sesiones %d terminadas %d", len(r.started), len(r.finished))
	}
}

// El cupo es por IP: muchos archivos distintos por HEAD no lo esquivan (ni los alias del nombre).
func TestHTTPCupoPorIPNoPorNombre(t *testing.T) {
	r := newRecorder()
	var names []string
	addr := serveHTTPCfg(t, 1<<10, func(c *Config) {
		r.tune(c)
		for i := 0; i < 40; i++ {
			p, _ := image(t, fmt.Sprintf("cfg%d.txt", i), 100)
			c.Files = append(c.Files, p)
			names = append(names, fmt.Sprintf("cfg%d.txt", i))
		}
	})
	for i := 0; i < 200; i++ {
		resp, err := http.Head("http://" + addr + "/" + names[i%len(names)])
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	r.wait(t, 200)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.audited != auditPerWindow {
		t.Fatalf("auditadas %d, quería %d (contadas %d)", r.audited, auditPerWindow, r.counted)
	}
}

// El resumen sale solo al vencer la ventana, sin nueva petición, con la primera y la última hora.
func TestHTTPResumenPeriodico(t *testing.T) {
	r := newRecorder()
	addr := serveHTTPCfg(t, 1<<10, func(c *Config) { r.tune(c); c.summaryTick = 10 * time.Millisecond })
	first := r.now
	for i := 0; i < auditPerWindow+7; i++ {
		rangeGet(t, addr, "ios.bin")
	}
	r.wait(t, auditPerWindow+7)
	r.mu.Lock()
	r.now = r.now.Add(auditWindow)
	r.mu.Unlock()
	for i := 0; i < 500; i++ {
		r.mu.Lock()
		n := len(r.summaries)
		r.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.summaries) != 1 || r.summaries[0].N != 7 || !r.summaries[0].First.Equal(first) || !r.summaries[0].Last.Equal(first) || r.summaries[0].Client != "127.0.0.1" {
		t.Fatalf("resumen: %+v", r.summaries)
	}
}

// Los GET cortados antes de que empiece la sesión tampoco esquivan el cupo.
func TestHTTPInterrumpidosSeCuentan(t *testing.T) {
	r := newRecorder()
	// Ninguna sesión antes de completar: el corte es determinista.
	addr := serveHTTPCfg(t, 64<<20, func(c *Config) { r.tune(c); c.liveAfter = 1 << 40 })
	const n = 30
	for i := 0; i < n; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, "GET /ios.bin HTTP/1.1\r\nHost: x\r\n\r\n")
		bufio.NewReader(c).ReadString('\n')
		c.(*net.TCPConn).SetLinger(0)
		c.Close()
	}
	r.wait(t, n)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.audited > auditPerWindow || len(r.started) != 0 {
		t.Fatalf("auditadas %d (tope %d), sesiones %d", r.audited, auditPerWindow, len(r.started))
	}
}

// Al detener el servidor sale el resumen de lo pendiente.
func TestHTTPResumenAlDetener(t *testing.T) {
	r := newRecorder()
	p, _ := image(t, "ios.bin", 1<<10)
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan struct{})
	cfg := Config{Addr: "127.0.0.1:0", Proto: "http", Files: []string{p}, OnListening: func(a string) { ready <- a }}
	r.tune(&cfg)
	go func() { Serve(ctx, cfg); close(done) }()
	addr := <-ready
	for i := 0; i < auditPerWindow+9; i++ {
		rangeGet(t, addr, "ios.bin")
	}
	r.wait(t, auditPerWindow+9)
	cancel()
	<-done
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.summaries) != 1 || r.summaries[0].N != 9 {
		t.Fatalf("resumen al detener: %+v", r.summaries)
	}
}

// El mapa de cupos se acota.
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

// El mapa de fallos de contraseña también se acota.
func TestLimiterFallosAcotado(t *testing.T) {
	now := time.Unix(1, 0)
	l := newLimiter(func() time.Time { return now })
	for i := 0; i < maxSeenIPs+500; i++ {
		l.fail(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String())
	}
	if len(l.fails) > maxSeenIPs {
		t.Fatalf("mapa de %d entradas", len(l.fails))
	}
}

func ipN(i int) string {
	return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String()
}

// Las direcciones de un mismo /64 comparten cupo; IPv4-mapped y zona se normalizan.
func TestIPKeyAgrupaV6(t *testing.T) {
	now := time.Unix(1, 0)
	q := newAuditQuota(func() time.Time { return now })
	ok := 0
	for i := 0; i < 50; i++ {
		if a, _ := q.take(ipKey(fmt.Sprintf("2001:db8:1:2::%x", i+1))); a {
			ok++
		}
	}
	if ok != auditPerWindow {
		t.Fatalf("auditadas %d de 50 del mismo /64, quería %d", ok, auditPerWindow)
	}
	if ipKey("::ffff:1.2.3.4") != ipKey("1.2.3.4") || ipKey("fe80::1%eth0") != ipKey("fe80::2") || ipKey("1.2.3.4") == ipKey("1.2.3.5") {
		t.Fatalf("normalización: %q %q %q", ipKey("::ffff:1.2.3.4"), ipKey("fe80::1%eth0"), ipKey("fe80::2"))
	}
}

// Con el mapa lleno, lo nuevo comparte un cupo común de desborde en vez de auditarse siempre.
func TestAuditQuotaLlenoUsaDesborde(t *testing.T) {
	now := time.Unix(1, 0)
	q := newAuditQuota(func() time.Time { return now })
	for i := 0; i < maxSeenIPs; i++ {
		q.take(ipN(i))
	}
	ok := 0
	for i := 0; i < 50; i++ {
		if a, _ := q.take(ipN(maxSeenIPs + i)); a {
			ok++
		}
	}
	if ok != auditPerWindow {
		t.Fatalf("auditadas %d de 50 nuevas con el mapa lleno, quería %d", ok, auditPerWindow)
	}
	if got := q.flush(); len(got) == 0 {
		t.Fatal("el desborde debe salir en el resumen")
	}
}

// Con el mapa de fallos lleno se sigue bloqueando a los orígenes nuevos.
func TestLimiterLlenoSigueBloqueando(t *testing.T) {
	now := time.Unix(1, 0)
	l := newLimiter(func() time.Time { return now })
	for i := 0; i < maxSeenIPs; i++ {
		l.fail(ipN(i))
	}
	for i := 0; i < maxAuthFails; i++ {
		l.fail(ipN(maxSeenIPs + i))
	}
	if !l.blocked(ipN(maxSeenIPs + 1000)) {
		t.Fatal("un origen nuevo debió quedar bloqueado por el desborde")
	}
	if l.blocked(ipN(0)) {
		t.Fatal("un origen con un solo fallo no se bloquea")
	}
}

// Un archivo publicado que ya no se abre tampoco audita más que el cupo.
func TestHTTPNoSeAbreRespetaCupo(t *testing.T) {
	r := newRecorder()
	var p string
	addr := serveHTTPCfg(t, 1<<10, func(c *Config) { r.tune(c); p = c.Files[0] })
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	const n = 50
	for i := 0; i < n; i++ {
		resp, err := http.Head("http://" + addr + "/ios.bin")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	r.wait(t, n)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.audited != auditPerWindow {
		t.Fatalf("auditadas %d, quería %d (contadas %d)", r.audited, auditPerWindow, r.counted)
	}
}
