package fileserve

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/listen"
)

// netAddr adapta r.RemoteAddr (texto) a net.Addr para hostOf.
type netAddr string

func (a netAddr) Network() string { return "tcp" }
func (a netAddr) String() string  { return string(a) }

type countingWriter struct {
	http.ResponseWriter
	n      int64
	status int
	err    error
	live   *Live
	idle   time.Duration           // plazo de inactividad de escritura
	total  int64                   // Content-Length de la respuesta 2xx
	begin  func(total int64) *Live // abre la sesión de un GET 2xx
}

func (w *countingWriter) WriteHeader(s int) {
	w.status = s
	if s >= 200 && s < 300 {
		// ServeContent ya fijó Content-Length: el tamaño del tramo (o del archivo).
		w.total, _ = strconv.ParseInt(w.Header().Get("Content-Length"), 10, 64)
	}
	w.ResponseWriter.WriteHeader(s)
}

// startLive abre la sesión (solo GET 2xx) con lo enviado hasta ahora.
func (w *countingWriter) startLive() {
	if w.live == nil && w.begin != nil && w.status >= 200 && w.status < 300 {
		w.live = w.begin(w.total)
		w.live.add(w.n)
	}
}

func (w *countingWriter) Write(b []byte) (int, error) {
	// Plazo de inactividad: se renueva en cada escritura (ErrNotSupported fuera de un servidor real: se ignora).
	http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now().Add(w.idle))
	n, err := w.ResponseWriter.Write(b)
	w.n += int64(n)
	if w.live == nil && w.n >= liveAfter {
		w.startLive()
	} else {
		w.live.add(int64(n))
	}
	if err != nil && w.err == nil {
		w.err = err
	}
	return n, err
}

func serveHTTP(ctx context.Context, c Config, src *source) error {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", c.Addr)
	if err != nil {
		return listen.Bind("fileserve", err, listen.PortOf(c.Addr))
	}
	lim := newLimiter(c.clock) // cupo global y por IP; aquí no hay contraseñas
	quota := newAuditQuota(c.clock)
	writeIdle := httpWriteIdle // se lee una vez: las pruebas lo cambian entre servidores
	// srv.Close no espera a los handlers: Serve los espera para no volver antes de su OnTransfer (el que
	// llama cierra su canal de eventos al volver y una transferencia tardía se perdería de la auditoría).
	var (
		hmu     sync.Mutex
		stopped bool
		active  sync.WaitGroup
	)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hmu.Lock()
		if stopped {
			hmu.Unlock()
			return
		}
		active.Add(1)
		hmu.Unlock()
		defer active.Done()
		start := time.Now()
		name := strings.TrimPrefix(r.URL.Path, "/")
		t := Transfer{Proto: "http", Client: r.RemoteAddr, File: name, Dir: "lectura", Result: "error"}
		defer func() { t.Duration = time.Since(start); c.OnTransfer(t) }()
		if ap, err := netip.ParseAddrPort(r.RemoteAddr); err != nil || !c.permits(ap.Addr()) {
			http.Error(w, "origen no permitido", http.StatusForbidden)
			t.Error, t.ReasonT, t.Rejected, t.Cause = "origen no permitido", lit("origen no permitido"), true, CauseOriginDenied
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "solo GET", http.StatusMethodNotAllowed)
			t.Error, t.ReasonT, t.Rejected, t.Cause = "método "+r.Method, why("method", "method", r.Method), true, CauseMethod
			return
		}
		if !src.exists(name) {
			http.NotFound(w, r) // sin listado ni pistas de qué hay publicado
			t.Error, t.ReasonT, t.Rejected, t.Cause = "archivo no publicado", lit("archivo no publicado"), true, CauseNotFound
			return
		}
		ip := hostOf(netAddr(r.RemoteAddr))
		release, ok := lim.acquire(ip)
		if !ok {
			http.Error(w, "ocupado", http.StatusServiceUnavailable)
			msg := "demasiadas transferencias simultáneas"
			if lim.ipBusy(ip) {
				msg = "demasiadas transferencias simultáneas desde este cliente"
			}
			t.Error, t.ReasonT, t.Rejected, t.Cause = msg, lit(msg), true, CauseBusy
			return
		}
		defer release()
		f, st, err := src.open(name)
		if err != nil {
			http.Error(w, "no disponible", http.StatusInternalServerError)
			t.setErr(err)
			return
		}
		defer f.Close()
		t.Path = f.Name()
		// Sesión solo con un GET 2xx: arranca al pasar liveAfter bytes o, si se entrega completo, al terminar. HEAD, 304,
		// 412 y 416 no la crean: un escáner con Range inválidos no desplaza la historia.
		cw := &countingWriter{ResponseWriter: w, status: http.StatusOK, idle: writeIdle}
		if r.Method == http.MethodGet {
			cw.begin = func(total int64) *Live { return c.start(t, total) }
		}
		http.ServeContent(cw, r, name, st.ModTime(), f) // atiende Range e If-Modified-Since
		// Descarga completa: 200 con todo el cuerpo y sin corte. Se audita siempre y sin cupo.
		if r.Method == http.MethodGet && cw.status == http.StatusOK && cw.err == nil && cw.n == cw.total {
			cw.startLive()
		}
		t.Bytes, t.Live = cw.n, cw.live
		switch {
		case cw.err != nil:
			t.Error, t.ReasonT = "interrumpida: "+cw.err.Error(), why("interrupted", "error", cw.err.Error())
		case cw.status >= 400:
			t.Error = fmt.Sprintf("HTTP %d", cw.status)
		default:
			t.Result = "ok"
		}
		// Sin sesión no entregó el archivo (HEAD, 304, Range parcial, corte temprano, 416): cupo de auditoría por IP.
		// Pasado el cupo se cuenta con motivo propio, sin auditarla una por una; lo cortado o con error conserva su texto.
		if cw.live == nil {
			allowed, closed := quota.take(ip)
			for _, x := range closed {
				c.repeats(x)
			}
			if !allowed {
				t.Rejected, t.Cause = true, CauseRepeat
				if t.Result == "ok" {
					t.Error, t.ReasonT = "repetida", lit("repetida")
				}
			}
		}
	})
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 8 << 10,
		ErrorLog: log.New(io.Discard, "", 0)}
	c.ready(Ready{Addr: ln.Addr().String()})
	// Vaciado periódico: el resumen de una ventana vencida sale aunque no llegue otra petición.
	tickDone := make(chan struct{})
	var ticker sync.WaitGroup
	ticker.Add(1)
	go func() {
		defer ticker.Done()
		tk := time.NewTicker(summaryTick)
		defer tk.Stop()
		for {
			select {
			case <-tickDone:
				return
			case <-tk.C:
				for _, x := range quota.expire() {
					c.repeats(x)
				}
			}
		}
	}()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	// Mismo apagado si Serve termina con error: sin srv.Close las conexiones keep-alive seguirían bajando archivos.
	err = nil
	select {
	case <-ctx.Done():
	case err = <-done:
	}
	srv.Close()
	if err == nil {
		<-done
	}
	hmu.Lock()
	stopped = true
	hmu.Unlock()
	active.Wait()
	close(tickDone)
	ticker.Wait()
	for _, x := range quota.flush() {
		c.repeats(x)
	}
	if err != nil {
		return fmt.Errorf("fileserve: %w", err)
	}
	return nil
}
