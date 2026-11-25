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
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
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
	begin  func(total int64) *Live // arranca la sesión en la primera cabecera 2xx de un GET
}

func (w *countingWriter) WriteHeader(s int) {
	w.status = s
	if s >= 200 && s < 300 && w.live == nil && w.begin != nil {
		// ServeContent ya fijó Content-Length: el tamaño del tramo (o del archivo).
		cl, _ := strconv.ParseInt(w.Header().Get("Content-Length"), 10, 64)
		w.live = w.begin(cl)
	}
	w.ResponseWriter.WriteHeader(s)
}
func (w *countingWriter) Write(b []byte) (int, error) {
	// Plazo de inactividad: se renueva en cada escritura (ErrNotSupported fuera de un servidor real: se ignora).
	http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now().Add(httpWriteIdle))
	n, err := w.ResponseWriter.Write(b)
	w.n += int64(n)
	w.live.add(int64(n))
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
		// Sesión solo con un GET que responde 2xx (HEAD, 304, 412 y 416 no la crean: un escáner
		// con Range inválidos no desplaza la historia). El arranque es perezoso, en WriteHeader.
		// El cupo se decide antes de servir: sin cupo no hay sesión (salvo cuerpos grandes), y lo que no abre
		// sesión puede salir como contado; una sesión abierta nunca termina como rechazo.
		allowed := quota.take(ip)
		cw := &countingWriter{ResponseWriter: w, status: http.StatusOK}
		if r.Method == http.MethodGet {
			cw.begin = func(total int64) *Live {
				if !allowed && total < bigBody {
					return nil
				}
				return c.start(t, total)
			}
		}
		http.ServeContent(cw, r, name, st.ModTime(), f) // atiende Range e If-Modified-Since
		t.Bytes, t.Live = cw.n, cw.live
		switch {
		case cw.err != nil:
			t.Error, t.ReasonT = "interrumpida: "+cw.err.Error(), why("interrupted", "error", cw.err.Error())
		case cw.status >= 400:
			t.Error = fmt.Sprintf("HTTP %d", cw.status)
		default:
			t.Result = "ok"
		}
		// Sin cupo y sin sesión: se cuenta como rechazo (no es un fallo de la transferencia) y no se audita.
		if !allowed && cw.live == nil && cw.err == nil {
			t.Rejected, t.Cause = true, CauseOther
			t.Error, t.ReasonT = "", i18n.Text{}
			if cw.status >= 400 {
				t.Result = "error"
				t.Error = fmt.Sprintf("HTTP %d", cw.status)
			}
		}
	})
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 8 << 10,
		ErrorLog: log.New(io.Discard, "", 0)}
	c.ready(Ready{Addr: ln.Addr().String()})
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
	if err != nil {
		return fmt.Errorf("fileserve: %w", err)
	}
	return nil
}
