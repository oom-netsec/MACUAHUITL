package fileserve

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/listen"
)

type countingWriter struct {
	http.ResponseWriter
	n      int64
	status int
	err    error
}

func (w *countingWriter) WriteHeader(s int) { w.status = s; w.ResponseWriter.WriteHeader(s) }
func (w *countingWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.n += int64(n)
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
	sem := make(chan struct{}, maxTransfers)
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
			t.Error, t.ReasonT, t.Rejected = "origen no permitido", lit("origen no permitido"), true
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "solo GET", http.StatusMethodNotAllowed)
			t.Error, t.ReasonT, t.Rejected = "método "+r.Method, why("method", "method", r.Method), true
			return
		}
		if !src.exists(name) {
			http.NotFound(w, r) // sin listado ni pistas de qué hay publicado
			t.Error, t.ReasonT, t.Rejected = "archivo no publicado", lit("archivo no publicado"), true
			return
		}
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			http.Error(w, "ocupado", http.StatusServiceUnavailable)
			t.Error, t.ReasonT, t.Rejected = "demasiadas transferencias simultáneas", lit("demasiadas transferencias simultáneas"), true
			return
		}
		f, st, err := src.open(name)
		if err != nil {
			http.Error(w, "no disponible", http.StatusInternalServerError)
			t.setErr(err)
			return
		}
		defer f.Close()
		t.Path = f.Name()
		cw := &countingWriter{ResponseWriter: w, status: http.StatusOK}
		http.ServeContent(cw, r, name, st.ModTime(), f) // atiende Range e If-Modified-Since
		t.Bytes = cw.n
		switch {
		case cw.err != nil:
			t.Error, t.ReasonT = "interrumpida: "+cw.err.Error(), why("interrupted", "error", cw.err.Error())
		case cw.status >= 400:
			t.Error = fmt.Sprintf("HTTP %d", cw.status)
		default:
			t.Result = "ok"
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
