// Package terminal es el servicio gRPC de la terminal SSH interactiva. Es manual: lo que el
// ingeniero teclea va directo al equipo, sin modo asistido. Toda sesión sale por el EgressGuard,
// usa la credencial de la bóveda y la verificación estricta de la llave de host, y se cierra,
// revoca el guard y se audita en todos los caminos (el cliente cierra, el núcleo se cierra o el equipo corta).
package terminal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/terminal"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
)

const (
	maxSessions = 8
	closeWait   = 15 * time.Second
)

type termSvc struct {
	v1.UnimplementedTerminalServiceServer
	d      service.Deps
	ctx    context.Context // vive mientras el núcleo: cancelarlo cierra todas las sesiones
	cancel context.CancelFunc
	wg     sync.WaitGroup
	live   atomic.Int32
}

func newSvc(d service.Deps) *termSvc {
	ctx, cancel := context.WithCancel(context.Background())
	return &termSvc{d: d, ctx: ctx, cancel: cancel}
}

// close cierra las sesiones vivas y espera a que cada una cierre SSH, revoque el guard y audite.
// El núcleo lo llama antes de cerrar la base de datos.
func (s *termSvc) close() {
	s.cancel()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(closeWait):
	}
}

// connErr traduce los errores de conexión a códigos gRPC; la huella de una llave nueva va en el mensaje.
func connErr(ctx context.Context, err error) error {
	var he *transport.HostKeyError
	switch {
	case errors.As(err, &he):
		return service.ErrFrom(ctx, codes.FailedPrecondition, err)
	case errors.Is(err, transport.ErrAuth), errors.Is(err, transport.ErrEgressDenied):
		return service.ErrFrom(ctx, codes.PermissionDenied, err)
	}
	if s := service.VaultErr(ctx, err); status.Code(s) != codes.Internal {
		return s
	}
	return service.ErrFrom(ctx, codes.Unavailable, err)
}

// unavailable da el código del catálogo del motivo (en inglés, como queda en la auditoría) con que se cierra un stream
// por el núcleo o el equipo; el mensaje en español es el de siempre.
var unavailable = map[string]string{"core shutting down": "terminal.err.core_closing", "client disconnected": "terminal.err.client_gone", "the device closed the session": "terminal.err.device_closed"}

func clamp(v, def, lo, hi uint32) int {
	if v == 0 {
		return int(def)
	}
	return int(min(max(v, lo), hi))
}

// safeName deja en el nombre del archivo solo letras, números y . _ -
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x80 && (r == '.' || r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return strings.TrimLeft(b.String(), ".-")
}

func (s *termSvc) recording(ctx context.Context, label, id string) (*os.File, error) {
	dir := filepath.Join(s.d.Outputs(), "terminal")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, service.Err(ctx, codes.Internal, "terminal.err.out_dir", i18n.A("error", err.Error()))
	}
	// O_EXCL: no pisa un archivo ni sigue un enlace puesto con el mismo nombre.
	p := filepath.Join(dir, fmt.Sprintf("%s_%s_%s.log", safeName(label), s.d.Now().Format("20060102-150405"), id[len(id)-6:]))
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return nil, service.Err(ctx, codes.Internal, "terminal.err.recording", i18n.A("error", err.Error()))
	}
	return f, nil
}

// refuse audita un rechazo anterior a la apertura: aún no hay sesión viva ni autorización en el guard.
func (s *termSvc) refuse(label string, err error, reason string) error {
	s.d.Audit("terminal.failed", label, fmt.Sprintf("reason=%q guard=unauthorized", reason))
	return err
}

func (s *termSvc) OpenTerminal(st v1.TerminalService_OpenTerminalServer) error {
	s.d.MarkActive()
	first, err := st.Recv()
	if err != nil {
		return err
	}
	o := first.GetOpen()
	if o == nil {
		return service.Err(st.Context(), codes.InvalidArgument, "terminal.err.first_open", nil)
	}
	if o.Address == "" || o.CredentialId == "" {
		return service.Err(st.Context(), codes.InvalidArgument, "terminal.err.no_address", nil)
	}
	if o.Port > 65535 {
		return service.Err(st.Context(), codes.InvalidArgument, "terminal.err.port", nil)
	}
	port := uint16(o.Port)
	if port == 0 {
		port = 22
	}
	label := o.Name
	if label == "" {
		label = o.Address + ":" + strconv.Itoa(int(port))
	}
	v := s.d.Vault()
	if v == nil || !v.Unlocked() {
		return s.refuse(label, service.Err(st.Context(), codes.FailedPrecondition, "terminal.err.vault_closed", nil), "vault is closed: the terminal needs the device credentials")
	}
	if s.live.Add(1) > maxSessions {
		s.live.Add(-1)
		return s.refuse(label, service.Err(st.Context(), codes.ResourceExhausted, "terminal.err.max_sessions", i18n.A("max", maxSessions)), fmt.Sprintf("at most %d terminals open", maxSessions))
	}
	defer s.live.Add(-1)
	s.wg.Add(1)
	defer s.wg.Done()
	if s.ctx.Err() != nil {
		return s.refuse(label, service.Err(st.Context(), codes.Unavailable, "terminal.err.shutting_down", nil), "the core is shutting down")
	}

	ctx, cancel := context.WithCancel(st.Context())
	defer cancel()
	go func() { // cierre del núcleo → termina esta sesión
		select {
		case <-s.ctx.Done():
			cancel()
		case <-ctx.Done():
		}
	}()

	id := "term-" + service.NewID()
	if err := s.d.Guard().Allow(ctx, id, []string{o.Address}); err != nil {
		return s.refuse(label, service.ErrFrom(st.Context(), codes.PermissionDenied, err), i18n.English(err))
	}
	// A partir de aquí, todo camino de salida pasa por este defer: cierra SSH y grabación,
	// revoca el guard y audita. Es lo que garantiza que no quede una autorización abierta.
	var (
		sess       *transport.Session
		f          *os.File
		rec        *terminal.Recorder
		opened     bool
		reason     = "no se pudo abrir"
		reasonEN   = "could not open" // lo mismo que reason, en inglés, para la auditoría
		rx, tx     atomic.Int64
		recordPath string
	)
	defer func() {
		if sess != nil {
			sess.Close()
		}
		if rec != nil {
			rec.Mark("cerrado: " + reason)
			rec.Close()
		}
		if f != nil {
			f.Close()
		}
		s.d.Guard().Revoke(id)
		action := "terminal.close"
		if !opened {
			action = "terminal.failed"
		}
		s.d.Audit(action, label, fmt.Sprintf("session=%s reason=%q received=%d sent=%d guard=revoked recording=%s", id, reasonEN, rx.Load(), tx.Load(), recordPath))
	}()

	cred, err := v.Get(o.CredentialId)
	if err != nil {
		reason, reasonEN = err.Error(), i18n.English(err)
		return service.VaultErr(ctx, err)
	}
	user := cred.Username
	accepted := map[string]bool{}
	for _, fp := range o.AcceptedHostKeyFingerprints {
		accepted[fp] = true
	}
	hk := s.d.Hosts().Callback(transport.HostKeyPolicy{Accepted: accepted}, func(en audit.Entry) { s.d.Audit(en.Action, en.Target, en.Detail) })
	sess, err = transport.OpenSSH(ctx, s.d.Guard(), id, o.Address, port, cred, hk, transport.SSHOptions{})
	cred.Enable.Destroy() // la terminal es manual: el usuario escribe enable por su cuenta
	if err != nil {
		reason, reasonEN = err.Error(), i18n.English(err)
		return connErr(st.Context(), err)
	}
	r, w, err := sess.ShellSize(clamp(o.Rows, 24, 1, 200), clamp(o.Cols, 200, 20, 500))
	if err != nil {
		reason, reasonEN = err.Error(), i18n.English(err)
		return connErr(st.Context(), err)
	}
	if f, err = s.recording(st.Context(), label, id); err != nil {
		reason, reasonEN = err.Error(), i18n.English(err)
		return err
	}
	recordPath = f.Name()
	rec = terminal.NewRecorder(f, s.d.Now)
	summary := fmt.Sprintf("%s@%s:%d", user, o.Address, port)
	rec.Mark("abierto " + summary)
	opened, reason, reasonEN = true, "cerrada por el usuario", "closed by the user"
	s.d.Audit("terminal.open", label, fmt.Sprintf("session=%s user=%s recording=%s manual=true", id, user, recordPath))
	if err := st.Send(&v1.OpenTerminalResponse{Opened: summary, Recording: recordPath}); err != nil {
		reason, reasonEN = err.Error(), i18n.English(err)
		return err
	}

	devDone := make(chan error, 1)
	readerExit := make(chan struct{})
	go func() { // equipo → pantalla y grabación; solo este goroutine envía por el stream desde aquí
		defer close(readerExit)
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				rx.Add(int64(n))
				rec.Output(buf[:n])
				if serr := st.Send(&v1.OpenTerminalResponse{Data: append([]byte(nil), buf[:n]...)}); serr != nil {
					devDone <- serr
					return
				}
			}
			if err != nil {
				devDone <- err
				return
			}
		}
	}()
	clientDone := make(chan struct{})
	go func() { // teclado → equipo
		defer close(clientDone)
		for {
			m, err := st.Recv()
			if err != nil {
				return
			}
			switch {
			case m.GetResize() != nil:
				sz := m.GetResize()
				sess.Resize(clamp(sz.Rows, 24, 1, 200), clamp(sz.Cols, 200, 20, 500))
			case len(m.GetData()) > 0:
				rec.Input(m.GetData())
				if n, err := w.Write(m.GetData()); err != nil {
					return
				} else {
					tx.Add(int64(n))
				}
			}
		}
	}()

	var lost error
	select {
	case <-clientDone:
		if s.ctx.Err() != nil {
			reason, reasonEN = "núcleo cerrándose", "core shutting down"
		} else if st.Context().Err() != nil {
			// Recv devuelve en cuanto el contexto del stream se cancela, antes de que lo haga el derivado ctx.
			reason, reasonEN = "cliente desconectado", "client disconnected"
		}
	case <-ctx.Done():
		reason, reasonEN = "cliente desconectado", "client disconnected"
		if s.ctx.Err() != nil {
			reason, reasonEN = "núcleo cerrándose", "core shutting down"
		}
	case lost = <-devDone:
		reason, reasonEN = "el equipo cerró la sesión", "the device closed the session"
		if lost != nil && !errors.Is(lost, io.EOF) {
			reason, reasonEN = "conexión perdida: "+lost.Error(), "connection lost: "+i18n.English(lost)
		}
	}
	sess.Close() // desbloquea la lectura; el defer termina de cerrar y revoca
	select {     // nadie envía por el stream después de volver el manejador
	case <-readerExit:
	case <-time.After(5 * time.Second):
	}
	if lost != nil && !errors.Is(lost, io.EOF) {
		return service.Err(st.Context(), codes.Unavailable, "terminal.err.lost", i18n.A("error", lost.Error()))
	}
	if s.ctx.Err() != nil {
		if key, ok := unavailable[reasonEN]; ok {
			return service.Err(st.Context(), codes.Unavailable, key, nil)
		}
		return status.Error(codes.Unavailable, reason)
	}
	return nil
}

// Module registra el servicio Terminal y, al cerrarse el núcleo, cierra las sesiones vivas.
type Module struct{}

func (Module) Register(r ipc.Registrar, d service.Deps) {
	s := newSvc(d)
	d.OnClose(s.close)
	v1.RegisterTerminalServiceServer(r, s)
}
