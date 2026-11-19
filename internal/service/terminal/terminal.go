// Package terminal es el servicio gRPC de la terminal SSH interactiva. Es manual: lo que el
// ingeniero teclea va directo al equipo, sin modo asistido. Toda sesión sale por el EgressGuard,
// usa la credencial de la bóveda y la verificación estricta de la llave de host, y se cierra,
// revoca el guard y se audita en todos los caminos (el cliente cierra, el núcleo se cierra o el equipo corta).
package terminal

import (
	"context"
	"database/sql"
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
	"unicode"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/devices"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/terminal"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

const (
	maxSessions = 8
	closeWait   = 15 * time.Second
	maxUser     = 128  // bytes del usuario tecleado
	maxAnswer   = 1024 // bytes de cada respuesta tecleada: el mismo tope del transport
)

// wipeMsg pone en ceros lo que un mensaje ignorado pudiera traer: respuestas de autenticación y data.
func wipeMsg(m *v1.OpenTerminalRequest) {
	for _, b := range m.GetAuthAnswer().GetAnswers() {
		clear(b)
	}
	clear(m.GetData())
}

// Motivos propios de la autenticación tecleada (fase 47t). Ninguno lleva respuestas ni textos de preguntas.
var (
	errAuthTimeout = i18n.New("terminal.err.auth_timeout", nil)
	errAuthAnswer  = i18n.New("terminal.err.auth_answer", nil)
	errAuthNoMeth  = i18n.New("terminal.err.auth_no_method", nil)
	errAuthTries   = i18n.New("terminal.err.auth_attempts", nil)
	errUsername    = i18n.New("terminal.err.username", nil)
	errClientGone  = i18n.New("terminal.err.client_gone", nil)
	errCoreClosing = i18n.New("terminal.err.core_closing", nil)
)

// cleanUser recorta espacios y valida el usuario (el de la petición y el de «login as:» pasan por aquí): UTF-8
// imprimible, sin controles, C1 ni Unicode de formato, de 1 a maxUser bytes.
func cleanUser(u string) (string, bool) {
	u = strings.TrimSpace(u)
	if u == "" || len(u) > maxUser || !utf8.ValidString(u) {
		return "", false
	}
	for _, r := range u {
		if !unicode.IsPrint(r) {
			return "", false
		}
	}
	return u, true
}

type termSvc struct {
	v1.UnimplementedTerminalServiceServer
	d        service.Deps
	ctx      context.Context // vive mientras el núcleo: cancelarlo cierra todas las sesiones
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	live     atomic.Int32
	authWait time.Duration // espera máxima de la respuesta a cada pregunta tecleada
}

func newSvc(d service.Deps) *termSvc {
	ctx, cancel := context.WithCancel(context.Background())
	return &termSvc{d: d, ctx: ctx, cancel: cancel, authWait: 2 * time.Minute}
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
	var (
		address, credID, startup string
		port                     uint16
		label                    = o.Name
		username                 string // modo tecleado: el de la petición, ya recortado y validado
		typed                    bool   // fase 47t: credencial tecleada
		generic                  bool   // host guardado linux o windows: PTY xterm, orden de inicio y credencial de llave
	)
	if o.HostId != "" {
		// host_id es exclusivo: ni otra dirección ni otra credencial sobre un host guardado.
		if label == "" {
			label = o.HostId
		}
		if o.Address != "" || o.Port != 0 || o.CredentialId != "" {
			return s.refuse(label, service.Err(st.Context(), codes.InvalidArgument, "terminal.err.host_and_address", nil), "host and address")
		}
		if o.Username != "" { // hoy todo host guardado trae su credencial
			return s.refuse(label, service.Err(st.Context(), codes.InvalidArgument, "terminal.err.username_with_credential", nil), "username with a credential")
		}
		h, err := service.SavedHost(s.d.DB(), o.HostId)
		if errors.Is(err, sql.ErrNoRows) {
			return s.refuse(label, service.Err(st.Context(), codes.NotFound, "terminal.err.host_not_found", nil), "saved host not found")
		}
		if err != nil {
			return s.refuse(label, service.ErrFrom(st.Context(), codes.Internal, err), i18n.English(err))
		}
		label = h.Name                                                // el nombre de la libreta, no el que mande el cliente
		if h.StartupCommand != "" && !devices.IsGeneric(h.Platform) { // Clean no lo permite: datos alterados o viejos
			return s.refuse(label, service.Err(st.Context(), codes.FailedPrecondition, "terminal.err.startup_changed", nil), "startup on a non-generic host")
		}
		if h.CredentialID == "" {
			return s.refuse(label, service.Err(st.Context(), codes.FailedPrecondition, "terminal.err.host_no_credential", nil), "saved host has no credential")
		}
		if o.ExpectedStartupCommand != h.StartupCommand { // lo que corre es lo que el usuario vio
			return s.refuse(label, service.Err(st.Context(), codes.FailedPrecondition, "terminal.err.startup_changed", nil), "startup changed")
		}
		address, port, credID, startup, generic = h.Address, uint16(h.Port), h.CredentialID, h.StartupCommand, devices.IsGeneric(h.Platform)
	} else {
		if o.Address == "" {
			return service.Err(st.Context(), codes.InvalidArgument, "terminal.err.no_address", nil)
		}
		if o.Port > 65535 {
			return service.Err(st.Context(), codes.InvalidArgument, "terminal.err.port", nil)
		}
		if o.CredentialId != "" && o.Username != "" {
			return service.Err(st.Context(), codes.InvalidArgument, "terminal.err.username_with_credential", nil)
		}
		if o.Username != "" {
			var ok bool
			if username, ok = cleanUser(o.Username); !ok && strings.TrimSpace(o.Username) != "" {
				return service.Err(st.Context(), codes.InvalidArgument, "terminal.err.username", nil)
			}
		}
		typed = o.CredentialId == "" // sin credencial: las respuestas se piden por el stream y no se usa la bóveda
		address, credID, port = o.Address, o.CredentialId, uint16(o.Port)
	}
	if port == 0 {
		port = 22
	}
	if label == "" {
		label = address + ":" + strconv.Itoa(int(port))
	}
	// Las huellas aceptadas solo dependen del pedido: se validan antes de la bóveda, del guard y de preguntar «login as:».
	accepted, err := service.HostKeyAccepts(st.Context(), []string{transport.HostKeyID(address, port)}, o.AcceptedHostKeyFingerprints, o.AcceptedHostKeys)
	if err != nil {
		return s.refuse(label, err, i18n.English(err))
	}
	v := s.d.Vault()
	if !typed {
		if v == nil || !v.Unlocked() {
			return s.refuse(label, service.Err(st.Context(), codes.FailedPrecondition, "terminal.err.vault_closed", nil), "vault is closed: the terminal needs the device credentials")
		}
		// Una credencial de solo llave solo se usa por host_id de un host linux o windows; se rechaza antes de Guard.Allow (sin DNS) y de conectar.
		infos, err := v.List()
		if err != nil { // la bóveda se cerró entre medio: sin saber el tipo no se sigue
			return s.refuse(label, service.Err(st.Context(), codes.FailedPrecondition, "terminal.err.vault_closed", nil), "vault is closed: the terminal needs the device credentials")
		}
		for _, i := range infos {
			if i.ID == credID && i.IsKey() && !generic {
				return s.refuse(label, service.Err(st.Context(), codes.FailedPrecondition, "terminal.err.key_credential", nil), "key credential")
			}
		}
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
	if err := s.d.Guard().Allow(ctx, id, []string{address}); err != nil {
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
		user       = username // en modo tecleado, el de la petición o el de «login as:»
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
		who := ""
		if typed {
			who = fmt.Sprintf(" credential=typed user=%q", user)
		}
		s.d.Audit(action, label, fmt.Sprintf("session=%s%s reason=%q received=%d sent=%d guard=revoked recording=%s", id, who, reasonEN, rx.Load(), tx.Load(), recordPath))
	}()

	// Un solo Recv desde aquí: el handshake tecleado y, después, el teclado leen de este canal.
	msgs := make(chan *v1.OpenTerminalRequest)
	go func() {
		defer close(msgs)
		for {
			m, err := st.Recv()
			if err != nil {
				return
			}
			select {
			case msgs <- m:
			case <-ctx.Done():
				wipeMsg(m) // nadie la va a leer
				return
			}
		}
	}()
	szRows, szCols := o.Rows, o.Cols // un resize durante la autenticación se guarda para el PTY
	var (
		seq, lastAttempt = uint32(0), 1
		askErr           error
		askMu            sync.Mutex
		askClosed        bool
		askWG            sync.WaitGroup
	)
	// ask lo llama el handshake (otra goroutine, una a la vez) o este manejador: nunca hay dos emisores a la vez.
	ask := func(actx context.Context, p transport.Prompt) (ans [][]byte, err error) {
		askMu.Lock()
		if askClosed {
			askMu.Unlock()
			return nil, errClientGone
		}
		askWG.Add(1)
		askMu.Unlock()
		defer askWG.Done()
		defer func() {
			if err != nil && askErr == nil {
				askErr = err
			}
		}()
		for drained := false; !drained; { // una respuesta que llegó antes de esta pregunta no es de ella: se vacía y se borra
			select {
			case m, ok := <-msgs:
				if !ok {
					return nil, errClientGone
				}
				if rz := m.GetResize(); rz != nil {
					szRows, szCols = rz.Rows, rz.Cols
				}
				wipeMsg(m)
			default:
				drained = true
			}
		}
		if p.Attempt > lastAttempt {
			lastAttempt = p.Attempt
			if st.Send(&v1.OpenTerminalResponse{Data: []byte(i18n.T(st.Context(), "terminal.auth.denied", nil) + "\r\n")}) != nil {
				return nil, errClientGone
			}
		}
		seq++
		ap := &v1.AuthPrompt{Seq: seq, Name: p.Name, Instruction: p.Instruction}
		for _, q := range p.Questions {
			ap.Prompts = append(ap.Prompts, &v1.AuthQuestion{Text: q.Text, Echo: q.Echo})
		}
		if st.Send(&v1.OpenTerminalResponse{AuthPrompt: ap}) != nil {
			return nil, errClientGone
		}
		timer := time.NewTimer(s.authWait)
		defer timer.Stop()
		for {
			select {
			case m, ok := <-msgs:
				if !ok {
					return nil, errClientGone
				}
				switch {
				case m.GetResize() != nil:
					szRows, szCols = m.GetResize().Rows, m.GetResize().Cols
				case m.GetAuthAnswer() != nil:
					a := m.GetAuthAnswer()
					big := false
					for _, b := range a.Answers {
						big = big || len(b) > maxAnswer
					}
					if a.Seq != seq || len(a.Answers) != len(p.Questions) || big {
						wipeMsg(m)
						return nil, errAuthAnswer
					}
					return a.Answers, nil
				default: // data durante la autenticación: se descarta
					clear(m.GetData())
				}
			case <-actx.Done():
				return nil, actx.Err()
			case <-timer.C:
				return nil, errAuthTimeout
			}
		}
	}
	// failTyped traduce el fallo de la autenticación tecleada a un motivo propio; ok=false deja el error al connErr de siempre.
	failTyped := func(err error) (error, bool) {
		if askErr != nil {
			err = askErr
		}
		var he *transport.HostKeyError
		var te error
		code := codes.Unavailable
		switch {
		case errors.As(err, &he):
			return nil, false
		case s.ctx.Err() != nil:
			te = errCoreClosing
		case errors.Is(err, errClientGone) || ctx.Err() != nil:
			te = errClientGone
		case errors.Is(err, errAuthTimeout):
			te, code = errAuthTimeout, codes.DeadlineExceeded
		case errors.Is(err, errAuthAnswer), errors.Is(err, errUsername):
			te, code = err, codes.InvalidArgument
		case errors.Is(err, transport.ErrAuthAttempts), errors.Is(err, transport.ErrAuthRounds): // los dos topes dan el mismo motivo
			te, code = errAuthTries, codes.PermissionDenied
		case errors.Is(err, transport.ErrTypedNoMethod):
			te, code = errAuthNoMeth, codes.FailedPrecondition
		default:
			return nil, false
		}
		reason, reasonEN = te.Error(), i18n.English(te)
		return service.ErrFrom(st.Context(), code, te), true
	}

	var cred vault.Credential
	opts := transport.SSHOptions{GenericHost: generic}
	if typed {
		if user == "" { // «login as:» antes de marcar: x/crypto no cambia el usuario a mitad del handshake
			ans, err := ask(ctx, transport.Prompt{Attempt: 1, Questions: []transport.Question{{Text: i18n.T(st.Context(), "terminal.auth.login", nil), Echo: true}}})
			if err != nil {
				te, _ := failTyped(err)
				return te
			}
			u, ok := cleanUser(string(ans[0]))
			clear(ans[0])
			if user = u; !ok {
				askErr = errUsername
				te, _ := failTyped(errUsername)
				return te
			}
		}
		cred.Username, opts.Ask = user, ask
	} else {
		var err error
		if cred, err = v.Get(credID); err != nil {
			reason, reasonEN = err.Error(), i18n.English(err)
			return service.VaultErr(ctx, err)
		}
		user = cred.Username
	}
	hk := s.d.Hosts().Callback(transport.HostKeyPolicy{Accepted: accepted}, func(en audit.Entry) { s.d.Audit(en.Action, en.Target, en.Detail) })
	sess, err = transport.OpenSSH(ctx, s.d.Guard(), id, address, port, cred, hk, opts)
	cred.Enable.Destroy() // la terminal es manual: el usuario escribe enable por su cuenta
	askMu.Lock()
	askClosed = true
	askMu.Unlock()
	askWG.Wait() // ninguna ask sigue enviando por el stream ni tocando szRows
	if err != nil {
		if typed {
			if te, ok := failTyped(err); ok {
				return te
			}
		}
		reason, reasonEN = err.Error(), i18n.English(err)
		return connErr(st.Context(), err)
	}
	term, rows, cols := "vt100", clamp(szRows, 24, 1, 200), clamp(szCols, 200, 20, 500)
	if generic {
		term = "xterm-256color"
	}
	var r io.Reader
	var w io.Writer
	if generic && startup != "" { // exec con PTY, como `ssh -t host orden`: no se teclea en el shell
		r, w, err = sess.CommandSize(term, rows, cols, startup)
	} else {
		r, w, err = sess.ShellSize(term, rows, cols)
	}
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
	summary := fmt.Sprintf("%s@%s:%d", user, address, port)
	rec.Mark("abierto " + summary)
	detail := fmt.Sprintf("session=%s user=%s recording=%s manual=true", id, user, recordPath)
	if typed {
		detail = fmt.Sprintf("session=%s credential=typed user=%q recording=%s manual=true", id, user, recordPath)
	}
	if o.HostId != "" {
		start := "none"
		if startup != "" {
			rec.Mark("orden de inicio: " + strconv.Quote(startup))
			start = strconv.Quote(startup)
		}
		detail += " host=" + o.HostId + " startup=" + start
	}
	opened, reason, reasonEN = true, "cerrada por el usuario", "closed by the user"
	s.d.Audit("terminal.open", label, detail)
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
			m, ok := <-msgs
			if !ok {
				return
			}
			switch {
			case m.GetResize() != nil:
				sz := m.GetResize()
				sess.Resize(clamp(sz.Rows, 24, 1, 200), clamp(sz.Cols, 200, 20, 500))
			case m.GetAuthAnswer() != nil: // llegó tarde: no es de nadie
				wipeMsg(m)
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
