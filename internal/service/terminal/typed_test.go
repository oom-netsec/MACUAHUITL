package terminal

import (
	"bytes"
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

const otp = "123456"

// typed abre la terminal por dirección y sin credencial: el modo tecleado.
func (r *rig) typed(user string) *v1.TerminalOpen {
	o := proto.Clone(r.open).(*v1.TerminalOpen)
	o.CredentialId, o.Username = "", user
	return o
}

// prompt lee lo que devuelve el núcleo hasta el siguiente AuthPrompt; data trae lo que llegó antes como texto.
func (f *fakeStream) prompt(t *testing.T) (p *v1.AuthPrompt, data string) {
	t.Helper()
	var b strings.Builder
	for {
		select {
		case r := <-f.out:
			b.Write(r.Data)
			if r.AuthPrompt != nil {
				return r.AuthPrompt, b.String()
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("no llegó un AuthPrompt; salida: %q", b.String())
		}
	}
}

func (f *fakeStream) answer(seq uint32, ans ...string) {
	a := &v1.AuthAnswer{Seq: seq}
	for _, s := range ans {
		a.Answers = append(a.Answers, []byte(s))
	}
	f.in <- &v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_AuthAnswer{AuthAnswer: a}}
}

func TestTecleadaLoginYMFA(t *testing.T) {
	r := newRig(t, simulator.Config{OTP: otp})
	st, done, cancel := r.session(r.typed(""))
	defer cancel()
	p, _ := st.prompt(t)
	if len(p.Prompts) != 1 || p.Prompts[0].Text != "usuario: " || !p.Prompts[0].Echo || p.Seq == 0 {
		t.Fatalf("login = %+v", p)
	}
	st.answer(p.Seq, "admin")
	m, _ := st.prompt(t)
	if m.Seq == p.Seq || m.Name != "MFA" || m.Instruction != "Enter password and code" || len(m.Prompts) != 2 ||
		m.Prompts[0].Text != "Password: " || m.Prompts[0].Echo || m.Prompts[1].Text != "Verification code: " || !m.Prompts[1].Echo {
		t.Fatalf("MFA = %+v", m)
	}
	st.answer(m.Seq, "pw", otp)
	first := <-st.out
	if first.Opened != "admin@"+r.host+":"+strconv.Itoa(int(r.port)) || first.Recording == "" {
		t.Fatalf("primer evento = %+v", first)
	}
	st.waitFor(t, "SW1>")
	st.data("show version\r")
	st.waitFor(t, "Cisco")
	close(st.in)
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
	r.cerrada("terminal.close", "closed by the user")
	a := r.d.AuditText()
	if !strings.Contains(a, `credential=typed user=\"admin\"`) {
		t.Errorf("auditoría sin credential=typed:\n%s", a)
	}
}

func TestTecleadaTresIntentos(t *testing.T) {
	var att, conns atomic.Int32
	r := newRig(t, simulator.Config{OTP: otp, Attempts: &att, Conns: &conns})
	st, done, cancel := r.session(r.typed("admin"))
	defer cancel()
	var seqs []uint32
	for i := 0; i < 3; i++ {
		p, data := st.prompt(t)
		if (i > 0) != strings.Contains(data, "Acceso denegado\r\n") {
			t.Fatalf("ronda %d: «Access denied» = %q", i, data)
		}
		seqs = append(seqs, p.Seq)
		st.answer(p.Seq, "pw", "000000")
	}
	if seqs[0] >= seqs[1] || seqs[1] >= seqs[2] {
		t.Errorf("seq no crece: %v", seqs)
	}
	err := wait(t, done)
	if status.Code(err) != codes.PermissionDenied || reason(t, err) != "terminal.err.auth_attempts" {
		t.Fatalf("err = %v (%s)", err, reason(t, err))
	}
	if att.Load() != 3 || conns.Load() != 1 {
		t.Errorf("Attempts=%d Conns=%d, quería 3 y 1", att.Load(), conns.Load())
	}
	r.cerrada("terminal.failed", `credential=typed user=\"admin\"`)
	if !strings.Contains(r.d.AuditText(), "reason=\\\"the device rejected authentication after 3 attempts") {
		t.Errorf("sin el motivo:\n%s", r.d.AuditText())
	}
}

func goroutinesAt(base int) bool {
	for i := 0; i < 40; i++ {
		if runtime.NumGoroutine() <= base {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func TestTecleadaCierraPestanaEnPregunta(t *testing.T) {
	for name, tc := range map[string]struct {
		act  func(r *rig, st *fakeStream, cancel context.CancelFunc)
		want string
	}{
		"closesend": {func(_ *rig, st *fakeStream, _ context.CancelFunc) { close(st.in) }, "client disconnected"},
		"ctx":       {func(_ *rig, _ *fakeStream, cancel context.CancelFunc) { cancel() }, "client disconnected"},
		"nucleo": {func(r *rig, _ *fakeStream, _ context.CancelFunc) {
			r.d.CloseAll()
			r.svc.close()
		}, "core shutting down"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, simulator.Config{OTP: otp})
			base := runtime.NumGoroutine()
			st, done, cancel := r.session(r.typed("admin"))
			defer cancel()
			st.prompt(t)
			t0 := time.Now()
			tc.act(r, st, cancel)
			wait(t, done)
			if d := time.Since(t0); d > 2*time.Second {
				t.Errorf("tardó %v", d)
			}
			cancel() // gRPC cancela el contexto del stream al volver el manejador
			r.cerrada("terminal.failed", tc.want)
			if !goroutinesAt(base) {
				buf := make([]byte, 1<<16)
				t.Fatalf("goroutines %d > base %d\n%s", runtime.NumGoroutine(), base, buf[:runtime.Stack(buf, true)])
			}
		})
	}
}

func TestTecleadaTimeout(t *testing.T) {
	r := newRig(t, simulator.Config{OTP: otp})
	r.svc.authWait = 200 * time.Millisecond
	st, done, cancel := r.session(r.typed("admin"))
	defer cancel()
	st.prompt(t)
	err := wait(t, done)
	if status.Code(err) != codes.DeadlineExceeded || reason(t, err) != "terminal.err.auth_timeout" {
		t.Fatalf("err = %v (%s)", err, reason(t, err))
	}
	r.cerrada("terminal.failed", "timed out")
}

func TestTecleadaRespuestaMala(t *testing.T) {
	for name, f := range map[string]func(st *fakeStream, seq uint32){
		"seq":      func(st *fakeStream, seq uint32) { st.answer(seq+1, "pw", otp) },
		"cantidad": func(st *fakeStream, seq uint32) { st.answer(seq, "pw") },
	} {
		t.Run(name, func(t *testing.T) {
			var att atomic.Int32
			r := newRig(t, simulator.Config{OTP: otp, Attempts: &att})
			st, done, cancel := r.session(r.typed("admin"))
			defer cancel()
			p, _ := st.prompt(t)
			f(st, p.Seq)
			err := wait(t, done)
			if status.Code(err) != codes.InvalidArgument || reason(t, err) != "terminal.err.auth_answer" {
				t.Fatalf("err = %v (%s)", err, reason(t, err))
			}
			if att.Load() != 0 {
				t.Errorf("el equipo recibió %d respuestas", att.Load())
			}
			r.cerrada("terminal.failed", "credential=typed")
		})
	}
}

func TestTecleadaBovedaCerrada(t *testing.T) {
	r := newRig(t, simulator.Config{OTP: otp})
	r.d.V.LockAll()
	st, done, cancel := r.session(r.typed("admin"))
	defer cancel()
	p, _ := st.prompt(t)
	st.answer(p.Seq, "pw", otp)
	st.waitFor(t, "SW1>")
	close(st.in)
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
	r.cerrada("terminal.close", "closed by the user")
	if a := r.d.AuditText(); !strings.Contains(a, `"action":"terminal.open"`) || !strings.Contains(a, `credential=typed`) {
		t.Errorf("terminal.open no quedó auditado con la bóveda cerrada:\n%s", a)
	}
}

func TestTecleadaNoFiltra(t *testing.T) {
	const marca = "MARCA-SECRETA-9f3"
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)
	t.Run("falla", func(t *testing.T) { // la contraseña es otra: tres intentos con la marca
		r := newRig(t, simulator.Config{OTP: otp})
		st, done, cancel := r.session(r.typed("admin"))
		defer cancel()
		for i := 0; i < 3; i++ {
			p, _ := st.prompt(t)
			st.answer(p.Seq, marca, marca)
		}
		if err := wait(t, done); err == nil || strings.Contains(err.Error(), marca) {
			t.Fatalf("err = %v", err)
		}
		buscaMarca(t, r, marca, logs.String())
	})
	t.Run("exito", func(t *testing.T) {
		r := newRig(t, simulator.Config{OTP: marca})
		st, done, cancel := r.session(r.typed("admin"))
		defer cancel()
		p, _ := st.prompt(t)
		st.answer(p.Seq, "pw", marca)
		st.waitFor(t, "SW1>")
		st.data("show version\r")
		st.waitFor(t, "Cisco")
		close(st.in)
		wait(t, done)
		buscaMarca(t, r, marca, logs.String())
	})
}

// buscaMarca revisa la grabación (todo Outputs), la auditoría y el log.
func buscaMarca(t *testing.T, r *rig, marca, log string) {
	t.Helper()
	if strings.Contains(r.d.AuditText(), marca) || strings.Contains(log, marca) {
		t.Errorf("la marca está en la auditoría o en el log")
	}
	filepath.WalkDir(r.d.Outputs(), func(p string, e fs.DirEntry, err error) error {
		if err == nil && !e.IsDir() {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), marca) {
				t.Errorf("la marca está en %s", p)
			}
		}
		return nil
	})
}

func TestUsernameConCredencialRechaza(t *testing.T) {
	var conns atomic.Int32
	r := newRig(t, simulator.Config{Conns: &conns})
	o := proto.Clone(r.open).(*v1.TerminalOpen)
	o.Username = "root"
	for name, tc := range map[string]struct {
		o   *v1.TerminalOpen
		why string
	}{
		"con credencial": {o, "terminal.err.username_with_credential"},
		"control":        {r.typed("ad\x00min"), "terminal.err.username"},
		"salto":          {r.typed("ad\nmin"), "terminal.err.username"},
		"utf8":           {r.typed("ad\xffmin"), "terminal.err.username"},
		"largo":          {r.typed(strings.Repeat("a", 129)), "terminal.err.username"},
		"formato":        {r.typed("ad\u200bmin"), "terminal.err.username"},
		"bidi":           {r.typed("ad\u202emin"), "terminal.err.username"},
		"c1":             {r.typed("ad\u0085min"), "terminal.err.username"},
	} {
		_, done, cancel := r.session(tc.o)
		err := wait(t, done)
		cancel()
		if status.Code(err) != codes.InvalidArgument || reason(t, err) != tc.why {
			t.Errorf("%s: %v (%s)", name, err, reason(t, err))
		}
	}
	if conns.Load() != 0 {
		t.Errorf("conectó %d veces", conns.Load())
	}
}

func TestTecleadaHuellaNueva(t *testing.T) {
	var att atomic.Int32
	r := newRig(t, simulator.Config{OTP: otp, Attempts: &att})
	o := r.typed("admin")
	o.AcceptedHostKeyFingerprints = nil
	st, done, cancel := r.session(o)
	defer cancel()
	err := wait(t, done)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "SHA256:") {
		t.Fatalf("err = %v", err)
	}
	for len(st.out) > 0 {
		if m := <-st.out; m.AuthPrompt != nil {
			t.Fatal("preguntó antes de verificar la huella")
		}
	}
	if att.Load() != 0 {
		t.Errorf("el equipo recibió respuestas")
	}
	r.cerrada("terminal.failed", "unknown host key")
	_ = transport.ErrAuth
}

func capturaLog(t *testing.T) *bytes.Buffer {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &logs
}

// Más caminos de la marca: data durante la autenticación, respuestas rechazadas, «login as:» inválido y timeout.
func TestTecleadaNoFiltraOtrosCaminos(t *testing.T) {
	const marca = "MARCA-OTROS-77c"
	logs := capturaLog(t)
	t.Run("data", func(t *testing.T) {
		r := newRig(t, simulator.Config{OTP: otp})
		st, done, cancel := r.session(r.typed("admin"))
		defer cancel()
		p, _ := st.prompt(t)
		st.data(marca)
		st.answer(p.Seq, "pw", otp)
		st.waitFor(t, "SW1>")
		st.data("show version\r")
		st.waitFor(t, "Cisco")
		close(st.in)
		wait(t, done)
		buscaMarca(t, r, marca, logs.String())
	})
	for name, f := range map[string]func(st *fakeStream, seq uint32){
		"seq":      func(st *fakeStream, seq uint32) { st.answer(seq+1, marca, marca) },
		"cantidad": func(st *fakeStream, seq uint32) { st.answer(seq, marca) },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, simulator.Config{OTP: otp})
			st, done, cancel := r.session(r.typed("admin"))
			defer cancel()
			p, _ := st.prompt(t)
			f(st, p.Seq)
			if err := wait(t, done); err == nil || strings.Contains(err.Error(), marca) {
				t.Fatalf("err = %v", err)
			}
			buscaMarca(t, r, marca, logs.String())
		})
	}
	t.Run("login", func(t *testing.T) {
		r := newRig(t, simulator.Config{OTP: otp})
		st, done, cancel := r.session(r.typed(""))
		defer cancel()
		p, _ := st.prompt(t)
		st.answer(p.Seq, marca+"\x00")
		err := wait(t, done)
		if reason(t, err) != "terminal.err.username" || strings.Contains(err.Error(), marca) {
			t.Fatalf("err = %v", err)
		}
		buscaMarca(t, r, marca, logs.String())
	})
	t.Run("timeout", func(t *testing.T) {
		r := newRig(t, simulator.Config{OTP: otp})
		r.svc.authWait = 200 * time.Millisecond
		st, done, cancel := r.session(r.typed("admin"))
		defer cancel()
		st.prompt(t)
		st.data(marca)
		if err := wait(t, done); reason(t, err) != "terminal.err.auth_timeout" {
			t.Fatalf("err = %v", err)
		}
		buscaMarca(t, r, marca, logs.String())
	})
}

// Una respuesta que llega antes de su pregunta no se acepta aunque traiga el seq esperado.
func TestTecleadaRespuestaAdelantada(t *testing.T) {
	r := newRig(t, simulator.Config{OTP: otp})
	st, done, cancel := r.session(r.typed("admin"))
	defer cancel()
	p, _ := st.prompt(t)
	st.answer(p.Seq, "pw", "000000") // mala: el equipo la rechaza y vuelve a preguntar
	st.answer(p.Seq+1, "pw", otp)    // buena, pero adelantada: la siguiente pregunta aún no existe
	for len(st.in) > 0 {             // el Recv ya la tiene en la mano
		time.Sleep(time.Millisecond)
	}
	p2, _ := st.prompt(t)
	if p2.Seq != p.Seq+1 {
		t.Fatalf("seq = %d", p2.Seq)
	}
	select {
	case m := <-st.out:
		t.Fatalf("aceptó la respuesta adelantada: %+v", m)
	case err := <-done:
		t.Fatalf("terminó: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	st.answer(p2.Seq, "pw", otp)
	st.waitFor(t, "SW1>")
	close(st.in)
	wait(t, done)
}

func ceros(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func rawAnswer(seq uint32, ans ...[]byte) *v1.OpenTerminalRequest {
	return &v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_AuthAnswer{AuthAnswer: &v1.AuthAnswer{Seq: seq, Answers: ans}}}
}

// Toda respuesta ignorada se pone en ceros: la rechazada, la que llega tarde y la que queda en la mano del Recv al cancelar.
func TestTecleadaIgnoradasEnCeros(t *testing.T) {
	t.Run("rechazada", func(t *testing.T) {
		r := newRig(t, simulator.Config{OTP: otp})
		st, done, cancel := r.session(r.typed("admin"))
		defer cancel()
		p, _ := st.prompt(t)
		b := []byte("secreto-rechazado")
		st.in <- rawAnswer(p.Seq+1, b, b)
		wait(t, done)
		if !ceros(b) {
			t.Errorf("sin borrar: %q", b)
		}
	})
	t.Run("tarde", func(t *testing.T) {
		r := newRig(t, simulator.Config{OTP: otp})
		st, done, cancel := r.session(r.typed("admin"))
		defer cancel()
		p, _ := st.prompt(t)
		st.answer(p.Seq, "pw", otp)
		st.waitFor(t, "SW1>")
		b := []byte("secreto-tarde")
		st.in <- rawAnswer(p.Seq, b)
		for len(st.in) > 0 {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
		close(st.in)
		wait(t, done)
		if !ceros(b) {
			t.Errorf("sin borrar: %q", b)
		}
	})
	t.Run("en la mano del Recv", func(t *testing.T) {
		r := newRig(t, simulator.Config{OTP: otp})
		st, done, cancel := r.session(r.typed("admin"))
		defer cancel()
		p, _ := st.prompt(t)
		a, b := []byte("uno"), []byte("secreto-en-mano")
		st.in <- rawAnswer(p.Seq+1, a, a) // la primera se rechaza y cierra
		st.in <- rawAnswer(p.Seq, b)      // la segunda queda en la mano del Recv
		wait(t, done)
		for i := 0; i < 100 && !ceros(b); i++ {
			time.Sleep(10 * time.Millisecond)
		}
		if !ceros(b) {
			t.Errorf("sin borrar: %q", b)
		}
	})
}

func TestTecleadaRespuestaGrande(t *testing.T) {
	r := newRig(t, simulator.Config{OTP: otp})
	st, done, cancel := r.session(r.typed("admin"))
	defer cancel()
	p, _ := st.prompt(t)
	st.answer(p.Seq, "pw", strings.Repeat("9", 1025))
	err := wait(t, done)
	if status.Code(err) != codes.InvalidArgument || reason(t, err) != "terminal.err.auth_answer" {
		t.Fatalf("err = %v (%s)", err, reason(t, err))
	}
}

func TestTecleadaUsuarioConEspaciosYFormatoEnLogin(t *testing.T) {
	r := newRig(t, simulator.Config{OTP: otp})
	st, done, cancel := r.session(r.typed("  admin \t"))
	defer cancel()
	p, _ := st.prompt(t)
	st.answer(p.Seq, "pw", otp)
	if f := <-st.out; f.Opened != "admin@"+r.host+":"+strconv.Itoa(int(r.port)) {
		t.Fatalf("opened = %q", f.Opened)
	}
	close(st.in)
	wait(t, done)
	for name, u := range map[string]string{"formato": "ad\u200bmin", "bidi": "ad\u202emin", "c1": "ad\u0085min", "largo": strings.Repeat("a", 129), "vacío": "  "} {
		r := newRig(t, simulator.Config{OTP: otp})
		st, done, cancel := r.session(r.typed(""))
		p, _ := st.prompt(t)
		st.answer(p.Seq, u)
		if err := wait(t, done); status.Code(err) != codes.InvalidArgument || reason(t, err) != "terminal.err.username" {
			t.Errorf("%s: %v", name, err)
		}
		cancel()
	}
}

func TestTecleadaSinMetodo(t *testing.T) {
	_, pub, err := servicetest.New(t).CreateVault().GenerateKey("k", "k") // el equipo solo ofrece publickey
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, simulator.Config{NoPassword: true, AuthorizedKeys: simulator.Keys(simulator.ParseAuthorizedKey(t, pub.AuthorizedKey()))})
	st, done, cancel := r.session(r.typed("admin"))
	defer cancel()
	err = wait(t, done)
	if status.Code(err) != codes.FailedPrecondition || reason(t, err) != "terminal.err.auth_no_method" {
		t.Fatalf("err = %v (%s)", err, reason(t, err))
	}
	r.cerrada("terminal.failed", "offers neither password nor keyboard-interactive")
	_ = st
}

func TestTecleadaResizeDuranteAutenticacion(t *testing.T) {
	var mu sync.Mutex
	var got [2]uint32
	r := newRig(t, simulator.Config{OTP: otp, OnPtySize: func(c, rw uint32) { mu.Lock(); got = [2]uint32{c, rw}; mu.Unlock() }})
	st, done, cancel := r.session(r.typed("admin"))
	defer cancel()
	p, _ := st.prompt(t)
	st.in <- &v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Resize{Resize: &v1.TerminalSize{Rows: 40, Cols: 120}}}
	st.answer(p.Seq, "pw", otp)
	st.waitFor(t, "SW1>")
	close(st.in)
	wait(t, done)
	mu.Lock()
	defer mu.Unlock()
	if got != [2]uint32{120, 40} {
		t.Errorf("pty = %v, quería 120x40", got)
	}
}

func TestTecleadaTextosEnIngles(t *testing.T) {
	r := newRig(t, simulator.Config{OTP: otp})
	st, done, cancel := r.sessionCtx(i18n.WithLocale(context.Background(), "en"), r.typed(""))
	defer cancel()
	p, _ := st.prompt(t)
	if p.Prompts[0].Text != "login as: " {
		t.Fatalf("login = %q", p.Prompts[0].Text)
	}
	st.answer(p.Seq, "admin")
	p, _ = st.prompt(t)
	st.answer(p.Seq, "pw", "000000")
	_, data := st.prompt(t)
	if !strings.Contains(data, "Access denied\r\n") {
		t.Errorf("data = %q", data)
	}
	cancel()
	wait(t, done)
}

func TestTecleadaCancelarEnLoginAs(t *testing.T) {
	r := newRig(t, simulator.Config{OTP: otp})
	base := runtime.NumGoroutine()
	st, done, cancel := r.session(r.typed(""))
	defer cancel()
	st.prompt(t)
	t0 := time.Now()
	cancel()
	wait(t, done)
	if time.Since(t0) > 2*time.Second {
		t.Error("tardó")
	}
	r.cerrada("terminal.failed", "client disconnected")
	if !goroutinesAt(base) {
		t.Fatalf("goroutines %d > base %d", runtime.NumGoroutine(), base)
	}
}

// Revisión de 47t-4 sobre #280: una huella por host ilegible se rechaza antes de preguntar «login as:», sin marcar.
func TestTecleadaHuellaInvalidaAntesDeLoginAs(t *testing.T) {
	var conns atomic.Int32
	r := newRig(t, simulator.Config{OTP: otp, Conns: &conns})
	o := r.typed("")
	fp := o.AcceptedHostKeyFingerprints[0]
	o.AcceptedHostKeyFingerprints = nil
	o.AcceptedHostKeys = []*v1.AcceptedHostKey{{Host: "sw1:0", Fingerprint: fp}} // puerto 0: hostkey.err.accept_invalid
	st, done, cancel := r.session(o)
	defer cancel()
	if err := wait(t, done); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v", err)
	}
	for len(st.out) > 0 {
		if m := <-st.out; m.AuthPrompt != nil {
			t.Fatal("preguntó «login as:» con una huella ilegible")
		}
	}
	if conns.Load() != 0 {
		t.Errorf("marcó al equipo %d veces", conns.Load())
	}
}

// Las huellas por host (accepted_host_keys) valen en modo tecleado: la del equipo abre, la de otro equipo no.
func TestTecleadaHuellasPorHost(t *testing.T) {
	for _, ajena := range []bool{false, true} {
		r := newRig(t, simulator.Config{OTP: otp}) // uno por caso: la llave aceptada queda en known_hosts
		fp := r.open.AcceptedHostKeyFingerprints[0]
		c := struct {
			host string
			abre bool
		}{transport.HostKeyID(r.host, r.port), true}
		if ajena {
			c.host, c.abre = "192.0.2.9", false
		}
		o := r.typed("admin")
		o.AcceptedHostKeyFingerprints = nil
		o.AcceptedHostKeys = []*v1.AcceptedHostKey{{Host: c.host, Fingerprint: fp}}
		st, done, cancel := r.session(o)
		if !c.abre {
			if err := wait(t, done); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "SHA256:") {
				t.Fatalf("%s: err = %v", c.host, err)
			}
			cancel()
			continue
		}
		m, _ := st.prompt(t)
		st.answer(m.Seq, "pw", otp)
		if first := <-st.out; first.Opened == "" {
			t.Fatalf("%s: primer evento = %+v", c.host, first)
		}
		close(st.in)
		if err := wait(t, done); err != nil {
			t.Fatalf("%s: %v", c.host, err)
		}
		cancel()
	}
}
