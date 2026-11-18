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
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
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
