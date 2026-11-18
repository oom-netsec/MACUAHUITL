package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

type askSim struct {
	g        *Guard
	host     string
	port     uint16
	hk       ssh.PublicKey
	attempts *atomic.Int32
	conns    *atomic.Int32
}

func startAskSim(t *testing.T, c simulator.Config) askSim {
	t.Helper()
	c.Hostname, c.Username, c.Password, c.Transcripts = "SW1", "admin", "pw", iosxeDir()
	c.Attempts, c.Conns = new(atomic.Int32), new(atomic.Int32)
	addr, hk := simulator.Start(t, c)
	ap := netip.MustParseAddrPort(addr)
	g := NewGuard(nil, nil)
	if err := g.Allow(context.Background(), "j", []string{ap.Addr().String()}); err != nil {
		t.Fatal(err)
	}
	return askSim{g, ap.Addr().String(), ap.Port(), hk, c.Attempts, c.Conns}
}

func (s askSim) open(ctx context.Context, cred vault.Credential, o SSHOptions) (*Session, error) {
	return OpenSSH(ctx, s.g, "j", s.host, s.port, cred, ssh.FixedHostKey(s.hk), o)
}

func userOnly() vault.Credential { return vault.Credential{Username: "admin"} }

// scripted responde el par MFA (dos preguntas) y anota cada ronda.
type scripted struct {
	mu      sync.Mutex
	prompts []Prompt
	pw, otp string
}

func (s *scripted) ask(_ context.Context, p Prompt) ([][]byte, error) {
	s.mu.Lock()
	s.prompts = append(s.prompts, p)
	s.mu.Unlock()
	if len(p.Questions) == 2 {
		return [][]byte{[]byte(s.pw), []byte(s.otp)}, nil
	}
	return [][]byte{[]byte(s.pw)}, nil
}

func TestAskRelayaMFA(t *testing.T) {
	sim := startAskSim(t, simulator.Config{OTP: "123456"})
	sc := &scripted{pw: "pw", otp: "123456"}
	s, err := sim.open(context.Background(), userOnly(), SSHOptions{Ask: sc.ask})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(sc.prompts) != 1 {
		t.Fatalf("rondas = %d", len(sc.prompts))
	}
	p := sc.prompts[0]
	want := Prompt{Name: "MFA", Instruction: "Enter password and code", Attempt: 1,
		Questions: []Question{{"Password: ", false}, {"Verification code: ", true}}}
	if p.Name != want.Name || p.Instruction != want.Instruction || p.Attempt != 1 || len(p.Questions) != 2 || p.Questions[0] != want.Questions[0] || p.Questions[1] != want.Questions[1] {
		t.Fatalf("prompt = %+v", p)
	}
	if _, _, err := s.Shell(); err != nil {
		t.Fatal(err)
	}
	// Código malo una vez y luego bueno: Attempt sube a 2.
	n := 0
	sc2 := &scripted{pw: "pw"}
	s2, err := sim.open(context.Background(), userOnly(), SSHOptions{Ask: func(_ context.Context, p Prompt) ([][]byte, error) {
		n++
		sc2.otp = map[int]string{1: "000000", 2: "123456"}[n]
		return sc2.ask(context.Background(), p)
	}})
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()
	if len(sc2.prompts) != 2 || sc2.prompts[1].Attempt != 2 {
		t.Fatalf("prompts = %+v", sc2.prompts)
	}
}

func TestAskTopeTresIntentos(t *testing.T) {
	sim := startAskSim(t, simulator.Config{OTP: "123456"})
	sc := &scripted{pw: "pw", otp: "000000"}
	_, err := sim.open(context.Background(), userOnly(), SSHOptions{Ask: sc.ask})
	if !errors.Is(err, ErrAuthAttempts) {
		t.Fatalf("err = %v", err)
	}
	if a, c := sim.attempts.Load(), sim.conns.Load(); a != 3 || c != 1 {
		t.Fatalf("Attempts=%d Conns=%d", a, c)
	}
	if len(sc.prompts) != 3 {
		t.Fatalf("rondas = %d", len(sc.prompts))
	}
}

func TestAskPassword(t *testing.T) {
	sim := startAskSim(t, simulator.Config{}) // solo password
	sc := &scripted{pw: "pw"}
	s, err := sim.open(context.Background(), userOnly(), SSHOptions{Ask: sc.ask})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if len(sc.prompts) != 1 || len(sc.prompts[0].Questions) != 1 {
		t.Fatalf("prompts = %+v", sc.prompts)
	}
	if q := sc.prompts[0].Questions[0]; q.Text != fmt.Sprintf("admin@%s's password: ", sim.host) || q.Echo {
		t.Fatalf("pregunta = %+v", q)
	}
	bad := &scripted{pw: "mala"}
	_, err = sim.open(context.Background(), userOnly(), SSHOptions{Ask: bad.ask})
	if !errors.Is(err, ErrAuthAttempts) || sim.attempts.Load() != 4 { // 1 del éxito + 3 de las malas
		t.Fatalf("err = %v, attempts = %d", err, sim.attempts.Load())
	}
}

func TestAskEsperaMasQueElHandshake(t *testing.T) {
	sim := startAskSim(t, simulator.Config{OTP: "123456"})
	sc := &scripted{pw: "pw", otp: "123456"}
	s, err := sim.open(context.Background(), userOnly(), SSHOptions{HandshakeTimeout: 300 * time.Millisecond, Ask: func(_ context.Context, p Prompt) ([][]byte, error) {
		time.Sleep(900 * time.Millisecond)
		return sc.ask(context.Background(), p)
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, _, err := s.Shell(); err != nil {
		t.Fatal(err)
	}
}

func TestAskCanceladoNoDejaNada(t *testing.T) {
	sim := startAskSim(t, simulator.Config{OTP: "123456"})
	before := runtime.NumGoroutine()
	release := make(chan struct{})
	wiped := make(chan struct{})
	lateWiped = func() { close(wiped) }
	defer func() { lateWiped = nil }()
	late := []byte("pw") // lo que Ask devuelve tarde, ya cancelado: debe quedar en ceros
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	_, err := sim.open(ctx, userOnly(), SSHOptions{Ask: func(context.Context, Prompt) ([][]byte, error) {
		<-release
		return [][]byte{late, []byte("123456")}, nil
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("tardó %v", d)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before+1 {
		t.Fatalf("goroutines: %d -> %d", before, n)
	}
	select {
	case <-wiped:
	case <-time.After(2 * time.Second):
		t.Fatal("la respuesta tardía no se borró")
	}
	if string(late) != "\x00\x00" {
		t.Fatalf("respuesta tardía sin borrar: %q", late)
	}
}

func TestAskErrorPropioAborta(t *testing.T) {
	sim := startAskSim(t, simulator.Config{OTP: "123456"})
	boom := errors.New("usuario canceló")
	_, err := sim.open(context.Background(), userOnly(), SSHOptions{Ask: func(context.Context, Prompt) ([][]byte, error) { return nil, boom }})
	if !errors.Is(err, boom) || sim.attempts.Load() != 0 {
		t.Fatalf("err = %v, attempts = %d", err, sim.attempts.Load())
	}
}

func TestCredencialVaciaNoMarca(t *testing.T) {
	sim := startAskSim(t, simulator.Config{})
	_, err := sim.open(context.Background(), userOnly(), SSHOptions{})
	if !errors.Is(err, ErrNoCredential) || sim.conns.Load() != 0 {
		t.Fatalf("err = %v, conns = %d", err, sim.conns.Load())
	}
}

func TestAskConSecretoRechaza(t *testing.T) {
	sim := startAskSim(t, simulator.Config{})
	ask := func(context.Context, Prompt) ([][]byte, error) { t.Error("Ask no debe llamarse"); return nil, nil }
	for name, c := range map[string]vault.Credential{
		"password": {Username: "admin", Password: secret.New([]byte("pw"))},
		"llave":    {Username: "admin", SSHKey: secret.New([]byte("x"))},
	} {
		_, err := sim.open(context.Background(), c, SSHOptions{Ask: ask, GenericHost: true})
		if !errors.Is(err, ErrTypedMixed) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if sim.conns.Load() != 0 {
		t.Fatalf("conns = %d", sim.conns.Load())
	}
}

// kiServer es un servidor crudo cuya ronda keyboard-interactive la fija la prueba; acepta cualquier respuesta.
func kiServer(t *testing.T, name, ins string, qs []string, echos []bool) (*Guard, string, uint16, ssh.PublicKey) {
	t.Helper()
	return rawServer(t, &ssh.ServerConfig{KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		if _, err := ch(name, ins, qs, echos); err != nil {
			return nil, err
		}
		return nil, nil
	}})
}

// rawServer levanta un servidor x/crypto con la configuración de la prueba (sin shell: rechaza todo canal).
func rawServer(t *testing.T, cfg *ssh.ServerConfig) (*Guard, string, uint16, ssh.PublicKey) {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(mustEd25519(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if sc, chans, reqs, err := ssh.NewServerConn(c, cfg); err == nil {
					go ssh.DiscardRequests(reqs)
					go func() {
						for ch := range chans {
							ch.Reject(ssh.Prohibited, "")
						}
					}()
					sc.Wait()
				}
			}()
		}
	}()
	ap := netip.MustParseAddrPort(ln.Addr().String())
	g := NewGuard(nil, nil)
	if err := g.Allow(context.Background(), "j", []string{ap.Addr().String()}); err != nil {
		t.Fatal(err)
	}
	g.AllowAnyOnPorts("j", []uint16{ap.Port()})
	return g, ap.Addr().String(), ap.Port(), signer.PublicKey()
}

// chainKI: n rondas con éxito parcial y la siguiente (n+1) entra; n<0 es un equipo que siempre pide otra.
func chainKI(n int) *ssh.ServerConfig {
	var cb func(left int) func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error)
	cb = func(left int) func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		return func(_ ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if _, err := ch("", "paso", []string{"Código: "}, []bool{true}); err != nil {
				return nil, err
			}
			if left == 0 {
				return nil, nil
			}
			return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{KeyboardInteractiveCallback: cb(left - 1)}}
		}
	}
	return &ssh.ServerConfig{KeyboardInteractiveCallback: cb(n)}
}

func TestAskParcialNoCuentaComoFallo(t *testing.T) {
	g, host, port, hk := rawServer(t, chainKI(3)) // 3 parciales y la cuarta entra: contarlos como fallos abortaría a la tercera
	rounds := 0
	s, err := OpenSSH(context.Background(), g, "j", host, port, userOnly(), ssh.FixedHostKey(hk), SSHOptions{Ask: func(_ context.Context, p Prompt) ([][]byte, error) {
		rounds++
		if p.Attempt != 1 {
			t.Errorf("ronda %d: Attempt = %d", rounds, p.Attempt)
		}
		return [][]byte{[]byte("1")}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if rounds != 4 {
		t.Fatalf("rondas = %d", rounds)
	}
}

func TestAskTopeDeRondas(t *testing.T) {
	g, host, port, hk := rawServer(t, chainKI(1000)) // siempre pide otra: x/crypto lo dejaría llegar a 64
	rounds := 0
	_, err := OpenSSH(context.Background(), g, "j", host, port, userOnly(), ssh.FixedHostKey(hk), SSHOptions{Ask: func(context.Context, Prompt) ([][]byte, error) {
		rounds++
		return [][]byte{[]byte("1")}, nil
	}})
	if !errors.Is(err, ErrAuthRounds) || rounds != 10 {
		t.Fatalf("err = %v, rondas = %d", err, rounds)
	}
}

// Un equipo que calla tras recibir la respuesta muere por HandshakeTimeout: el plazo se repone al volver Ask.
func TestAskReponeElPlazo(t *testing.T) {
	quiet := make(chan struct{})
	t.Cleanup(func() { close(quiet) })
	g, host, port, hk := rawServer(t, &ssh.ServerConfig{KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		if _, err := ch("", "", []string{"x: "}, []bool{false}); err != nil {
			return nil, err
		}
		<-quiet
		return nil, errors.New("tarde")
	}})
	done := make(chan error, 1)
	go func() {
		_, err := OpenSSH(context.Background(), g, "j", host, port, userOnly(), ssh.FixedHostKey(hk), SSHOptions{HandshakeTimeout: 300 * time.Millisecond, Ask: func(context.Context, Prompt) ([][]byte, error) {
			time.Sleep(500 * time.Millisecond) // pasa el plazo mientras espera
			return [][]byte{[]byte("a")}, nil
		}})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("debió fallar por plazo")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("el handshake no cortó: el plazo no se repuso")
	}
}

// Con password y keyboard-interactive a la vez se usa keyboard-interactive.
func TestAskPrefiereKeyboardInteractive(t *testing.T) {
	var pwUsed atomic.Bool
	g, host, port, hk := rawServer(t, &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { pwUsed.Store(true); return nil, nil },
		KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			_, err := ch("KI", "", []string{"Código: "}, []bool{true})
			return nil, err
		}})
	var got Prompt
	s, err := OpenSSH(context.Background(), g, "j", host, port, userOnly(), ssh.FixedHostKey(hk), SSHOptions{Ask: func(_ context.Context, p Prompt) ([][]byte, error) {
		got = p
		return [][]byte{[]byte("1")}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if got.Name != "KI" || pwUsed.Load() {
		t.Fatalf("prompt = %+v, password usado = %v", got, pwUsed.Load())
	}
}

func TestAskSanea(t *testing.T) {
	run := func(name, ins string, qs []string, answers func(n int) [][]byte) (Prompt, error) {
		echos := make([]bool, len(qs))
		g, host, port, hk := kiServer(t, name, ins, qs, echos)
		var got Prompt
		s, err := OpenSSH(context.Background(), g, "j", host, port, userOnly(), ssh.FixedHostKey(hk), SSHOptions{Ask: func(_ context.Context, p Prompt) ([][]byte, error) {
			got = p
			return answers(len(p.Questions)), nil
		}})
		if err == nil {
			s.Close()
		}
		return got, err
	}
	one := func(n int) [][]byte {
		a := make([][]byte, n)
		for i := range a {
			a[i] = []byte("x")
		}
		return a
	}
	p, err := run("\x1b[31mM\u202eF\u2028A\x00", "uno\u2029\n\x1b]0;t\x07d\u200bos\r\u0085", []string{"Pass\x1b[2J\u2066\u2028word: \n"}, one)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "[31mMFA" || p.Instruction != "uno\n]0;tdos" || len(p.Questions) != 1 || p.Questions[0].Text != "Pass[2Jword: " {
		t.Fatalf("prompt = %+v", p)
	}
	rep := func(n int) string { return strings.Repeat("a", n) }
	qs := func(n int) []string {
		r := make([]string, n)
		for i := range r {
			r[i] = "q"
		}
		return r
	}
	// En el tope pasa; un byte más es ErrTypedPrompt y Ask ni se llama.
	if _, err := run(rep(128), rep(1024), []string{rep(256)}, one); err != nil {
		t.Fatalf("en el tope: %v", err)
	}
	if _, err := run("n", "i", qs(16), one); err != nil {
		t.Fatalf("16 preguntas: %v", err)
	}
	for name, f := range map[string]func() (Prompt, error){
		"name":        func() (Prompt, error) { return run(rep(129), "", []string{"q"}, one) },
		"instruction": func() (Prompt, error) { return run("", rep(1025), []string{"q"}, one) },
		"texto":       func() (Prompt, error) { return run("", "", []string{rep(257)}, one) },
		"preguntas":   func() (Prompt, error) { return run("", "", qs(17), one) },
	} {
		got, err := f()
		if !errors.Is(err, ErrTypedPrompt) || got.Questions != nil {
			t.Fatalf("%s: err = %v, prompt = %+v", name, err, got)
		}
	}
	// Respuestas de más, de menos o de más de 1 KiB.
	for name, a := range map[string][][]byte{"de más": {[]byte("a"), []byte("b")}, "de menos": {}, "grande": {[]byte(rep(1025))}} {
		_, err := run("", "", []string{"q"}, func(int) [][]byte { return a })
		if !errors.Is(err, ErrTypedPrompt) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	// Respuestas a cero tras usarse.
	ans := []byte("secreto")
	if _, err := run("", "", []string{"q"}, func(int) [][]byte { return [][]byte{ans} }); err != nil {
		t.Fatal(err)
	}
	if string(ans) != strings.Repeat("\x00", len("secreto")) {
		t.Fatalf("respuesta sin borrar: %q", ans)
	}
}

// askFuera lista los lugares donde un archivo fija SSHOptions.Ask: un literal SSHOptions{Ask: …} o una asignación x.Ask = ….
func askFuera(f *ast.File) []token.Pos {
	var out []token.Pos
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			var name string
			switch ty := n.Type.(type) {
			case *ast.Ident:
				name = ty.Name
			case *ast.SelectorExpr:
				name = ty.Sel.Name
			}
			if name == "SSHOptions" {
				for _, e := range n.Elts {
					if kv, ok := e.(*ast.KeyValueExpr); ok {
						if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Ask" {
							out = append(out, kv.Pos())
						}
					}
				}
			}
		case *ast.AssignStmt:
			for _, l := range n.Lhs {
				if s, ok := l.(*ast.SelectorExpr); ok && s.Sel.Name == "Ask" {
					out = append(out, s.Pos())
				}
			}
		}
		return true
	})
	return out
}

func TestAskSoloEnTerminal(t *testing.T) {
	parse := func(src string) *ast.File {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	if len(askFuera(parse(`package p; var _ = transport.SSHOptions{Ask: f}`))) != 1 || len(askFuera(parse(`package p; func g(){ o.Ask = f }`))) != 1 {
		t.Fatal("la guarda no detecta lo que debe")
	}
	_, self, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(self), "..", "..")
	allowed := filepath.Join(root, "internal", "service", "terminal")
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules" || d.Name() == "vendor" || p == allowed) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, p, src, 0)
		if err != nil {
			return nil // un .go que no compila no es asunto de esta guarda
		}
		for _, pos := range askFuera(f) {
			t.Errorf("%s: SSHOptions.Ask solo se fija en internal/service/terminal", fset.Position(pos))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func mustEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
