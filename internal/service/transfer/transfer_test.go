package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

type fakeStream struct {
	v1.TransferService_StartServerServer
	ctx context.Context
	out chan *v1.StartServerResponse
}

func (f *fakeStream) Context() context.Context { return f.ctx }
func (f *fakeStream) Send(r *v1.StartServerResponse) error {
	select {
	case f.out <- r:
	case <-f.ctx.Done():
	}
	return nil
}

type running struct {
	ready *v1.ServerReady
	out   chan *v1.StartServerResponse
	done  chan error
	stop  context.CancelFunc
}

func (r *running) transfers(t *testing.T, n int) []map[string]any {
	t.Helper()
	var got []map[string]any
	for len(got) < n {
		select {
		case ev := <-r.out:
			var m map[string]any
			json.Unmarshal([]byte(ev.GetTransferJson()), &m)
			got = append(got, m)
		case <-time.After(5 * time.Second):
			t.Fatalf("eventos = %v", got)
		}
	}
	return got
}

func startServer(t *testing.T, s *svc, req *v1.StartServerRequest) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	st := &fakeStream{ctx: ctx, out: make(chan *v1.StartServerResponse, 64)}
	r := &running{out: st.out, done: make(chan error, 1), stop: cancel}
	go func() { r.done <- s.StartServer(req, st) }()
	select {
	case ev := <-st.out:
		r.ready = ev.GetReady()
	case err := <-r.done:
		cancel()
		t.Fatalf("StartServer: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("el servidor no abrió")
	}
	t.Cleanup(func() { cancel(); <-r.done })
	return r
}

func newTest(t *testing.T) (*svc, *servicetest.Deps) {
	d := servicetest.New(t)
	s := newSvc(d)
	t.Cleanup(s.close)
	return s, d
}

func code(err error) codes.Code { return status.Code(err) }

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func TestServerLifecycleAndAudit(t *testing.T) {
	s, d := newTest(t)
	pub := t.TempDir()
	data := bytes.Repeat([]byte("hostname R1\n"), 300)
	os.WriteFile(filepath.Join(pub, "r1.cfg"), data, 0o600)
	run := startServer(t, s, &v1.StartServerRequest{Protocol: "tftp", Listen: "127.0.0.1:0", FromDir: pub, Write: true, Allow: []string{"127.0.0.1"}})
	rd := run.ready
	if rd.Protocol != "tftp" || !strings.HasPrefix(rd.Listening, "127.0.0.1:") || rd.FromDir != pub || len(rd.Files) != 1 || rd.Files[0] != "r1.cfg" {
		t.Fatalf("ready = %+v", rd)
	}
	// Carpeta de recepción por omisión: outputs/recibidos/<sello>/.
	if !strings.HasPrefix(rd.RecvDir, filepath.Join(d.Out, "recibidos")) {
		t.Fatalf("recv_dir = %q", rd.RecvDir)
	}
	if st, err := os.Stat(rd.RecvDir); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("carpeta de recepción: %v %v", st, err)
	}
	if !strings.Contains(rd.Hint, "copy running-config tftp://127.0.0.1/") || !strings.Contains(rd.Hint, "udp dport 69 redirect to :") {
		t.Fatalf("hint = %s", rd.Hint)
	}
	// Con el cliente propio: subir y bajar.
	up := "tftp://" + rd.Listening + "/subida.cfg"
	if _, err := s.Put(context.Background(), &v1.PutRequest{Url: up, FromDir: pub, Name: "r1.cfg"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(rd.RecvDir, "subida.cfg")); !bytes.Equal(got, data) {
		t.Fatal("el servidor no recibió el archivo")
	}
	dest := t.TempDir()
	resp, err := s.Get(context.Background(), &v1.GetRequest{Url: "tftp://" + rd.Listening + "/r1.cfg", DestDir: dest, Sha256: sha(data)})
	if err != nil {
		t.Fatal(err)
	}
	if r := resp.Result; r.Verified != "ok" || r.Sha256 != sha(data) || r.Path != filepath.Join(dest, "r1.cfg") || !strings.Contains(r.Report, "SHA-256") {
		t.Fatalf("result = %+v", r)
	}
	// Los eventos de las dos transferencias llegan al stream.
	ev := run.transfers(t, 2)
	if ev[0]["Proto"] != "tftp" {
		t.Fatalf("eventos = %v", ev)
	}
	// ListServers y StopServer.
	l, _ := s.ListServers(context.Background(), &v1.ListServersRequest{})
	if len(l.Servers) != 1 || l.Servers[0].Transfers != 2 || !l.Servers[0].Write {
		t.Fatalf("servers = %v", l.Servers)
	}
	if r, _ := s.StopServer(context.Background(), &v1.StopServerRequest{ServerId: rd.ServerId}); !r.Stopped {
		t.Fatal("no se detuvo")
	}
	if err := <-run.done; err != nil {
		t.Fatal(err)
	}
	run.done <- nil
	// El último evento es el cierre, con el comando para quitar la regla de nftables de este servidor.
	port := rd.Listening[strings.LastIndex(rd.Listening, ":")+1:]
	var closed *v1.ServerClosed
	for len(run.out) > 0 {
		if c := (<-run.out).GetClosed(); c != nil {
			closed = c
		}
	}
	if closed == nil || closed.Cleanup != "sudo nft delete table ip macuahuitl_tftp_"+port {
		t.Fatalf("evento de cierre = %+v", closed)
	}
	if r, _ := s.StopServer(context.Background(), &v1.StopServerRequest{ServerId: rd.ServerId}); r.Stopped {
		t.Fatal("detuvo dos veces")
	}
	// Auditoría: apertura (sin contraseña), transferencias con ruta y hash, y cierre.
	a := d.AuditText()
	for _, want := range []string{"transfer.serve.open", "receive_into=", "transfer.serve.transfer", "direction=write", "direction=read", sha(data), "transfer.serve.stop", "transfer.serve.close",
		"transfer.put.start", "transfer.put", "transfer.get", "guard=revoked"} {
		if !strings.Contains(a, want) {
			t.Errorf("falta %q en la auditoría", want)
		}
	}
	// Cada trabajo de cliente revoca su autorización al terminar (defer Revoke).
	jobs := regexp.MustCompile(`job=(xfer-[0-9a-f]+)`).FindAllStringSubmatch(a, -1)
	if len(jobs) < 2 {
		t.Fatalf("trabajos auditados: %v", jobs)
	}
	for _, j := range jobs {
		if c, err := d.G.Dial(context.Background(), j[1], "127.0.0.1", 9); err == nil || !errors.Is(err, transport.ErrEgressDenied) {
			if c != nil {
				c.Close()
			}
			t.Fatalf("el trabajo %s sigue autorizado: %v", j[1], err)
		}
	}
	// Tras el trabajo el guard no deja salir a esa dirección con el id del trabajo.
	if _, err := s.Get(context.Background(), &v1.GetRequest{Url: "tftp://" + rd.Listening + "/r1.cfg", DestDir: dest}); err == nil {
		t.Fatal("el servidor ya estaba detenido: la descarga debió fallar")
	}
}

func TestStartServerValidation(t *testing.T) {
	s, _ := newTest(t)
	pub := t.TempDir()
	for name, req := range map[string]*v1.StartServerRequest{
		"protocolo":            {Protocol: "gopher", Listen: "127.0.0.1"},
		"sin nada":             {Protocol: "tftp", Listen: "127.0.0.1"},
		"puerto privilegiado":  {Protocol: "tftp", Listen: "127.0.0.1:69", FromDir: pub},
		"host no es IP":        {Protocol: "tftp", Listen: "localhost:6969", FromDir: pub},
		"todas sin permiso":    {Protocol: "tftp", Listen: "0.0.0.0", FromDir: pub},
		"escribir sin lista":   {Protocol: "tftp", Listen: "0.0.0.0", AllowAny: true, Write: true},
		"IP de origen mala":    {Protocol: "tftp", Listen: "127.0.0.1", FromDir: pub, Allow: []string{"no-es-ip"}},
		"carpeta sensible":     {Protocol: "tftp", Listen: "127.0.0.1", FromDir: "/etc"},
		"recepcion sensible":   {Protocol: "ftp", Listen: "127.0.0.1", Write: true, RecvDir: "/usr/lib"},
		"recepcion relativa":   {Protocol: "ftp", Listen: "127.0.0.1", Write: true, RecvDir: "rel"},
		"escritura por http":   {Protocol: "http", Listen: "127.0.0.1", FromDir: pub, Write: true},
		"rango pasivo":         {Protocol: "ftp", Listen: "127.0.0.1", FromDir: pub, PassivePortMin: 5000, PassivePortMax: 4000},
		"pasivo privilegiado":  {Protocol: "ftp", Listen: "127.0.0.1", FromDir: pub, PassivePortMin: 80, PassivePortMax: 90},
		"carpeta es un enlace": {Protocol: "tftp", Listen: "127.0.0.1", FromDir: linkTo(t, pub)},
	} {
		st := &fakeStream{ctx: context.Background(), out: make(chan *v1.StartServerResponse, 4)}
		err := s.StartServer(req, st)
		if code(err) != codes.InvalidArgument {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if len(s.servers) != 0 {
		t.Fatal("quedaron servidores abiertos")
	}
}

func linkTo(t *testing.T, dir string) string {
	l := filepath.Join(t.TempDir(), "l")
	os.Symlink(dir, l)
	return l
}

func TestDefaultPortsAreHigh(t *testing.T) {
	for p, want := range map[string]string{"tftp": "127.0.0.1:6969", "ftp": "127.0.0.1:2121", "scp": "127.0.0.1:2222", "sftp": "127.0.0.1:2222", "http": "127.0.0.1:8080"} {
		if got, err := listenAddr(context.Background(), p, "127.0.0.1"); err != nil || got != want {
			t.Errorf("%s: %q %v", p, got, err)
		}
		if got, _ := listenAddr(context.Background(), p, "127.0.0.1"); strings.HasSuffix(got, ":69") || strings.HasSuffix(got, ":21") || strings.HasSuffix(got, ":22") {
			t.Errorf("%s: puerto privilegiado por omisión", p)
		}
	}
	if got, _ := listenAddr(context.Background(), "tftp", "::1"); got != "[::1]:6969" {
		t.Errorf("IPv6: %q", got)
	}
}

func TestMaxServers(t *testing.T) {
	s, _ := newTest(t)
	pub := t.TempDir()
	for i := 0; i < maxServers; i++ {
		startServer(t, s, &v1.StartServerRequest{Protocol: "tftp", Listen: "127.0.0.1:0", FromDir: pub})
	}
	st := &fakeStream{ctx: context.Background(), out: make(chan *v1.StartServerResponse, 4)}
	if err := s.StartServer(&v1.StartServerRequest{Protocol: "tftp", Listen: "127.0.0.1:0", FromDir: pub}, st); code(err) != codes.ResourceExhausted {
		t.Fatalf("err = %v", err)
	}
}

// SCP/SFTP con la credencial de la bóveda y llave de host estricta.
func TestSSHClientWithVaultAndStrictHostKey(t *testing.T) {
	for _, proto := range []string{"scp", "sftp"} {
		t.Run(proto, func(t *testing.T) {
			s, d := newTest(t)
			v := d.CreateVault()
			pub, recv := t.TempDir(), t.TempDir()
			data := []byte("imagen " + proto)
			os.WriteFile(filepath.Join(pub, "i.bin"), data, 0o600)
			run := startServer(t, s, &v1.StartServerRequest{Protocol: proto, Listen: "127.0.0.1:0", FromDir: pub, Write: true, RecvDir: recv, Allow: []string{"127.0.0.1"}})
			rd := run.ready
			if rd.User == "" || len(rd.Password) < 12 || len(rd.Fingerprints) != 2 {
				t.Fatalf("ready = %+v", rd)
			}
			if strings.Contains(d.AuditText(), rd.Password) {
				t.Fatal("la contraseña de sesión llegó a la auditoría")
			}
			id, err := v.Put(vault.Credential{Label: "srv", Username: rd.User, Password: secret.New([]byte(rd.Password))})
			if err != nil {
				t.Fatal(err)
			}
			url := proto + "://" + rd.Listening + "/i.bin"
			dest := t.TempDir()
			// Sin credencial, o sin aceptar la huella de una llave nueva, no entra.
			if _, err := s.Get(context.Background(), &v1.GetRequest{Url: url, DestDir: dest}); code(err) != codes.InvalidArgument {
				t.Fatalf("sin --cred: %v", err)
			}
			_, err = s.Get(context.Background(), &v1.GetRequest{Url: url, DestDir: dest, CredentialId: id})
			if code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "SHA256:") {
				t.Fatalf("llave desconocida: %v", err)
			}
			// Aceptar una huella que no es la del servidor tampoco sirve.
			if _, err = s.Get(context.Background(), &v1.GetRequest{Url: url, DestDir: dest, CredentialId: id, AcceptedHostKeyFingerprints: []string{"SHA256:otra"}}); err == nil {
				t.Fatal("aceptó una huella ajena")
			}
			// Con la huella de la llave que el servidor mostró, sí (y queda guardada).
			got := false
			for _, fp := range rd.Fingerprints {
				resp, err := s.Get(context.Background(), &v1.GetRequest{Url: url, DestDir: dest, CredentialId: id, AcceptedHostKeyFingerprints: []string{fp}, Sha256: sha(data)})
				if err == nil {
					got = resp.Result.Verified == "ok"
					break
				}
			}
			if !got {
				t.Fatal("no bajó con la huella correcta")
			}
			if b, _ := os.ReadFile(filepath.Join(dest, "i.bin")); !bytes.Equal(b, data) {
				t.Fatal("contenido distinto")
			}
			// Ya conocida: sin aceptar nada. Y subir.
			if _, err := s.Put(context.Background(), &v1.PutRequest{Url: proto + "://" + rd.Listening + "/up.cfg", FromDir: pub, Name: "i.bin", CredentialId: id}); err != nil {
				t.Fatal(err)
			}
			if b, _ := os.ReadFile(filepath.Join(recv, "up.cfg")); !bytes.Equal(b, data) {
				t.Fatal("el servidor no recibió el put")
			}
			// Credencial equivocada.
			bad, _ := v.Put(vault.Credential{Label: "mala", Username: rd.User, Password: secret.New([]byte("no"))})
			if _, err := s.Get(context.Background(), &v1.GetRequest{Url: url, DestDir: t.TempDir(), CredentialId: bad}); code(err) != codes.PermissionDenied {
				t.Fatalf("credencial mala: %v", err)
			}
			a := d.AuditText()
			for _, want := range []string{"hostkey.accepted", "transfer.get.failed", "transfer.get.start"} {
				if !strings.Contains(a, want) {
					t.Errorf("falta %q en la auditoría", want)
				}
			}
			if strings.Contains(a, rd.Password) {
				t.Fatal("contraseña en la auditoría")
			}
		})
	}
}

func TestFTPClientUsesVaultCredential(t *testing.T) {
	s, d := newTest(t)
	v := d.CreateVault()
	pub := t.TempDir()
	os.WriteFile(filepath.Join(pub, "a.bin"), []byte("ftp"), 0o600)
	run := startServer(t, s, &v1.StartServerRequest{Protocol: "ftp", Listen: "127.0.0.1:0", FromDir: pub})
	id, _ := v.Put(vault.Credential{Label: "ftp", Username: run.ready.User, Password: secret.New([]byte(run.ready.Password))})
	if _, err := s.Get(context.Background(), &v1.GetRequest{Url: "ftp://" + run.ready.Listening + "/a.bin", DestDir: t.TempDir(), CredentialId: id}); err != nil {
		t.Fatal(err)
	}
	// Anónimo no entra a este servidor.
	if _, err := s.Get(context.Background(), &v1.GetRequest{Url: "ftp://" + run.ready.Listening + "/a.bin", DestDir: t.TempDir()}); err == nil {
		t.Fatal("anónimo aceptado")
	}
}

func TestClientValidation(t *testing.T) {
	s, d := newTest(t)
	dest := t.TempDir()
	cases := map[string]*v1.GetRequest{
		"contraseña en la URL": {Url: "ftp://u:p@127.0.0.1/a", DestDir: dest},
		"esquema":              {Url: "gopher://127.0.0.1/a", DestDir: dest},
		"sin host":             {Url: "http:///a", DestDir: dest},
		"insecure en http":     {Url: "http://127.0.0.1/a", DestDir: dest, Insecure: true},
		"destino sensible":     {Url: "http://127.0.0.1/a", DestDir: "/etc"},
		"destino enlace":       {Url: "http://127.0.0.1/a", DestDir: linkTo(t, dest)},
		"tiempo":               {Url: "http://127.0.0.1/a", DestDir: dest, TimeoutSeconds: 99999},
		"tope negativo":        {Url: "http://127.0.0.1/a", DestDir: dest, MaxBytes: -1},
	}
	for name, r := range cases {
		if _, err := s.Get(context.Background(), r); code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Con credencial pero la bóveda cerrada.
	if _, err := s.Get(context.Background(), &v1.GetRequest{Url: "scp://127.0.0.1/a", DestDir: dest, CredentialId: "x"}); code(err) != codes.FailedPrecondition {
		t.Errorf("bóveda cerrada: %v", err)
	}
	// Sin autorización en el guard no se sale: un destino en TEST-NET no llega ni a conectar.
	if s.clients.Load() != 0 {
		t.Fatalf("clientes sin liberar: %d", s.clients.Load())
	}
	_ = d
	if _, err := s.Put(context.Background(), &v1.PutRequest{Url: "http://127.0.0.1/a", FromDir: dest, Name: "x"}); code(err) != codes.InvalidArgument {
		t.Errorf("put sin archivo: %v", err)
	}
}

func TestGetDefaultsToReceiveFolderAndSha512(t *testing.T) {
	s, d := newTest(t)
	pub := t.TempDir()
	data := []byte("imagen")
	os.WriteFile(filepath.Join(pub, "i.bin"), data, 0o600)
	run := startServer(t, s, &v1.StartServerRequest{Protocol: "http", Listen: "127.0.0.1:0", FromDir: pub})
	url := "http://" + run.ready.Listening + "/i.bin"
	// SHA-512 equivocado: se descarta lo bajado.
	dest := t.TempDir()
	if _, err := s.Get(context.Background(), &v1.GetRequest{Url: url, DestDir: dest, Sha512: strings.Repeat("0", 128)}); err == nil {
		t.Fatal("SHA-512 distinto aceptado")
	}
	if ents, _ := os.ReadDir(dest); len(ents) != 0 {
		t.Fatalf("quedó %v", ents)
	}
	// Sin carpeta: outputs/recibidos/<sello>/.
	resp, err := s.Get(context.Background(), &v1.GetRequest{Url: url})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.Result.Path, filepath.Join(d.Out, "recibidos")) {
		t.Fatalf("path = %q", resp.Result.Path)
	}
	// Un destino que ya tiene el archivo no se pisa.
	if _, err := s.Get(context.Background(), &v1.GetRequest{Url: url, DestDir: filepath.Dir(resp.Result.Path)}); err == nil {
		t.Fatal("sobrescribió")
	}
}

func TestRedirectHintRPC(t *testing.T) {
	s, _ := newTest(t)
	r, err := s.RedirectHint(context.Background(), &v1.RedirectHintRequest{Protocol: "ftp", Port: 2121, Ip: "10.0.0.5"})
	if err != nil || r.StandardPort != 21 || !strings.Contains(r.Nftables, "ip daddr 10.0.0.5 tcp dport 21 redirect to :2121") || !strings.Contains(r.Setcap, "ADVERTENCIA") ||
		r.Remove != "sudo nft delete table ip macuahuitl_ftp_2121" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := s.RedirectHint(context.Background(), &v1.RedirectHintRequest{Protocol: "ftp", Port: 2121, Ip: "no-es-ip"}); err == nil {
		t.Error("IP inválida aceptada")
	}
	for _, bad := range []*v1.RedirectHintRequest{{Protocol: "http", Port: 8080}, {Protocol: "tftp", Port: 0}, {Protocol: "x", Port: 1}} {
		if _, err := s.RedirectHint(context.Background(), bad); err == nil {
			t.Errorf("%+v aceptado", bad)
		}
	}
}

var _ = io.EOF

// La bitácora no guarda la query string de la URL (suele llevar tokens): ni en el objetivo ni en los errores.
func TestAuditDropsURLQuery(t *testing.T) {
	s, d := newTest(t)
	dest := t.TempDir()
	if _, err := s.Get(context.Background(), &v1.GetRequest{Url: "http://127.0.0.1:1/x.bin?token=SECRETO123&sig=ABC", DestDir: dest}); err == nil {
		t.Fatal("el puerto 1 respondió")
	}
	a := d.AuditText()
	if !strings.Contains(a, "transfer.get.failed") {
		t.Fatalf("no se auditó el fallo:\n%s", a)
	}
	for _, leak := range []string{"SECRETO123", "sig=ABC", "token="} {
		if strings.Contains(a, leak) {
			t.Errorf("la bitácora guarda %q:\n%s", leak, a)
		}
	}
}
