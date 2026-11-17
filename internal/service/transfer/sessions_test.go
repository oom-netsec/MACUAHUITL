package transfer

import (
	"context"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/fileserve"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func listSessions(t *testing.T, s *svc, id string) *v1.ListTransferSessionsResponse {
	t.Helper()
	r, err := s.ListTransferSessions(context.Background(), &v1.ListTransferSessionsRequest{ServerId: id})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func serverID(t *testing.T, s *svc) string {
	t.Helper()
	l, _ := s.ListServers(context.Background(), &v1.ListServersRequest{})
	if len(l.Servers) != 1 {
		t.Fatalf("servidores = %d", len(l.Servers))
	}
	return l.Servers[0].ServerId
}

// Activa (con client, name y total) y después done; "" lista todo.
func TestListTransferSessionsActiveThenDone(t *testing.T) {
	s, d := newTest(t)
	pub := t.TempDir()
	big := filepath.Join(pub, "big.bin")
	f, _ := os.Create(big)
	f.Truncate(4 << 20)
	f.Close()
	run := startServer(t, s, &v1.StartServerRequest{Protocol: "tftp", Listen: "127.0.0.1:0", FromDir: pub})
	id := serverID(t, s)
	done := make(chan error, 1)
	go func() {
		_, err := s.Get(context.Background(), &v1.GetRequest{Url: "tftp://" + run.ready.Listening + "/big.bin", DestDir: t.TempDir()})
		done <- err
	}()
	var seen *v1.TransferSession
	for end := time.Now().Add(20 * time.Second); seen == nil && time.Now().Before(end); time.Sleep(time.Millisecond) {
		for _, x := range listSessions(t, s, id).Sessions {
			if x.State == "active" {
				seen = x
			}
		}
	}
	if seen == nil {
		t.Fatal("no se vio la sesión activa")
	}
	if !strings.HasPrefix(seen.Client, "127.0.0.1:") || seen.Name != "big.bin" || seen.Total != 4<<20 || seen.Direction != "out" ||
		seen.Protocol != "tftp" || seen.ServerId != id || seen.Ended != 0 || seen.Started == 0 {
		t.Fatalf("activa = %+v", seen)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	run.transfers(t, 1) // el cliente vuelve antes de que el servidor procese el último ACK: se espera su OnTransfer
	for _, id := range []string{id, ""} {
		g := listSessions(t, s, id).Sessions
		if len(g) != 1 || g[0].State != "done" || g[0].Bytes != 4<<20 || g[0].Ended == 0 || g[0].Id != seen.Id || g[0].BytesPerSec <= 0 {
			t.Fatalf("id=%q terminada = %+v", id, g)
		}
	}
	closeServer(run)
	// Cerrado hace menos de 10 min: sigue, y ya no sale en ListServers.
	if g := listSessions(t, s, id).Sessions; len(g) != 1 || g[0].State != "done" {
		t.Fatalf("tras cerrar: %+v", g)
	}
	// Pasados 10 minutos del cierre, el servidor sale del registro.
	d.SetClock(func() time.Time { return time.Now().Add(10*time.Minute + time.Second) })
	if _, err := s.ListTransferSessions(context.Background(), &v1.ListTransferSessionsRequest{ServerId: id}); code(err) != codes.NotFound {
		t.Fatalf("a los 10 min: %v", err)
	}
}

func TestListTransferSessionsUnknownIsNotFound(t *testing.T) {
	s, _ := newTest(t)
	_, err := s.ListTransferSessions(context.Background(), &v1.ListTransferSessionsRequest{ServerId: "nada"})
	if code(err) != codes.NotFound || !strings.Contains(err.Error(), "nada") {
		t.Fatalf("err = %v", err)
	}
	if r := listSessions(t, s, ""); len(r.Sessions) != 0 || len(r.Rejections) != 0 {
		t.Fatalf("vacío = %+v", r)
	}
}

// Detener el servidor a media descarga deja la sesión failed con su error_code.
func TestListTransferSessionsFailedHasErrorCode(t *testing.T) {
	s, _ := newTest(t)
	pub := t.TempDir()
	f, _ := os.Create(filepath.Join(pub, "big.bin"))
	f.Truncate(256 << 20)
	f.Close()
	run := startServer(t, s, &v1.StartServerRequest{Protocol: "tftp", Listen: "127.0.0.1:0", FromDir: pub})
	gctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Get(gctx, &v1.GetRequest{Url: "tftp://" + run.ready.Listening + "/big.bin", DestDir: t.TempDir()})
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		if g := listSessions(t, s, "").Sessions; len(g) == 1 && g[0].Bytes > 0 {
			break
		}
	}
	closeServer(run)
	cancel()
	g := listSessions(t, s, "").Sessions
	if len(g) != 1 || g[0].State != "failed" || g[0].ErrorCode != "fileserve.reason.stopped" || g[0].Error != "servidor detenido" || g[0].Ended == 0 {
		t.Fatalf("failed = %+v", g)
	}
}

// Un rechazo no es sesión: va a rejections, sube rejected y no se audita uno por uno.
func TestListTransferSessionsRejectionsNotSessions(t *testing.T) {
	s, d := newTest(t)
	pub := t.TempDir()
	os.WriteFile(filepath.Join(pub, "ok.cfg"), []byte("x"), 0o600)
	run := startServer(t, s, &v1.StartServerRequest{Protocol: "tftp", Listen: "127.0.0.1:0", FromDir: pub})
	id := serverID(t, s)
	for i := 0; i < 2; i++ {
		s.Get(context.Background(), &v1.GetRequest{Url: "tftp://" + run.ready.Listening + "/falta.cfg", DestDir: t.TempDir()})
	}
	s.Put(context.Background(), &v1.PutRequest{Url: "tftp://" + run.ready.Listening + "/s.cfg", FromDir: pub, Name: "ok.cfg"}) // sin --write
	run.transfers(t, 3)                                                                                                        // fail() responde antes de llamar a OnTransfer
	r := listSessions(t, s, id)
	if len(r.Sessions) != 0 {
		t.Fatalf("sesiones = %+v", r.Sessions)
	}
	by := map[string]*v1.TransferRejection{}
	for _, x := range r.Rejections {
		by[x.Cause] = x
	}
	nf, wd := by["not_found"], by["write_disabled"]
	if len(r.Rejections) != 2 || nf == nil || wd == nil || nf.Count != 2 || nf.Ip != "127.0.0.1" || nf.Name != "falta.cfg" || nf.Protocol != "tftp" ||
		nf.ServerId != id || nf.First == 0 || nf.Last < nf.First || nf.Reason == "" || nf.ReasonCode == "" || wd.Count != 1 || wd.Name != "s.cfg" {
		t.Fatalf("rechazos = %+v", r.Rejections)
	}
	l, _ := s.ListServers(context.Background(), &v1.ListServersRequest{})
	if l.Servers[0].Rejected != 3 {
		t.Fatalf("rejected = %d", l.Servers[0].Rejected)
	}
	closeServer(run)
	if strings.Contains(d.AuditText(), "transfer.serve.transfer") {
		t.Fatal("un rechazo se auditó como transferencia")
	}
}

func TestListTransferSessionsOriginDenied(t *testing.T) {
	s, _ := newTest(t)
	pub := t.TempDir()
	os.WriteFile(filepath.Join(pub, "ok.cfg"), []byte("x"), 0o600)
	run := startServer(t, s, &v1.StartServerRequest{Protocol: "tftp", Listen: "127.0.0.1:0", FromDir: pub, Allow: []string{"10.9.9.9"}})
	s.Get(context.Background(), &v1.GetRequest{Url: "tftp://" + run.ready.Listening + "/ok.cfg", DestDir: t.TempDir(), TimeoutSeconds: 2})
	run.transfers(t, 1)
	r := listSessions(t, s, "")
	if len(r.Sessions) != 0 || len(r.Rejections) != 1 || r.Rejections[0].Cause != "origin_denied" || r.Rejections[0].Ip != "127.0.0.1" {
		t.Fatalf("%+v", r)
	}
}

// El nombre publicado con U+202E sale saneado.
func TestListTransferSessionsNameSanitized(t *testing.T) {
	s, _ := newTest(t)
	pub := t.TempDir()
	name := "a\u202eb.cfg"
	if os.WriteFile(filepath.Join(pub, name), []byte("x"), 0o600) != nil {
		t.Skip("el sistema de archivos no acepta el nombre")
	}
	run := startServer(t, s, &v1.StartServerRequest{Protocol: "http", Listen: "127.0.0.1:0", FromDir: pub})
	_, gerr := s.Get(context.Background(), &v1.GetRequest{Url: "http://" + run.ready.Listening + "/a%E2%80%AEb.cfg", DestDir: t.TempDir(), Name: "local.cfg", TimeoutSeconds: 2})
	run.transfers(t, 1)
	for _, x := range listSessions(t, s, "").Sessions {
		if x.Name != "a?b.cfg" {
			t.Fatalf("name = %q", x.Name)
		}
		return
	}
	t.Fatal("no hubo sesión para el nombre con U+202E: ", gerr)
}

// Auditoría con session= y total=, igual que la lista.
func TestTransferAuditCarriesSession(t *testing.T) {
	s, d := newTest(t)
	pub := t.TempDir()
	os.WriteFile(filepath.Join(pub, "r1.cfg"), []byte("hostname R1\n"), 0o600)
	run := startServer(t, s, &v1.StartServerRequest{Protocol: "tftp", Listen: "127.0.0.1:0", FromDir: pub})
	s.Get(context.Background(), &v1.GetRequest{Url: "tftp://" + run.ready.Listening + "/r1.cfg", DestDir: t.TempDir()})
	run.transfers(t, 1)
	g := listSessions(t, s, "").Sessions
	closeServer(run)
	if len(g) != 1 || !strings.Contains(d.AuditText(), "session="+g[0].Id+" total=12") {
		t.Fatalf("auditoría sin session=%v:\n%s", g, d.AuditText())
	}
}

// -race: List en paralelo mientras corren transferencias.
func TestListTransferSessionsRace(t *testing.T) {
	s, _ := newTest(t)
	pub := t.TempDir()
	os.WriteFile(filepath.Join(pub, "r.bin"), make([]byte, 3<<20), 0o600)
	run := startServer(t, s, &v1.StartServerRequest{Protocol: "tftp", Listen: "127.0.0.1:0", FromDir: pub})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					s.ListTransferSessions(context.Background(), &v1.ListTransferSessionsRequest{})
					time.Sleep(200 * time.Microsecond) // sin esto, con un solo hilo los lectores le quitan el turno a la transferencia
				}
			}
		}()
	}
	for i := 0; i < 3; i++ {
		s.Get(context.Background(), &v1.GetRequest{Url: "tftp://" + run.ready.Listening + "/r.bin", DestDir: t.TempDir()})
	}
	run.transfers(t, 3)
	close(stop)
	wg.Wait()
	if g := listSessions(t, s, "").Sessions; len(g) != 3 {
		t.Fatalf("sesiones = %d", len(g))
	}
}

// closeServer detiene el servidor y espera a que cierre; deja done lleno para el Cleanup de startServer.
func closeServer(r *running) {
	r.stop()
	err := <-r.done
	r.done <- err
}

// Cierre de seguridad: una sesión que nadie cerró pasa a failed «stopped» y se audita con session=.
func TestCloseSessionsFailsAndAuditsStranded(t *testing.T) {
	s, d := newTest(t)
	srv := &server{id: "S9", reg: d.TransferSessions().Open("S9")}
	srv.reg.Start(&fileserve.Live{Proto: "tftp", Client: "10.0.0.5:7", File: "x.bin", Dir: "lectura"})
	k := newSink(func(*v1.StartServerResponse) error { return nil })
	s.closeSessions(k, srv, "es")
	n, _ := k.stop()
	g := listSessions(t, s, "S9").Sessions
	if n != 1 || len(g) != 1 || g[0].State != "failed" || g[0].ErrorCode != "fileserve.reason.stopped" {
		t.Fatalf("n=%d %+v", n, g)
	}
	if a := d.AuditText(); !strings.Contains(a, "session="+g[0].Id) || !strings.Contains(a, "result=error") || !strings.Contains(a, "server stopped") {
		t.Fatalf("auditoría:\n%s", a)
	}
}
