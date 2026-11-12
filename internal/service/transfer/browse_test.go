package transfer

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	xfer "github.com/oom-netsec/MACUAHUITL/internal/diag/transfer"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

// evStream recoge los eventos de un stream de servidor; onEvent puede cancelar a mitad del lote.
type evStream struct {
	ctx     context.Context
	mu      sync.Mutex
	events  []*v1.TransferEvent
	onEvent func(*v1.TransferEvent)
}

func (f *evStream) Context() context.Context     { return f.ctx }
func (f *evStream) SetHeader(metadata.MD) error  { return nil }
func (f *evStream) SendHeader(metadata.MD) error { return nil }
func (f *evStream) SetTrailer(metadata.MD)       {}
func (f *evStream) RecvMsg(any) error            { return nil }
func (f *evStream) SendMsg(m any) error {
	var ev *v1.TransferEvent
	switch x := m.(type) {
	case *v1.GetStreamResponse:
		ev = x.Event
	case *v1.PutStreamResponse:
		ev = x.Event
	case *v1.GetManyResponse:
		ev = x.Event
	}
	f.mu.Lock()
	f.events = append(f.events, ev)
	f.mu.Unlock()
	if f.onEvent != nil {
		f.onEvent(ev)
	}
	return nil
}

type getStream struct{ *evStream }

func (g getStream) Send(m *v1.GetStreamResponse) error { return g.SendMsg(m) }

type batchStream struct{ *evStream }

func (b batchStream) Send(m *v1.GetManyResponse) error { return b.SendMsg(m) }

type putStream struct{ *evStream }

func (b putStream) Send(m *v1.PutStreamResponse) error { return b.SendMsg(m) }

func (f *evStream) files() (ok, bad []*v1.FileResult) {
	for _, e := range f.events {
		if fr := e.GetFile(); fr != nil {
			if fr.Ok {
				ok = append(ok, fr)
			} else {
				bad = append(bad, fr)
			}
		}
	}
	return
}

func TestBrowseSFTPConBovedaYLlaveEstricta(t *testing.T) {
	s, d := newTest(t)
	v := d.CreateVault()
	pub := t.TempDir()
	os.WriteFile(filepath.Join(pub, "i.bin"), bytes.Repeat([]byte("x"), 1000), 0o600)
	os.WriteFile(filepath.Join(pub, "r1.cfg"), []byte("hostname r1"), 0o600)
	run := startServer(t, s, &v1.StartServerRequest{Protocol: "sftp", Listen: "127.0.0.1:0", FromDir: pub, Allow: []string{"127.0.0.1"}})
	rd := run.ready
	id, _ := v.Put(vault.Credential{Label: "srv", Username: rd.User, Password: secret.New([]byte(rd.Password))})
	req := &v1.BrowseRequest{Url: "sftp://" + rd.Listening + "/", CredentialId: id}
	if _, err := s.Browse(context.Background(), &v1.BrowseRequest{Url: req.Url}); code(err) != codes.InvalidArgument {
		t.Fatalf("sin credencial: %v", err)
	}
	if _, err := s.Browse(context.Background(), req); code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "SHA256:") {
		t.Fatalf("llave nueva: %v", err)
	}
	var r *v1.BrowseResponse
	var err error
	for _, fp := range rd.Fingerprints {
		req.AcceptedHostKeyFingerprints = []string{fp}
		if r, err = s.Browse(context.Background(), req); err == nil {
			break
		}
	}
	if err != nil || r.Method != "sftp" || len(r.Entries) != 2 || r.Entries[0].Name != "i.bin" || r.Entries[0].Size != 1000 || !r.Entries[0].Downloadable || r.Entries[0].ModifiedMs == 0 {
		t.Fatalf("r = %+v err = %v", r, err)
	}
	a := d.AuditText()
	for _, want := range []string{"transfer.browse.start", `"action":"transfer.browse"`, "entries=2", "guard=revoked", "transfer.browse.failed"} {
		if !strings.Contains(a, want) {
			t.Errorf("falta %q en la auditoría", want)
		}
	}
	if strings.Contains(a, rd.Password) || strings.Contains(a, "r1.cfg") {
		t.Fatalf("la bitácora no lleva contraseñas ni nombres de archivo:\n%s", a)
	}
}

func TestBrowseFTPYSinListado(t *testing.T) {
	s, d := newTest(t)
	v := d.CreateVault()
	pub := t.TempDir()
	os.WriteFile(filepath.Join(pub, "a.bin"), []byte("ftp"), 0o600)
	run := startServer(t, s, &v1.StartServerRequest{Protocol: "ftp", Listen: "127.0.0.1:0", FromDir: pub})
	id, _ := v.Put(vault.Credential{Label: "ftp", Username: run.ready.User, Password: secret.New([]byte(run.ready.Password))})
	r, err := s.Browse(context.Background(), &v1.BrowseRequest{Url: "ftp://" + run.ready.Listening + "/", CredentialId: id})
	if err != nil || r.Method != "list" || len(r.Entries) != 1 || r.Entries[0].Name != "a.bin" || r.Entries[0].Type != "file" {
		t.Fatalf("ftp: %+v %v", r, err)
	}
	// TFTP no lista: Unimplemented con el mensaje, sin pedirle nada al guard
	n := strings.Count(d.AuditText(), "transfer.browse.start")
	_, err = s.Browse(context.Background(), &v1.BrowseRequest{Url: "tftp://127.0.0.1:6969/"})
	if code(err) != codes.Unimplemented || !strings.Contains(err.Error(), "este servidor no permite listar") {
		t.Fatalf("tftp: %v", err)
	}
	if strings.Count(d.AuditText(), "transfer.browse.start") != n {
		t.Fatal("TFTP no debía tocar el guard")
	}
	// scp puro: el servidor de pruebas solo habla scp -f/-t → error tipado y auditado
	srun := startServer(t, s, &v1.StartServerRequest{Protocol: "scp", Listen: "127.0.0.1:0", FromDir: pub})
	sid, _ := v.Put(vault.Credential{Label: "scp", Username: srun.ready.User, Password: secret.New([]byte(srun.ready.Password))})
	var last error
	for _, fp := range srun.ready.Fingerprints {
		_, last = s.Browse(context.Background(), &v1.BrowseRequest{Url: "scp://" + srun.ready.Listening + "/", CredentialId: sid, AcceptedHostKeyFingerprints: []string{fp}})
		if code(last) == codes.Unimplemented {
			break
		}
	}
	if code(last) != codes.Unimplemented || !strings.Contains(last.Error(), "este servidor no permite listar") || !strings.Contains(d.AuditText(), "transfer.browse.nolisting") {
		t.Fatalf("scp: %v", last)
	}
}

func TestBrowseValidacion(t *testing.T) {
	s, _ := newTest(t)
	for name, r := range map[string]*v1.BrowseRequest{
		"entradas negativas": {Url: "ftp://127.0.0.1/", MaxEntries: -1},
		"demasiadas":         {Url: "ftp://127.0.0.1/", MaxEntries: 100000},
		"plazo largo":        {Url: "ftp://127.0.0.1/", TimeoutSeconds: 3600},
		"insecure en http":   {Url: "http://127.0.0.1/", Insecure: true},
		"url sin host":       {Url: "ftp:///x"},
		"contraseña en url":  {Url: "ftp://u:p@127.0.0.1/"},
	} {
		if _, err := s.Browse(context.Background(), r); code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestGetStreamInformaAvance(t *testing.T) {
	s, d := newTest(t)
	v := d.CreateVault()
	pub := t.TempDir()
	data := bytes.Repeat([]byte("0123456789"), 5000)
	os.WriteFile(filepath.Join(pub, "a.bin"), data, 0o600)
	run := startServer(t, s, &v1.StartServerRequest{Protocol: "ftp", Listen: "127.0.0.1:0", FromDir: pub})
	id, _ := v.Put(vault.Credential{Label: "ftp", Username: run.ready.User, Password: secret.New([]byte(run.ready.Password))})
	st := &evStream{ctx: context.Background()}
	err := s.GetStream(&v1.GetStreamRequest{Request: &v1.GetRequest{Url: "ftp://" + run.ready.Listening + "/a.bin", DestDir: t.TempDir(), CredentialId: id}}, getStream{st})
	if err != nil {
		t.Fatal(err)
	}
	ok, bad := st.files()
	if len(ok) != 1 || len(bad) != 0 || ok[0].Name != "a.bin" || ok[0].Result.Bytes != int64(len(data)) {
		t.Fatalf("eventos = %+v", st.events)
	}
	var lastProg *v1.TransferProgress
	for _, e := range st.events {
		if p := e.GetProgress(); p != nil {
			lastProg = p
		}
	}
	if lastProg == nil || lastProg.Bytes != int64(len(data)) || lastProg.Total != int64(len(data)) || lastProg.Count != 1 {
		t.Fatalf("avance final = %+v", lastProg)
	}
	// un error termina el stream con su código
	err = s.GetStream(&v1.GetStreamRequest{Request: &v1.GetRequest{Url: "ftp://" + run.ready.Listening + "/nada.bin", DestDir: t.TempDir(), CredentialId: id}}, getStream{&evStream{ctx: context.Background()}})
	if err == nil {
		t.Fatal("un archivo inexistente debe fallar")
	}
}

func TestPutStreamInformaAvance(t *testing.T) {
	s, d := newTest(t)
	v := d.CreateVault()
	pub, recv := t.TempDir(), t.TempDir()
	data := bytes.Repeat([]byte("0123456789"), 5000)
	os.WriteFile(filepath.Join(pub, "a.bin"), data, 0o600)
	run := startServer(t, s, &v1.StartServerRequest{Protocol: "ftp", Listen: "127.0.0.1:0", Write: true, RecvDir: recv})
	id, _ := v.Put(vault.Credential{Label: "ftp", Username: run.ready.User, Password: secret.New([]byte(run.ready.Password))})
	st := &evStream{ctx: context.Background()}
	err := s.PutStream(&v1.PutStreamRequest{Request: &v1.PutRequest{Url: "ftp://" + run.ready.Listening + "/sube.bin", FromDir: pub, Name: "a.bin", CredentialId: id}}, putStream{st})
	if err != nil {
		t.Fatal(err)
	}
	ok, _ := st.files()
	if len(ok) != 1 || ok[0].Result.Bytes != int64(len(data)) || st.events[len(st.events)-2].GetProgress().GetTotal() != int64(len(data)) {
		t.Fatalf("eventos = %+v", st.events)
	}
}

func TestGetManyConFallasYCancelacion(t *testing.T) {
	s, d := newTest(t)
	v := d.CreateVault()
	pub := t.TempDir()
	for _, n := range []string{"a.cfg", "b.cfg", "c.cfg"} {
		os.WriteFile(filepath.Join(pub, n), []byte("hostname "+n), 0o600)
	}
	run := startServer(t, s, &v1.StartServerRequest{Protocol: "ftp", Listen: "127.0.0.1:0", FromDir: pub})
	id, _ := v.Put(vault.Credential{Label: "ftp", Username: run.ready.User, Password: secret.New([]byte(run.ready.Password))})
	dest := t.TempDir()
	st := &evStream{ctx: context.Background()}
	err := s.GetMany(&v1.GetManyRequest{Url: "ftp://" + run.ready.Listening + "/", Names: []string{"a.cfg", "falta.cfg", "../etc/passwd", "b.cfg", "a.cfg"}, DestDir: dest, CredentialId: id}, batchStream{st})
	if err != nil {
		t.Fatal(err)
	}
	ok, bad := st.files()
	if len(ok) != 2 || len(bad) != 2 {
		t.Fatalf("ok=%d mal=%d: %+v", len(ok), len(bad), st.events)
	}
	if !strings.Contains(bad[1].Error, "sin ruta") {
		t.Fatalf("la ruta con .. debe rechazarse por nombre: %+v", bad)
	}
	done := st.events[len(st.events)-1].GetDone()
	if done == nil || done.Ok != 2 || done.Failed != 2 {
		t.Fatalf("resumen = %+v", st.events[len(st.events)-1])
	}
	for _, n := range []string{"a.cfg", "b.cfg"} {
		if b, _ := os.ReadFile(filepath.Join(dest, n)); string(b) != "hostname "+n {
			t.Errorf("%s = %q", n, b)
		}
	}
	// el progreso trae el índice y el total del lote
	for _, e := range st.events {
		if p := e.GetProgress(); p != nil && (p.Count != 4 || p.Name == "") {
			t.Fatalf("progreso = %+v", p)
		}
	}
	// cancelar tras el primer archivo: no baja el resto
	dest2 := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st2 := &evStream{ctx: ctx, onEvent: func(e *v1.TransferEvent) {
		if e.GetFile() != nil {
			cancel()
		}
	}}
	err = s.GetMany(&v1.GetManyRequest{Url: "ftp://" + run.ready.Listening + "/", Names: []string{"a.cfg", "b.cfg", "c.cfg"}, DestDir: dest2, CredentialId: id}, batchStream{st2})
	if code(err) != codes.Canceled {
		t.Fatalf("err = %v", err)
	}
	if ents, _ := os.ReadDir(dest2); len(ents) != 1 {
		t.Fatalf("tras cancelar quedaron %d archivos", len(ents))
	}
	if a := d.AuditText(); !strings.Contains(a, "transfer.getmany.canceled") || !strings.Contains(a, "transfer.getmany.start") {
		t.Fatalf("auditoría:\n%s", a)
	}
}

func TestGetManyValidacion(t *testing.T) {
	s, _ := newTest(t)
	st := batchStream{&evStream{ctx: context.Background()}}
	for name, r := range map[string]*v1.GetManyRequest{
		"sin nombres":   {Url: "ftp://127.0.0.1/"},
		"url inválida":  {Url: "ftp:///", Names: []string{"a"}},
		"tftp":          {Url: "tftp://127.0.0.1/", Names: []string{"a"}},
		"carpeta mala":  {Url: "ftp://127.0.0.1/", Names: []string{"a"}, DestDir: "relativa"},
		"demasiados":    {Url: "ftp://127.0.0.1/", Names: make([]string, 201)},
		"tope negativo": {Url: "ftp://127.0.0.1/", Names: []string{"a"}, DestDir: t.TempDir(), MaxBytes: -1},
	} {
		if err := s.GetMany(r, st); code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestBatchURL(t *testing.T) {
	for in, want := range map[string]string{
		"ftp://h:21":                      "ftp://h:21/a.cfg",
		"ftp://h/imagenes/":               "ftp://h/imagenes/a.cfg",
		"sftp://u@h/dir/sub?token=x#frag": "sftp://h/dir/sub/a.cfg",
		"https://h:8443/pub/?k=v":         "https://h:8443/pub/a.cfg",
		"ftp://h//abs/dir/":               "ftp://h//abs/dir/a.cfg", // «//» = ruta absoluta en FTP, SCP y SFTP
		"sftp://h//abs":                   "sftp://h//abs/a.cfg",
	} {
		u, _ := url.Parse(in)
		if got := batchURL(u, "a.cfg"); got != want {
			t.Errorf("%s → %s; quería %s", in, got, want)
		}
	}
}

func TestGetManyTopeDeAvisosEsDelLoteNoDeCadaArchivo(t *testing.T) {
	s, d := newTest(t)
	v := d.CreateVault()
	pub := t.TempDir()
	var names []string
	for i := 0; i < maxBatch; i++ {
		n := fmt.Sprintf("f%03d.cfg", i)
		names = append(names, n)
		os.WriteFile(filepath.Join(pub, n), []byte("hostname "+n), 0o600)
	}
	run := startServer(t, s, &v1.StartServerRequest{Protocol: "ftp", Listen: "127.0.0.1:0", FromDir: pub})
	id, _ := v.Put(vault.Credential{Label: "ftp", Username: run.ready.User, Password: secret.New([]byte(run.ready.Password))})
	st := &evStream{ctx: context.Background()}
	start := time.Now()
	if err := s.GetMany(&v1.GetManyRequest{Url: "ftp://" + run.ready.Listening + "/", Names: names, DestDir: t.TempDir(), CredentialId: id}, batchStream{st}); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	progress := 0
	for _, e := range st.events {
		if e.GetProgress() != nil {
			progress++
		}
	}
	if ok, _ := st.files(); len(ok) != maxBatch {
		t.Fatalf("bajaron %d de %d", len(ok), maxBatch)
	}
	// a lo más 10 por segundo en todo el lote (más el primero), con el fin de cada archivo en su propio evento
	if max := int(elapsed/xfer.ProgressEvery) + 2; progress > max {
		t.Fatalf("%d avisos de avance en %v (tope %d): el límite debe ser del lote, no de cada archivo", progress, elapsed, max)
	}
}
