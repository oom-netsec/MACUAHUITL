package bridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeSec struct {
	v1.UnimplementedSecurityServiceServer
	got chan *v1.RadiusTestRequest
}

func (f fakeSec) RadiusTest(_ context.Context, r *v1.RadiusTestRequest) (*v1.RadiusTestResponse, error) {
	f.got <- r
	return &v1.RadiusTestResponse{Report: &v1.ToolReport{Text: "radius ok"}}, nil
}

func (fakeSec) PkiExport(_ context.Context, r *v1.PkiExportRequest) (*v1.PkiExportResponse, error) {
	return &v1.PkiExportResponse{Data: []byte{0, 1, 2, 0xff}}, nil
}

func (fakeSec) PkiCsr(_ context.Context, r *v1.PkiCsrRequest) (*v1.PkiCsrResponse, error) {
	return &v1.PkiCsrResponse{CsrPem: "CSR " + r.Subject.Cn, SealedKeyPem: "KEY", Report: &v1.ToolReport{Text: "t"}}, nil
}

func TestSecurityBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs := fakeSec{got: make(chan *v1.RadiusTestRequest, 1)}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterSecurityServiceServer(r, fs) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	txt, err := b.SecRadius(RadiusDTO{Host: "10.0.0.1", SecretCredID: "c1", Username: "alice", Password: "pw", Method: "chap", Accounting: true})
	if err != nil || txt != "radius ok" {
		t.Fatalf("%q %v", txt, err)
	}
	r := <-fs.got
	if r.SharedSecret.CredentialId != "c1" || string(r.Password.Value) != "pw" || r.Method != "chap" || !r.Accounting {
		t.Fatalf("request = %+v", r)
	}
	if _, err := b.SecRadius(RadiusDTO{Host: "h", AuthPort: 70000}); err == nil {
		t.Fatal("puerto inválido aceptado")
	}
	dst := filepath.Join(d, "x.p12")
	if _, err := b.SecPkiExport(ExportDTO{Format: "p12", Cert: "c", Path: dst}); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(dst); len(raw) != 4 || raw[3] != 0xff {
		t.Fatalf("%x", raw)
	}
	if _, err := b.SecPkiExport(ExportDTO{Format: "p12", Cert: "c", Path: dst}); err == nil {
		t.Fatal("sobrescribió el archivo")
	}
	if _, err := b.SecPkiExport(ExportDTO{Format: "p12", Path: "rel.p12"}); err == nil {
		t.Fatal("ruta relativa aceptada")
	}
	res, err := b.SecPkiCsr(CsrDTO{Cn: "ise01"})
	if err != nil || res.Pem != "CSR ise01" || res.Key != "KEY" {
		t.Fatalf("%+v %v", res, err)
	}
}
