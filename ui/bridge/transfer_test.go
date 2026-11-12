package bridge

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeTransfer struct {
	v1.UnimplementedTransferServiceServer
	stopped chan struct{} // StopServer lo cierra: el servidor manda su evento de cierre y termina
}

func (f fakeTransfer) StartServer(r *v1.StartServerRequest, st v1.TransferService_StartServerServer) error {
	st.Send(&v1.StartServerResponse{Event: &v1.StartServerResponse_Ready{Ready: &v1.ServerReady{ServerId: "s1", Protocol: r.Protocol, Listening: "127.0.0.1:6969",
		RecvDir: r.RecvDir, FromDir: r.FromDir, User: "mac", Password: "pw"}}})
	st.Send(&v1.StartServerResponse{Event: &v1.StartServerResponse_TransferJson{TransferJson: `{"File":"a.cfg"}`}})
	select {
	case <-f.stopped:
		st.Send(&v1.StartServerResponse{Event: &v1.StartServerResponse_Closed{Closed: &v1.ServerClosed{Cleanup: "sudo nft delete table ip macuahuitl_tftp_6969"}}})
	case <-st.Context().Done():
	}
	return nil
}
func (f fakeTransfer) StopServer(_ context.Context, r *v1.StopServerRequest) (*v1.StopServerResponse, error) {
	if r.ServerId == "s1" {
		close(f.stopped)
	}
	return &v1.StopServerResponse{Stopped: r.ServerId == "s1"}, nil
}
func (fakeTransfer) ListServers(context.Context, *v1.ListServersRequest) (*v1.ListServersResponse, error) {
	return &v1.ListServersResponse{Servers: []*v1.ServerInfo{{ServerId: "s1", Protocol: "tftp", Write: true, RecvDir: "/r", Transfers: 2}}}, nil
}
func (fakeTransfer) Get(_ context.Context, r *v1.GetRequest) (*v1.GetResponse, error) {
	// Report devuelve lo que llegó al núcleo: la prueba verifica que el puente no pierde campos.
	rep := fmt.Sprintf("%s|%v|%v|%d|%d|%v|%s", r.CredentialId, r.AcceptedHostKeyFingerprints, r.Insecure, r.MaxBytes, r.TimeoutSeconds, r.LegacySsh, r.Md5)
	return &v1.GetResponse{Result: &v1.TransferResult{Path: r.DestDir + "/" + r.Name, Sha256: "abc", Verified: "ok", Report: rep}}, nil
}
func (fakeTransfer) Put(_ context.Context, r *v1.PutRequest) (*v1.PutResponse, error) {
	rep := fmt.Sprintf("%s|%v|%d|%d|%v", r.CredentialId, r.AcceptedHostKeyFingerprints, r.MaxBytes, r.TimeoutSeconds, r.LegacySsh)
	return &v1.PutResponse{Result: &v1.TransferResult{Path: r.FromDir + "/" + r.Name, Bytes: 7, Report: rep}}, nil
}
func (fakeTransfer) RedirectHint(_ context.Context, r *v1.RedirectHintRequest) (*v1.RedirectHintResponse, error) {
	return &v1.RedirectHintResponse{StandardPort: 22, Nftables: "nft", Setcap: "setcap", Remove: "rm"}, nil
}

func TestTransferBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterTransferServiceServer(r, fakeTransfer{stopped: make(chan struct{})}) })
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	Start(ctx, b)
	id, err := b.TransferServe(TransferServeDTO{Protocol: "tftp", Listen: "127.0.0.1", Write: true, RecvDir: "/r", FromDir: "/f"})
	if err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, `transfer:ready {"files":null,"fingerprints":null,"fromDir":"/f","hint":"","listening":"127.0.0.1:6969","password":"pw","protocol":"tftp","recvDir":"/r","runId":"`+id+`","serverId":"s1","user":"mac"}`)
	rec.waitFor(t, `transfer:msg {"runId":"`+id+`","transfer":"{\"File\":\"a.cfg\"}"}`)
	if ok, err := b.TransferStop("s1"); err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	// Al cerrarse, el cierre trae el comando para quitar la regla de nftables.
	rec.waitFor(t, `transfer:done {"cleanup":"sudo nft delete table ip macuahuitl_tftp_6969","runId":"`+id+`"}`)
	if s, err := b.TransferServers(); err != nil || len(s) != 1 || s[0].Transfers != 2 || !s[0].Write {
		t.Fatalf("%+v %v", s, err)
	}
	g, err := b.TransferGet(TransferGetDTO{URL: "tftp://h/x", DestDir: "/d", Name: "x"})
	if err != nil || g.Path != "/d/x" || g.Verified != "ok" {
		t.Fatalf("%+v %v", g, err)
	}
	p, err := b.TransferPut(TransferPutDTO{URL: "tftp://h/x", FromDir: "/f", Name: "y"})
	if err != nil || p.Path != "/f/y" || p.Bytes != 7 {
		t.Fatalf("%+v %v", p, err)
	}
	// El formulario del cliente manda credencial, huellas, topes y SSH antiguo: todo debe llegar al núcleo.
	g, err = b.TransferGet(TransferGetDTO{URL: "https://h/x", CredentialID: "c1", HostKeys: []string{"SHA256:a"}, Insecure: true, MaxBytes: 2097152, Seconds: 180, LegacySSH: true, MD5: "m5"})
	if err != nil || g.Report != "c1|[SHA256:a]|true|2097152|180|true|m5" {
		t.Fatalf("%+v %v", g, err)
	}
	p, err = b.TransferPut(TransferPutDTO{URL: "sftp://h/x", FromDir: "/f", Name: "y", CredentialID: "c1", HostKeys: []string{"SHA256:a"}, MaxBytes: 1048576, Seconds: 60, LegacySSH: true})
	if err != nil || p.Report != "c1|[SHA256:a]|1048576|60|true" {
		t.Fatalf("%+v %v", p, err)
	}
	if h, err := b.TransferHint("scp", "10.0.0.5", 2222); err != nil || h.StandardPort != 22 || h.Remove != "rm" {
		t.Fatalf("%+v %v", h, err)
	}
}
