package bridge

import (
	"context"
	"os"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc/ipctest"
)

// Doble de la bóveda y del inventario de la fase 44: guarda lo último que recibió.
type fake44 struct {
	v1.UnimplementedVaultServiceServer
	v1.UnimplementedInventoryServiceServer
	v1.UnimplementedTerminalServiceServer
	gen  *v1.GenerateKeyCredentialRequest
	pub  *v1.GetCredentialPublicKeyRequest
	put  *v1.PutCredentialRequest
	reg  *v1.RegenerateKeyCredentialRequest
	dev  *v1.PutDeviceRequest
	del  *v1.DeleteHostFolderRequest
	mov  *v1.MoveHostsRequest
	ren  *v1.RenameHostFolderRequest
	cre  *v1.CreateHostFolderRequest
	open chan *v1.TerminalOpen
}

func (f *fake44) GenerateKeyCredential(_ context.Context, r *v1.GenerateKeyCredentialRequest) (*v1.GenerateKeyCredentialResponse, error) {
	f.gen = r
	return &v1.GenerateKeyCredentialResponse{Id: "k1", PublicKey: "ssh-ed25519 AAAA"}, nil
}
func (f *fake44) GetCredentialPublicKey(_ context.Context, r *v1.GetCredentialPublicKeyRequest) (*v1.GetCredentialPublicKeyResponse, error) {
	f.pub = r
	return &v1.GetCredentialPublicKeyResponse{PublicKey: "ssh-ed25519 BBBB"}, nil
}
func (f *fake44) ListCredentials(context.Context, *v1.ListCredentialsRequest) (*v1.ListCredentialsResponse, error) {
	return &v1.ListCredentialsResponse{Credentials: []*v1.CredentialInfo{{Id: "k1", Label: "pi", HasSshKey: true, Kind: "key"}}}, nil
}
func (f *fake44) RegenerateKeyCredential(_ context.Context, r *v1.RegenerateKeyCredentialRequest) (*v1.RegenerateKeyCredentialResponse, error) {
	f.reg = r
	return &v1.RegenerateKeyCredentialResponse{PublicKey: "ssh-ed25519 NEW", PreviousOrigin: "imported"}, nil
}
func (f *fake44) PutCredential(_ context.Context, r *v1.PutCredentialRequest) (*v1.PutCredentialResponse, error) {
	f.put = r
	return &v1.PutCredentialResponse{Id: "p1"}, nil
}
func (f *fake44) ExportBackup(context.Context, *v1.ExportBackupRequest) (*v1.ExportBackupResponse, error) {
	return &v1.ExportBackupResponse{Count: 2, SshKeysIncluded: 1}, nil
}
func (f *fake44) PreviewBackupImport(context.Context, *v1.PreviewBackupImportRequest) (*v1.PreviewBackupImportResponse, error) {
	return &v1.PreviewBackupImportResponse{Items: []*v1.VaultBackupItem{{Id: "a", State: "nueva"}, {Id: "b", State: "nueva"}}}, nil
}
func (f *fake44) PutDevice(_ context.Context, r *v1.PutDeviceRequest) (*v1.PutDeviceResponse, error) {
	f.dev = r
	return &v1.PutDeviceResponse{Id: "h1"}, nil
}
func (f *fake44) ListDevices(context.Context, *v1.ListDevicesRequest) (*v1.ListDevicesResponse, error) {
	return &v1.ListDevicesResponse{Devices: []*v1.Device{{Id: "h1", Name: "pi", Platform: "linux", StartupCommand: "tmux attach"}}}, nil
}
func (f *fake44) PreviewImportHosts(context.Context, *v1.PreviewImportHostsRequest) (*v1.PreviewImportHostsResponse, error) {
	return &v1.PreviewImportHostsResponse{Items: []*v1.ImportHostItem{{Host: &v1.Device{Name: "x", StartupCommand: "ls"}, HasStartupCommand: true},
		{Host: &v1.Device{Name: "t", Protocol: "telnet", CredentialLabel: "admin"}, TelnetTyped: true}}}, nil
}
func (f *fake44) ApplyImportHosts(context.Context, *v1.ApplyImportHostsRequest) (*v1.ApplyImportHostsResponse, error) {
	return &v1.ApplyImportHostsResponse{Created: 1, FoldersCreated: 2}, nil
}
func (f *fake44) ListHostFolders(context.Context, *v1.ListHostFoldersRequest) (*v1.ListHostFoldersResponse, error) {
	return &v1.ListHostFoldersResponse{Folders: []*v1.HostFolder{{Name: "Lab", HostCount: 2}, {Name: "Vacia"}}}, nil
}
func (f *fake44) CreateHostFolder(_ context.Context, r *v1.CreateHostFolderRequest) (*v1.CreateHostFolderResponse, error) {
	f.cre = r
	return &v1.CreateHostFolderResponse{Folder: &v1.HostFolder{Name: r.Name}}, nil
}
func (f *fake44) RenameHostFolder(_ context.Context, r *v1.RenameHostFolderRequest) (*v1.RenameHostFolderResponse, error) {
	f.ren = r
	return &v1.RenameHostFolderResponse{}, nil
}
func (f *fake44) DeleteHostFolder(_ context.Context, r *v1.DeleteHostFolderRequest) (*v1.DeleteHostFolderResponse, error) {
	f.del = r
	return &v1.DeleteHostFolderResponse{HostsUnfiled: 4}, nil
}
func (f *fake44) MoveHosts(_ context.Context, r *v1.MoveHostsRequest) (*v1.MoveHostsResponse, error) {
	f.mov = r
	return &v1.MoveHostsResponse{Moved: 2, FolderCreated: true}, nil
}
func (f *fake44) OpenTerminal(st v1.TerminalService_OpenTerminalServer) error {
	m, _ := st.Recv()
	f.open <- m.GetOpen()
	return nil
}

func new44(t *testing.T) (*Bridge, *fake44) {
	d, _ := os.MkdirTemp("", "brg")
	t.Cleanup(func() { os.RemoveAll(d) })
	sock := ipctest.Addr(d)
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := &fake44{open: make(chan *v1.TerminalOpen, 2)}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) {
		v1.RegisterVaultServiceServer(r, f)
		v1.RegisterInventoryServiceServer(r, f)
		v1.RegisterTerminalServiceServer(r, f)
	})
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	return b, f
}

func TestVault44(t *testing.T) {
	b, f := new44(t)
	k, err := b.CreateKeyCredential("pi", "root")
	if err != nil || k != (KeyCredentialDTO{ID: "k1", PublicKey: "ssh-ed25519 AAAA"}) || f.gen.Label != "pi" || f.gen.Username != "root" {
		t.Fatalf("%+v %v", k, err)
	}
	if p, err := b.CredentialPublicKey("k1"); err != nil || p != "ssh-ed25519 BBBB" || f.pub.Id != "k1" {
		t.Fatalf("%q %v", p, err)
	}
	cs, _ := b.ListCredentials()
	if len(cs) != 1 || cs[0].Kind != "key" || !cs[0].HasSSHKey {
		t.Fatalf("%+v", cs)
	}
	// La llave privada nunca viaja: el núcleo la rechaza y el puente no tiene por dónde mandarla.
	if _, err := b.PutCredential("a", "u", "p", "e"); err != nil || len(f.put.SshPrivateKey) != 0 {
		t.Fatalf("put %+v %v", f.put, err)
	}
	e, _ := b.ExportVaultBackup("/x", "frase-larga-123", "m", true, true)
	if e.Count != 2 || e.SSHKeysIncluded != 1 {
		t.Fatalf("%+v", e)
	}
	if pk, err := b.RegenerateKeyCredential("k1", true); err != nil || pk.PublicKey != "ssh-ed25519 NEW" || pk.PreviousOrigin != "imported" || f.reg.Id != "k1" || !f.reg.Confirm {
		t.Fatalf("regen %+v %v %+v", pk, err, f.reg)
	}
	if _, err := b.RegenerateKeyCredential("k1", false); err != nil || f.reg.Confirm {
		t.Fatal("confirm debe viajar tal cual")
	}
	p, _ := b.PreviewVaultBackupImport("/x", "f")
	if len(p.Items) != 2 {
		t.Fatalf("%+v", p.Items)
	}
}

func TestHosts44(t *testing.T) {
	b, f := new44(t)
	if _, err := b.SaveHost(HostDTO{Name: "pi", Address: "10.0.0.5", Platform: "linux", StartupCommand: "tmux attach"}); err != nil || f.dev.Device.StartupCommand != "tmux attach" {
		t.Fatalf("%+v %v", f.dev, err)
	}
	hs, _ := b.ListHosts("", "", "")
	if hs[0].StartupCommand != "tmux attach" {
		t.Fatalf("%+v", hs)
	}
	pv, _ := b.PreviewHostsImport("/h.csv", "")
	if !pv.Items[0].HasStartupCommand || pv.Items[0].Host.StartupCommand != "ls" {
		t.Fatalf("%+v", pv.Items)
	}
	if pv.Items[0].TelnetTyped || !pv.Items[1].TelnetTyped || pv.Items[1].Host.Protocol != "telnet" {
		t.Fatalf("telnetTyped: %+v", pv.Items)
	}
	ap, _ := b.ApplyHostsImport("t", nil)
	if ap.FoldersCreated != 2 || ap.Created != 1 {
		t.Fatalf("%+v", ap)
	}
}

func TestFolders44(t *testing.T) {
	b, f := new44(t)
	l, err := b.ListFolders()
	if err != nil || len(l) != 2 || l[0] != (FolderDTO{Name: "Lab", Count: 2}) || l[1].Count != 0 {
		t.Fatalf("%+v %v", l, err)
	}
	if err := b.CreateFolder("N"); err != nil || f.cre.Name != "N" {
		t.Fatal(err)
	}
	if err := b.RenameFolder("N", "M"); err != nil || f.ren.Name != "N" || f.ren.NewName != "M" {
		t.Fatal(err)
	}
	if n, err := b.DeleteFolder("Lab", true); err != nil || n != 4 || !f.del.Confirm || f.del.Name != "Lab" {
		t.Fatalf("%d %v", n, err)
	}
	if _, err := b.DeleteFolder("Lab", false); err != nil || f.del.Confirm {
		t.Fatal("confirm debe viajar tal cual")
	}
	m, err := b.MoveHosts([]string{"a", "b"}, "")
	if err != nil || m != (MoveHostsResultDTO{Moved: 2, FolderCreated: true}) || len(f.mov.Ids) != 2 || f.mov.Folder != "" {
		t.Fatalf("%+v %v", m, err)
	}
}

func TestTerminal44(t *testing.T) {
	b, f := new44(t)
	// Con hostId no viajan dirección, puerto ni credencial, aunque el DTO los traiga.
	if _, err := b.TerminalOpen(TerminalDTO{Name: "pi", HostID: "h1", Address: "1.2.3.4", Port: 22, CredentialID: "c", ExpectedStartupCommand: "tmux attach", Accept: []string{"SHA256:x"}}); err != nil {
		t.Fatal(err)
	}
	o := <-f.open
	if o.HostId != "h1" || o.Address != "" || o.Port != 0 || o.CredentialId != "" || o.ExpectedStartupCommand != "tmux attach" || o.AcceptedHostKeyFingerprints[0] != "SHA256:x" {
		t.Fatalf("%+v", o)
	}
	if _, err := b.TerminalOpen(TerminalDTO{Address: "1.2.3.4", CredentialID: "c"}); err != nil {
		t.Fatal(err)
	}
	if o = <-f.open; o.HostId != "" || o.Address != "1.2.3.4" || o.CredentialId != "c" {
		t.Fatalf("%+v", o)
	}
}
