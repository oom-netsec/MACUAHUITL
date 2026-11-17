package bridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// Doble de la bóveda de la fase 44: guarda lo último que recibió.
type fake44a struct {
	v1.UnimplementedVaultServiceServer
	gen *v1.GenerateKeyCredentialRequest
	pub *v1.GetCredentialPublicKeyRequest
	put *v1.PutCredentialRequest
	reg *v1.RegenerateKeyCredentialRequest
}

func (f *fake44a) GenerateKeyCredential(_ context.Context, r *v1.GenerateKeyCredentialRequest) (*v1.GenerateKeyCredentialResponse, error) {
	f.gen = r
	return &v1.GenerateKeyCredentialResponse{Id: "k1", PublicKey: "ssh-ed25519 AAAA"}, nil
}

func (f *fake44a) GetCredentialPublicKey(_ context.Context, r *v1.GetCredentialPublicKeyRequest) (*v1.GetCredentialPublicKeyResponse, error) {
	f.pub = r
	return &v1.GetCredentialPublicKeyResponse{PublicKey: "ssh-ed25519 BBBB"}, nil
}

func (f *fake44a) ListCredentials(context.Context, *v1.ListCredentialsRequest) (*v1.ListCredentialsResponse, error) {
	return &v1.ListCredentialsResponse{Credentials: []*v1.CredentialInfo{{Id: "k1", Label: "pi", HasSshKey: true, Kind: "key"}}}, nil
}

func (f *fake44a) RegenerateKeyCredential(_ context.Context, r *v1.RegenerateKeyCredentialRequest) (*v1.RegenerateKeyCredentialResponse, error) {
	f.reg = r
	return &v1.RegenerateKeyCredentialResponse{PublicKey: "ssh-ed25519 NEW"}, nil
}

func (f *fake44a) PutCredential(_ context.Context, r *v1.PutCredentialRequest) (*v1.PutCredentialResponse, error) {
	f.put = r
	return &v1.PutCredentialResponse{Id: "p1"}, nil
}

func (f *fake44a) ExportBackup(context.Context, *v1.ExportBackupRequest) (*v1.ExportBackupResponse, error) {
	return &v1.ExportBackupResponse{Count: 2, SshKeysIncluded: 1}, nil
}

func (f *fake44a) PreviewBackupImport(context.Context, *v1.PreviewBackupImportRequest) (*v1.PreviewBackupImportResponse, error) {
	return &v1.PreviewBackupImportResponse{Items: []*v1.VaultBackupItem{{Id: "a", State: "nueva"}, {Id: "b", State: "nueva"}}}, nil
}

func new44a(t *testing.T) (*Bridge, *fake44a) {
	d, _ := os.MkdirTemp("", "brg")
	t.Cleanup(func() { os.RemoveAll(d) })
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := &fake44a{}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterVaultServiceServer(r, f) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	return b, f
}

func TestVault44(t *testing.T) {
	b, f := new44a(t)
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
	e, _ := b.ExportVaultBackup("/x", "frase-larga-123", true, true)
	if e.Count != 2 || e.SSHKeysIncluded != 1 {
		t.Fatalf("%+v", e)
	}
	if pk, err := b.RegenerateKeyCredential("k1", true); err != nil || pk != "ssh-ed25519 NEW" || f.reg.Id != "k1" || !f.reg.Confirm {
		t.Fatalf("regen %q %v %+v", pk, err, f.reg)
	}
	if _, err := b.RegenerateKeyCredential("k1", false); err != nil || f.reg.Confirm {
		t.Fatal("confirm debe viajar tal cual")
	}
	p, _ := b.PreviewVaultBackupImport("/x", "f")
	if len(p.Items) != 2 {
		t.Fatalf("%+v", p.Items)
	}
}
