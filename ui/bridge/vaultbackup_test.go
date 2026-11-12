package bridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeVaultBackup struct {
	v1.UnimplementedVaultServiceServer
	exp *v1.ExportBackupRequest
	prv *v1.PreviewBackupImportRequest
	app *v1.ApplyBackupImportRequest
}

func (f *fakeVaultBackup) ExportBackup(_ context.Context, r *v1.ExportBackupRequest) (*v1.ExportBackupResponse, error) {
	f.exp = r
	return &v1.ExportBackupResponse{Count: 3, NoPermissions: r.Overwrite}, nil
}
func (f *fakeVaultBackup) PreviewBackupImport(_ context.Context, r *v1.PreviewBackupImportRequest) (*v1.PreviewBackupImportResponse, error) {
	f.prv = r
	return &v1.PreviewBackupImportResponse{Token: "tok", ExpiresMs: 9, Items: []*v1.VaultBackupItem{{Id: "a1", Label: "core", Username: "admin", State: "conflicto_etiqueta"}}}, nil
}
func (f *fakeVaultBackup) ApplyBackupImport(_ context.Context, r *v1.ApplyBackupImportRequest) (*v1.ApplyBackupImportResponse, error) {
	f.app = r
	return &v1.ApplyBackupImportResponse{Created: 1, Replaced: 2, Renamed: 3, Skipped: 4, Same: 5}, nil
}

func TestVaultBackupBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fakeVaultBackup{}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterVaultServiceServer(r, f) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)

	n, err := b.ExportVaultBackup("/tmp/r.mcvault", "la-frase-12345", true, true)
	if err != nil || n != (VaultBackupExportDTO{Count: 3, NoPermissions: true}) || f.exp.Path != "/tmp/r.mcvault" || string(f.exp.Passphrase) != "la-frase-12345" || !f.exp.Overwrite || !f.exp.Confirm {
		t.Fatalf("export: %+v %v %+v", n, err, f.exp)
	}
	if n, err = b.ExportVaultBackup("/tmp/r.mcvault", "x", false, false); err != nil || n != (VaultBackupExportDTO{Count: 3}) || f.exp.Confirm || f.exp.Overwrite {
		t.Fatalf("export sin banderas: %+v %v %+v", n, err, f.exp)
	}
	p, err := b.PreviewVaultBackupImport("/tmp/r.mcvault", "la-frase-12345")
	if err != nil || p.Token != "tok" || p.ExpiresMs != 9 || len(p.Items) != 1 || p.Items[0] != (VaultBackupItemDTO{ID: "a1", Label: "core", Username: "admin", State: "conflicto_etiqueta"}) || string(f.prv.Passphrase) != "la-frase-12345" {
		t.Fatalf("preview: %+v %v", p, err)
	}
	r, err := b.ApplyVaultBackupImport("tok", []VaultBackupDecisionDTO{{ID: "a1", Action: "renombrar"}})
	if err != nil || r != (VaultBackupResultDTO{Created: 1, Replaced: 2, Renamed: 3, Skipped: 4, Same: 5}) || f.app.Token != "tok" || len(f.app.Decisions) != 1 || f.app.Decisions[0].Id != "a1" || f.app.Decisions[0].Action != "renombrar" {
		t.Fatalf("apply: %+v %v %+v", r, err, f.app)
	}
	if _, err := b.ApplyVaultBackupImport("tok", nil); err != nil {
		t.Fatal(err)
	}
}

// Tras un export fallido, el diálogo de guardar deja un archivo vacío: solo ese se borra.
func TestRemoveEmptyFile(t *testing.T) {
	b := New(func() (*ipc.ClientConn, error) { return nil, os.ErrNotExist }, (&recorder{}).emit)
	d := t.TempDir()
	vacio := filepath.Join(d, "vacio.mcvault")
	os.WriteFile(vacio, nil, 0o600)
	if err := b.RemoveEmptyFile(vacio); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(vacio); err == nil {
		t.Fatal("no borró el archivo vacío")
	}
	lleno := filepath.Join(d, "lleno.mcvault")
	os.WriteFile(lleno, []byte("x"), 0o600)
	if err := b.RemoveEmptyFile(lleno); err == nil {
		t.Fatal("aceptó un archivo con contenido")
	}
	if _, err := os.Stat(lleno); err != nil {
		t.Fatal("borró un archivo con contenido")
	}
	enlace := filepath.Join(d, "enlace")
	objetivo := filepath.Join(d, "objetivo")
	os.WriteFile(objetivo, nil, 0o600)
	os.Symlink(objetivo, enlace)
	if err := b.RemoveEmptyFile(enlace); err == nil {
		t.Fatal("aceptó un enlace")
	}
	if _, err := os.Stat(objetivo); err != nil {
		t.Fatal("siguió el enlace")
	}
	carpeta := filepath.Join(d, "carpeta")
	os.Mkdir(carpeta, 0o700)
	if err := b.RemoveEmptyFile(carpeta); err == nil {
		t.Fatal("aceptó una carpeta")
	}
	if err := b.RemoveEmptyFile("relativa"); err == nil {
		t.Fatal("aceptó una ruta relativa")
	}
	if err := b.RemoveEmptyFile(filepath.Join(d, "no-existe")); err != nil {
		t.Fatalf("un archivo que ya no está no es error: %v", err)
	}
}
