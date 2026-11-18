package bridge

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fake47 struct {
	v1.UnimplementedVaultServiceServer
	imp *v1.ImportKeyCredentialRequest
}

func (f *fake47) ImportKeyCredential(_ context.Context, r *v1.ImportKeyCredentialRequest) (*v1.ImportKeyCredentialResponse, error) {
	f.imp = r
	return &v1.ImportKeyCredentialResponse{Id: "i1", PublicKey: "ssh-rsa AAAA", Fingerprint: "SHA256:x", Algorithm: "ssh-rsa", Bits: 2048, Weak: true}, nil
}
func (f *fake47) ListCredentials(context.Context, *v1.ListCredentialsRequest) (*v1.ListCredentialsResponse, error) {
	return &v1.ListCredentialsResponse{Credentials: []*v1.CredentialInfo{{Id: "i1", Kind: "key", Origin: "imported"}}}, nil
}

func TestImportKeyCredential(t *testing.T) {
	f := &fake47{}
	b, _ := startServices(t, func(r ipc.Registrar) { v1.RegisterVaultServiceServer(r, f) })
	dir := t.TempDir()
	file := filepath.Join(dir, "id_rsa")
	if err := os.WriteFile(file, []byte("CONTENIDO"), 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := b.ImportKeyCredential(ImportKeyDTO{Label: "l", Username: "u", Path: file, Passphrase: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if string(f.imp.PrivateKey) != "CONTENIDO" || string(f.imp.Passphrase) != "p" || f.imp.Label != "l" || f.imp.Username != "u" {
		t.Fatalf("request: %v", f.imp)
	}
	if bytes.Contains([]byte(f.imp.String()), []byte(file)) {
		t.Fatal("la ruta llegó al núcleo")
	}
	if r != (ImportKeyResultDTO{ID: "i1", PublicKey: "ssh-rsa AAAA", Fingerprint: "SHA256:x", Algorithm: "ssh-rsa", Bits: 2048, Weak: true}) {
		t.Fatalf("resultado: %+v", r)
	}

	if _, err := b.ImportKeyCredential(ImportKeyDTO{Username: "u", PrivateKey: "pegada"}); err != nil || string(f.imp.PrivateKey) != "pegada" {
		t.Fatalf("pegada: %v %v", err, f.imp)
	}

	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, bytes.Repeat([]byte("a"), 64<<10+5000), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ImportKeyCredential(ImportKeyDTO{Username: "u", Path: big}); err != nil || len(f.imp.PrivateKey) != 64<<10+1 {
		t.Fatalf("grande: %v %d", err, len(f.imp.PrivateKey))
	}

	for _, d := range []ImportKeyDTO{{Username: "u"}, {Username: "u", Path: file, PrivateKey: "x"}} {
		_, err := b.ImportKeyCredential(d)
		var be *Error
		if !errors.As(err, &be) || be.Code != "InvalidArgument" || be.Reason != "bridge.err.import_source" {
			t.Fatalf("%+v: %v", d, err)
		}
	}
	// no regulares: un directorio y /dev/null
	for _, p := range []string{dir, os.DevNull} {
		var be *Error
		if _, err := b.ImportKeyCredential(ImportKeyDTO{Username: "u", Path: p}); !errors.As(err, &be) || be.Reason != "bridge.err.import_not_regular" {
			t.Fatalf("%s: %v", p, err)
		}
	}
	// la ruta no aparece en el error ni en su metadata
	miss := filepath.Join(dir, "secreto-nada")
	_, err = b.ImportKeyCredential(ImportKeyDTO{Username: "u", Path: miss})
	var be *Error
	if !errors.As(err, &be) || be.Reason != "bridge.err.import_read" || be.Metadata["kind"] != "not_found" {
		t.Fatalf("read: %v", err)
	}
	if j := jsonOf(t, be) + err.Error(); strings.Contains(j, "secreto-nada") || strings.Contains(j, dir) {
		t.Fatalf("la ruta se filtró: %s", j)
	}

	l, err := b.ListCredentials()
	if err != nil || l[0].Origin != "imported" {
		t.Fatalf("origin: %v %+v", err, l)
	}
}
