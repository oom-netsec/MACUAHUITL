package sshkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestParse(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	plain, _ := ssh.MarshalPrivateKey(priv, "")
	pass, _ := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("frase"))
	if err := Parse(pem.EncodeToMemory(plain)); err != nil {
		t.Fatalf("sin frase: %v", err)
	}
	if err := Parse(pem.EncodeToMemory(pass)); err == nil {
		t.Fatal("una llave con frase no debe pasar")
	}
	if Parse([]byte("basura")) == nil {
		t.Fatal("basura pasó")
	}
}

// noegress permite este paquete por coincidencia exacta: fuera de la stdlib sin red solo puede importar x/crypto/ssh.
func TestSoloImportaCryptoSSH(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "sshkey.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		std := !strings.Contains(strings.SplitN(p, "/", 2)[0], ".")
		if p == "golang.org/x/crypto/ssh" || (std && p != "net" && !strings.HasPrefix(p, "net/")) {
			continue
		}
		t.Errorf("import no permitido: %s", p)
	}
}
