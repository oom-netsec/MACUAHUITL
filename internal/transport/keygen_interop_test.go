package transport

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

// vault no importa x/crypto/ssh (noegress): aquí se comprueba que su formato lo entiende la librería real.
func TestLlaveGeneradaPorLaBovedaLaLeeSSH(t *testing.T) {
	vault.MinMemoryKiB = 8192
	v, err := vault.Create(filepath.Join(t.TempDir(), "v.mcv"), []byte("maestra"), vault.Params{MemoryKiB: 8192, Iterations: 1, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	id, pub, err := v.GenerateKey("pi", "pi")
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	defer c.SSHKey.Destroy()
	signer, err := ssh.ParsePrivateKey(c.SSHKey.Bytes())
	if err != nil {
		t.Fatalf("ssh no lee la privada: %v", err)
	}
	line := pub.AuthorizedKey()
	apub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || !strings.HasPrefix(comment, "macuahuitl@") {
		t.Fatalf("ssh no lee la línea: %v %q", err, comment)
	}
	if !bytes.Equal(apub.Marshal(), signer.PublicKey().Marshal()) {
		t.Fatal("la pública de la línea no es la de la privada")
	}
	sig, err := signer.Sign(nil, []byte("reto"))
	if err != nil {
		t.Fatal(err)
	}
	if err := apub.Verify([]byte("reto"), sig); err != nil {
		t.Fatalf("la pública no verifica la firma: %v", err)
	}
	if ssh.FingerprintSHA256(apub) != pub.Fingerprint() {
		t.Fatalf("huella: %s vs %s", ssh.FingerprintSHA256(apub), pub.Fingerprint())
	}
}

// Hasta que 44b/44c abran el camino de los hosts linux/windows, una credencial de tipo key no sirve para ningún equipo Cisco.
func TestOpenSSHRechazaCredencialKey(t *testing.T) {
	vault.MinMemoryKiB = 8192
	v, err := vault.Create(filepath.Join(t.TempDir(), "v.mcv"), []byte("maestra"), vault.Params{MemoryKiB: 8192, Iterations: 1, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	id, _, _ := v.GenerateKey("pi", "pi")
	c, _ := v.Get(id)
	g, host, port, hk := startSim(t)
	_, err = OpenSSH(context.Background(), g, "j", host, port, c, ssh.FixedHostKey(hk), SSHOptions{})
	if !errors.Is(err, ErrKeyCredential) {
		t.Fatalf("quería ErrKeyCredential, vino %v", err)
	}
	if !c.SSHKey.Empty() {
		t.Fatal("la privada no se destruyó al rechazar")
	}
}
