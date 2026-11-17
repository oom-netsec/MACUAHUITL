package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/secret"
)

// Las llaves de prueba se arman con la stdlib (vault no puede importar x/crypto/ssh): Import las lee y las guarda en OpenSSH.
func pkcs8Ed25519(t *testing.T) []byte {
	t.Helper()
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	d, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: d})
}

func rsaLegacy(t *testing.T, bits int, pass []byte) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	d := x509.MarshalPKCS1PrivateKey(k)
	if pass == nil {
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: d})
	}
	//lint:ignore SA1019 se prueba el cifrado PEM legado que Import acepta
	b, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", d, pass, x509.PEMCipherAES128)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(b)
}

func TestImportKeyOrigenYBorrado(t *testing.T) {
	v, p := newVault(t)
	in := pkcs8Ed25519(t)
	id, info, err := v.ImportKey("pi", "pi", in, []byte("sobra"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(in, make([]byte, len(in))) {
		t.Fatal("no se borró la llave de entrada")
	}
	infos, _ := v.List()
	if len(infos) != 1 || infos[0].Origin != OriginImported || !infos[0].IsKey() {
		t.Fatalf("List: %+v", infos)
	}
	// La pública sale con el comentario macuahuitl@host, igual que en una generada, y con la huella de la importación.
	pub, err := reopen(t, p).PublicKey(id)
	if err != nil || pub.Fingerprint() != info.Fingerprint || !strings.Contains(pub.AuthorizedKey(), " macuahuitl@") || !strings.HasPrefix(pub.AuthorizedKey(), "ssh-ed25519 ") {
		t.Fatalf("PublicKey: %v %q", err, pub.AuthorizedKey())
	}
	gid, _, _ := v.GenerateKey("gen", "u")
	eid, _ := v.Put(Credential{Label: "ec", Username: "u", SSHKey: secret.New(llaveECDSAPEM(t))})
	got := map[string]string{}
	infos, _ = v.List()
	for _, i := range infos {
		got[i.ID] = i.Origin
	}
	if got[gid] != OriginGenerated || got[id] != OriginImported || got[eid] != OriginImported {
		t.Fatalf("origen: %v", got)
	}
	if pw, _ := v.Put(Credential{Label: "pw", Username: "u", Password: secret.New([]byte("x"))}); pw != "" {
		if infos, _ := v.List(); len(infos) != 4 {
			t.Fatal(infos)
		}
		for _, i := range infos {
			if i.ID == pw && i.Origin != "" {
				t.Fatalf("origen de una de contraseña: %q", i.Origin)
			}
		}
	}
}

func TestImportKeyRSAyLegadoCifrado(t *testing.T) {
	v, _ := newVault(t)
	id, info, err := v.ImportKey("rsa", "u", rsaLegacy(t, 2048, []byte("la frase")), []byte("la frase"))
	if err != nil || !info.Weak || info.Bits != 2048 || info.Algorithm != "ssh-rsa" {
		t.Fatalf("%+v %v", info, err)
	}
	if p, err := v.PublicKey(id); err != nil || !strings.HasPrefix(p.AuthorizedKey(), "ssh-rsa ") {
		t.Fatalf("PublicKey: %v", err)
	}
}

func TestImportKeyErroresYTope(t *testing.T) {
	v, _ := newVault(t)
	enc := rsaLegacy(t, 1024, []byte("buena"))
	for _, c := range []struct {
		n    string
		pem  []byte
		pass []byte
		want error
	}{
		{"sin frase", enc, nil, ErrKeyPassphraseRequired},
		{"frase mala", enc, []byte("mala"), ErrKeyPassphraseWrong},
		{"basura", []byte("basura"), nil, ErrKeyImportInvalid},
		{"tope", bytes.Repeat([]byte("a"), MaxFieldBytes+1), nil, ErrFieldTooLong},
	} {
		_, _, err := v.ImportKey("x", "u", bytes.Clone(c.pem), c.pass)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v", c.n, err)
		}
		if err != nil && (strings.Contains(err.Error(), "buena") || strings.Contains(err.Error(), "mala")) {
			t.Errorf("%s: el error cita la frase", c.n)
		}
	}
	if infos, _ := v.List(); len(infos) != 0 {
		t.Fatalf("algo se guardó: %+v", infos)
	}
}

func TestOrigenSobreviveAlRespaldo(t *testing.T) {
	v, _ := newVault(t)
	v.ImportKey("imp", "u", pkcs8Ed25519(t), nil)
	v.GenerateKey("gen", "u")
	path := rutaRespaldo(t)
	if _, err := WriteBackup(v, path, pw(frase), false); err != nil {
		t.Fatal(err)
	}
	b, err := OpenBackup(path, pw(frase))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	infos, _ := b.List()
	for _, i := range infos {
		got[i.Label] = i.Origin
	}
	if got["imp"] != OriginImported || got["gen"] != OriginGenerated {
		t.Fatalf("origen tras el respaldo: %v", got)
	}
}

func TestRekeyDeImportadaDaGenerated(t *testing.T) {
	v, _ := newVault(t)
	id, info, _ := v.ImportKey("imp", "u", pkcs8Ed25519(t), nil)
	old, _, prev, err := v.RegenerateKey(id)
	if err != nil || prev != OriginImported || old.Fingerprint() != info.Fingerprint {
		t.Fatalf("%v prev=%s", err, prev)
	}
	if infos, _ := v.List(); infos[0].Origin != OriginGenerated {
		t.Fatalf("origen %s", infos[0].Origin)
	}
	if _, _, prev, _ := v.RegenerateKey(id); prev != OriginGenerated {
		t.Fatalf("prev %s", prev)
	}
}

// La frontera estricta usa la política de sshkey.Check: lo que entra por Put o por un .mcvault también la cumple.
func TestFronteraRechazaRSAPequena(t *testing.T) {
	v, _ := newVault(t)
	t.Setenv("GODEBUG", "rsa1024min=0")
	if _, err := rsa.GenerateKey(rand.Reader, 512); err != nil {
		t.Skip(err)
	}
	_, err := v.Put(Credential{Label: "chica", Username: "u", SSHKey: secret.New(rsaLegacy(t, 512, nil))})
	if !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("RSA 512 guardada: %v", err)
	}
}

// Con la bóveda cerrada, ImportKey falla antes de analizar: no se pide la frase ni se toca la llave.
func TestImportKeyBovedaCerrada(t *testing.T) {
	v, _ := newVault(t)
	v.Lock()
	_, _, err := v.ImportKey("x", "u", rsaLegacy(t, 1024, []byte("f")), nil) // sin frase: de abrirse, daría ErrKeyPassphraseRequired
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("esperaba ErrLocked: %v", err)
	}
}
