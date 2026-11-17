package vault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/secret"
)

func TestGenerateKeyFirmaContraLaGuardada(t *testing.T) {
	v, p := newVault(t)
	id, pub, err := v.GenerateKey("pi", "pi")
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	defer c.SSHKey.Destroy()
	if c.Username != "pi" || !c.Password.Empty() || !c.Enable.Empty() {
		t.Fatalf("credencial: %+v", c)
	}
	// Firma con la privada guardada (formato openssh-key-v1: la semilla va tras el tipo y la pública) y verifica con la pública.
	_, priv := parseOpenSSH(t, c.SSHKey.Bytes())
	sig := ed25519.Sign(priv, []byte("reto"))
	if !ed25519.Verify(ed25519.PublicKey(pub[len(pub)-32:]), []byte("reto"), sig) {
		t.Fatal("la pública no verifica")
	}
	if !strings.HasPrefix(pub.AuthorizedKey(), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5") {
		t.Fatalf("tipo: %s", pub.AuthorizedKey())
	}
	// PublicKey la deriva de la guardada.
	got, err := v.PublicKey(id)
	if err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("PublicKey: %v", err)
	}
	// Tipo calculado.
	infos, _ := v.List()
	if len(infos) != 1 || !infos[0].HasSSHKey || infos[0].HasPassword || !infos[0].IsKey() {
		t.Fatalf("info: %+v", infos)
	}
	// El archivo va cifrado: ni PEM ni semilla en claro.
	raw, _ := os.ReadFile(p)
	if bytes.Contains(raw, []byte("OPENSSH PRIVATE KEY")) || bytes.Contains(raw, c.SSHKey.Bytes()) {
		t.Fatal("la privada aparece en claro en el archivo de la bóveda")
	}
	if bytes.Contains(raw, priv.Seed()) {
		t.Fatal("la semilla aparece en claro en el archivo de la bóveda")
	}
}

func TestAuthorizedKeyComentario(t *testing.T) {
	v, _ := newVault(t)
	_, pub, _ := v.GenerateKey("pi", "pi")
	l := pub.AuthorizedKey()
	if !strings.HasPrefix(l, "ssh-ed25519 AAAA") || strings.ContainsAny(l, "\n") || !strings.Contains(l, " macuahuitl@") {
		t.Fatalf("línea: %q", l)
	}
	for in, want := range map[string]string{"mi equipo!": "miequipo", "a.b-c_d": "a.b-c_d", "": "localhost", "ñ ü": "localhost"} {
		if got := cleanHost(in); got != want {
			t.Errorf("cleanHost(%q) = %q, quería %q", in, got, want)
		}
	}
}

func TestPublicKeySinLlave(t *testing.T) {
	v, _ := newVault(t)
	id, _ := v.Put(cred("x", "pw", "en"))
	if _, err := v.PublicKey(id); !errors.Is(err, ErrNoKey) {
		t.Fatalf("quería ErrNoKey, vino %v", err)
	}
	if _, err := v.PublicKey("00"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("quería ErrNotFound, vino %v", err)
	}
}

func TestRegenerateKeyConservaIDYDestruyeLaVieja(t *testing.T) {
	v, p := newVault(t)
	id, pub1, _ := v.GenerateKey("pi", "pi")
	var olds []*secret.Secret
	afterRekey = func(old *secret.Secret) { olds = append(olds, old) }
	t.Cleanup(func() { afterRekey = nil })
	old, pub2, _, err := v.RegenerateKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(old, pub1) || bytes.Equal(pub1, pub2) {
		t.Fatal("la pública vieja debe ser la de antes y la nueva distinta")
	}
	if len(olds) != 1 || !olds[0].Empty() {
		t.Fatal("la privada vieja no se destruyó")
	}
	infos, _ := reopen(t, p).List()
	if len(infos) != 1 || infos[0].ID != id || infos[0].Label != "pi" || infos[0].Username != "pi" {
		t.Fatalf("info tras reabrir: %+v", infos)
	}
	got, _ := reopen(t, p).PublicKey(id)
	if !bytes.Equal(got, pub2) {
		t.Fatal("persistió otra llave")
	}
}

func TestRegenerateKeyRechazaLoQueNoEsKey(t *testing.T) {
	v, _ := newVault(t)
	id, _ := v.Put(cred("x", "pw", "en"))
	if _, _, _, err := v.RegenerateKey(id); !errors.Is(err, ErrNotKey) {
		t.Fatalf("password: %v", err)
	}
	// Contraseña y llave: tampoco es "key".
	kid, _, _ := v.GenerateKey("k", "u")
	c, _ := v.Get(kid)
	c.Password = secret.New([]byte("pw"))
	v.Put(c)
	for _, i := range func() []Info { l, _ := v.List(); return l }() {
		if i.ID == kid && i.IsKey() {
			t.Fatal("llave con contraseña no es de tipo key")
		}
	}
	if _, _, _, err := v.RegenerateKey(kid); !errors.Is(err, ErrNotKey) {
		t.Fatalf("password+llave: %v", err)
	}
}

func TestRespaldoLlevaLasLlaves(t *testing.T) {
	v, _ := newVault(t)
	v.Put(cred("pw", "secreto", "en"))
	id, pub, _ := v.GenerateKey("pi", "pi")
	dst := rutaRespaldo(t)
	n, keys, _, err := WriteBackupKeys(v, dst, pw(frase), false)
	if err != nil || n != 2 || keys != 1 {
		t.Fatalf("n=%d keys=%d err=%v", n, keys, err)
	}
	b, err := OpenBackup(dst, pw(frase))
	if err != nil {
		t.Fatal(err)
	}
	defer b.LockAll()
	infos, _ := b.List()
	var bid string
	for _, i := range infos {
		if i.Label == "pi" {
			bid = i.ID
			if !i.IsKey() {
				t.Fatal("la restaurada ya no es key")
			}
		}
	}
	got, err := b.PublicKey(bid)
	if err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("la pública del respaldo no es la misma: %v", err)
	}
	_ = id
}

// parseOpenSSH lee una privada openssh-key-v1 ed25519 sin frase (solo para la prueba).
func parseOpenSSH(t *testing.T, pemBytes []byte) (pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	blk, _ := pem.Decode(pemBytes)
	b := blk.Bytes[len("openssh-key-v1\x00"):]
	str := func() []byte {
		n := binary.BigEndian.Uint32(b)
		s := b[4 : 4+n]
		b = b[4+n:]
		return s
	}
	str()
	str()
	str()
	b = b[4:]
	str()
	b = str()[8:]
	str()
	pub = str()
	priv = str()
	return pub, priv
}

// Desde la fase 47 PublicKey también deriva la pública de una ecdsa guardada; lo ilegible sigue siendo ErrKeyUnsupported.
func TestPublicKeyDeEcdsaYDeBasura(t *testing.T) {
	v, _ := newVault(t)
	id, _ := v.Put(Credential{Label: "x", Username: "u", SSHKey: secret.New(llaveECDSAPEM(t))})
	p, err := v.PublicKey(id)
	if err != nil || !strings.HasPrefix(p.AuthorizedKey(), "ecdsa-sha2-nistp256 ") {
		t.Fatalf("ecdsa: %v %q", err, p.AuthorizedKey())
	}
	cs := []Credential{{Label: "basura", Username: "u", SSHKey: secret.New([]byte("no es una llave"))}}
	ids, err := v.putBatch(cs, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.PublicKey(ids[0]); !errors.Is(err, ErrKeyUnsupported) {
		t.Fatalf("quería ErrKeyUnsupported, vino %v", err)
	}
}

func TestRegenerateKeyReemplazaLlaveAnteriorALaFase44(t *testing.T) {
	v, p := newVault(t)
	cs := []Credential{{Label: "vieja", Username: "u", SSHKey: secret.New([]byte("no es una llave"))}}
	ids, err := v.putBatch(cs, false, false)
	if err != nil {
		t.Fatal(err)
	}
	id := ids[0]
	old, pub, _, err := v.RegenerateKey(id)
	if err != nil || old != nil || len(pub) == 0 {
		t.Fatalf("RegenerateKey: old=%v err=%v", old, err)
	}
	got, err := reopen(t, p).PublicKey(id)
	if err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("no quedó la nueva con el mismo id: %v", err)
	}
	if infos, _ := v.List(); len(infos) != 1 || infos[0].Label != "vieja" || !infos[0].IsKey() || infos[0].Origin != OriginGenerated {
		t.Fatalf("info: %+v", infos)
	}
}

func TestPublicKeyBovedaArmadaYCerrada(t *testing.T) {
	v, clk, _, _ := armedVault(t)
	id, _, _ := v.GenerateKey("pi", "pi")
	if err := v.Arm("j", clk.t.Add(time.Hour), []string{id}); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	if _, err := v.PublicKey(id); !errors.Is(err, ErrLocked) {
		t.Fatalf("PublicKey con la bóveda cerrada: %v", err)
	}
}

// Una .mcvault armada a mano no puede mostrar una pública que no es la que firma.
func TestPublicKeyPublicasQueNoCoinciden(t *testing.T) {
	v, _ := newVault(t)
	_, pub, _ := v.GenerateKey("pi", "pi")
	raw := []byte(pub)[len(pub)-32:]
	c, _ := v.Get(mustID(t, v))
	good := append([]byte(nil), c.SSHKey.Bytes()...)
	c.SSHKey.Destroy()
	if _, _, err := pubOf(good); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 3; n++ { // 0: cabecera, 1: pública de la sección privada, 2: segunda mitad de la privada
		der, err := unarmor(good)
		if err != nil {
			t.Fatal(err)
		}
		at, from := -1, 0
		for i := 0; i <= n; i++ {
			at = bytes.Index(der[from:], raw) + from
			from = at + 1
		}
		der[at+31] ^= 1
		if _, _, err := pubOf(armor(der)); !errors.Is(err, ErrKeyUnsupported) {
			t.Errorf("copia %d alterada: %v", n, err)
		}
	}
}

func mustID(t *testing.T, v *Vault) string {
	t.Helper()
	infos, err := v.List()
	if err != nil || len(infos) != 1 {
		t.Fatal(err)
	}
	return infos[0].ID
}

func TestPutUnlessKeyNoReemplazaUnaKey(t *testing.T) {
	v, _ := newVault(t)
	kid, _, _ := v.GenerateKey("pi", "pi")
	if _, err := v.PutUnlessKey(Credential{ID: kid, Label: "pi", Username: "u", Password: secret.New([]byte("x"))}); !errors.Is(err, ErrKeyCredential) {
		t.Fatalf("reemplazo: %v", err)
	}
	if _, err := v.PublicKey(kid); err != nil {
		t.Fatalf("la key cambió: %v", err)
	}
	pid, _ := v.Put(cred("x", "pw", "en"))
	if _, err := v.PutUnlessKey(Credential{ID: pid, Label: "x", Username: "u", Password: secret.New([]byte("y"))}); err != nil {
		t.Fatalf("password: %v", err)
	}
	if _, err := v.PutUnlessKey(cred("nueva", "p", "")); err != nil {
		t.Fatalf("nueva: %v", err)
	}
	v.Lock()
	if _, err := v.PutUnlessKey(Credential{ID: kid, Label: "pi"}); !errors.Is(err, ErrLocked) {
		t.Fatalf("cerrada: %v", err)
	}
}
