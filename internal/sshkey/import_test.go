package sshkey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

var frase = []byte("frase de prueba")

func sstr(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

// caso es una llave en un formato, con o sin frase, y lo que Import debe decir de ella.
type caso struct {
	nombre, algo string
	bits         int
	weak         bool
	pem          []byte
	pass         []byte
	pub          crypto.PublicKey // la pública de la llave original del usuario
}

func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func ecKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func openssh(t *testing.T, k crypto.PrivateKey, comment string, pass []byte) []byte {
	t.Helper()
	var b *pem.Block
	var err error
	if pass == nil {
		b, err = ssh.MarshalPrivateKey(k, comment)
	} else {
		b, err = ssh.MarshalPrivateKeyWithPassphrase(k, comment, pass)
	}
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(b)
}

func der(t *testing.T, typ string, d []byte, err error, pass []byte) []byte {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	b := &pem.Block{Type: typ, Bytes: d}
	if pass != nil {
		//lint:ignore SA1019 se prueba el cifrado PEM legado que x/crypto/ssh todavía lee
		b, err = x509.EncryptPEMBlock(rand.Reader, typ, d, pass, x509.PEMCipherAES256)
		if err != nil {
			t.Fatal(err)
		}
	}
	return pem.EncodeToMemory(b)
}

func casos(t *testing.T) []caso {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	p256, p384, p521 := ecKey(t, elliptic.P256()), ecKey(t, elliptic.P384()), ecKey(t, elliptic.P521())
	r := rsaKey(t, 2048)
	r1024 := rsaKey(t, 1024)
	var cs []caso
	var cur crypto.PublicKey
	add := func(n, algo string, bits int, weak bool, p, pass []byte) {
		cs = append(cs, caso{n, algo, bits, weak, p, pass, cur})
	}
	for _, c := range []struct {
		n    string
		k    crypto.PrivateKey
		algo string
		bits int
	}{{"ed25519", ed, "ssh-ed25519", 256}, {"p256", p256, "ecdsa-sha2-nistp256", 256}, {"p384", p384, "ecdsa-sha2-nistp384", 384},
		{"p521", p521, "ecdsa-sha2-nistp521", 521}, {"rsa2048", r, "ssh-rsa", 2048}, {"rsa1024", r1024, "ssh-rsa", 1024}} {
		weak := c.algo == "ssh-rsa"
		cur = c.k.(crypto.Signer).Public()
		add(c.n+"/openssh", c.algo, c.bits, weak, openssh(t, c.k, "yo@pc", nil), nil)
		add(c.n+"/openssh+frase", c.algo, c.bits, weak, openssh(t, c.k, "yo@pc", frase), frase)
		d, err := x509.MarshalPKCS8PrivateKey(c.k)
		add(c.n+"/pkcs8", c.algo, c.bits, weak, der(t, "PRIVATE KEY", d, err, nil), nil)
	}
	cur = p256.Public()
	d, err := x509.MarshalECPrivateKey(p256)
	add("p256/sec1", "ecdsa-sha2-nistp256", 256, false, der(t, "EC PRIVATE KEY", d, err, nil), nil)
	add("p256/sec1+frase", "ecdsa-sha2-nistp256", 256, false, der(t, "EC PRIVATE KEY", d, err, frase), frase)
	cur = p521.Public()
	d, err = x509.MarshalECPrivateKey(p521)
	add("p521/sec1", "ecdsa-sha2-nistp521", 521, false, der(t, "EC PRIVATE KEY", d, err, nil), nil)
	cur = r.Public()
	add("rsa2048/pkcs1", "ssh-rsa", 2048, true, der(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(r), nil, nil), nil)
	add("rsa2048/pkcs1+frase", "ssh-rsa", 2048, true, der(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(r), nil, frase), frase)
	return cs
}

func TestImportFormatosYTipos(t *testing.T) {
	for _, c := range casos(t) {
		t.Run(c.nombre, func(t *testing.T) {
			out, info, err := Import(bytes.Clone(c.pem), c.pass)
			if err != nil {
				t.Fatal(err)
			}
			if info.Algorithm != c.algo || info.Bits != c.bits || info.Weak != c.weak || !strings.HasPrefix(info.Fingerprint, "SHA256:") {
				t.Fatalf("info: %+v", info)
			}
			// Lo guardado es OpenSSH sin frase y lo lee transport (ParsePrivateKey), con la misma pública.
			s, err := ssh.ParsePrivateKey(out)
			if err != nil {
				t.Fatal(err)
			}
			if ssh.FingerprintSHA256(s.PublicKey()) != info.Fingerprint {
				t.Fatal("la huella no coincide con lo guardado")
			}
			if c.pub != nil { // lo guardado es la llave del usuario, no otra válida
				op, err := ssh.NewPublicKey(c.pub)
				if err != nil || !bytes.Equal(op.Marshal(), s.PublicKey().Marshal()) {
					t.Fatal("lo guardado no es la llave original")
				}
			}
			if !strings.Contains(string(out), "BEGIN OPENSSH PRIVATE KEY") {
				t.Fatal("no es OpenSSH")
			}
			if comment(out) != ImportedTag {
				t.Fatalf("comentario del contenedor %q", comment(out))
			}
			i2, err := Inspect(out)
			if err != nil || i2.Fingerprint != info.Fingerprint {
				t.Fatalf("Inspect: %v", err)
			}
		})
	}
}

func comment(b []byte) string {
	blk, _ := pem.Decode(b)
	_, c, _, _ := container(blk)
	return c
}

func tipo(err error) (string, string, error) {
	var e *Error
	if errors.As(err, &e) {
		return e.Format, e.Type, e.Err
	}
	return "", "", err
}

func TestImportErrores(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	enc := openssh(t, ed, "", frase)
	r := rsaKey(t, 2048)
	d := x509.MarshalPKCS1PrivateKey(r)
	legacy := der(t, "RSA PRIVATE KEY", d, nil, frase)
	// Contenedores OpenSSH de cabecera sola: sk-* y ssh-dss (x/crypto no los parsea; se rechazan por el tipo).
	cab := func(typ string) []byte {
		b := []byte("openssh-key-v1\x00")
		b = sstr(sstr(sstr(b, []byte("none")), []byte("none")), nil)
		b = binary.BigEndian.AppendUint32(b, 1)
		b = sstr(b, sstr(nil, []byte(typ)))
		b = sstr(b, make([]byte, 16))
		return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: b})
	}
	k512 := func() []byte {
		t.Setenv("GODEBUG", "rsa1024min=0")
		k, err := rsa.GenerateKey(rand.Reader, 512)
		if err != nil {
			t.Skip("este Go no genera RSA de 512 bits:", err)
		}
		return der(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(k), nil, nil)
	}()
	// bcrypt con rondas de más: se rechaza por el encabezado, antes de pedir la frase.
	rondas := func(n uint32) []byte {
		b := []byte("openssh-key-v1\x00")
		b = sstr(sstr(b, []byte("aes256-ctr")), []byte("bcrypt"))
		b = sstr(b, binary.BigEndian.AppendUint32(sstr(nil, make([]byte, 16)), n))
		b = binary.BigEndian.AppendUint32(b, 1)
		b = sstr(b, sstr(nil, []byte("ssh-ed25519")))
		b = sstr(b, make([]byte, 16))
		return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: b})
	}
	// DEK-Info inválido: cifrado desconocido o IV de largo incorrecto es una llave ilegible, no una frase mala.
	dek := func(v string) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": v}, Bytes: d})
	}
	tests := []struct {
		nombre string
		pem    []byte
		pass   []byte
		want   error
		format string
		typ    string
	}{
		{"cifrada sin frase", enc, nil, ErrPassphraseRequired, "openssh", ""},
		{"frase incorrecta openssh", enc, []byte("otra"), ErrPassphraseWrong, "openssh", ""},
		{"cifrada legado sin frase", legacy, nil, ErrPassphraseRequired, "pem-legacy", ""},
		{"frase incorrecta legado", legacy, []byte("otra frase"), ErrPassphraseWrong, "pem-legacy", ""},
		{"dsa", pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte("x")}), nil, ErrUnsupported, "", "ssh-dss"},
		{"ssh-dss openssh", cab("ssh-dss"), nil, ErrUnsupported, "", "ssh-dss"},
		{"sk-ed25519", cab("sk-ssh-ed25519@openssh.com"), nil, ErrUnsupported, "", "sk-ed25519"},
		{"sk-ecdsa", cab("sk-ecdsa-sha2-nistp256@openssh.com"), nil, ErrUnsupported, "", "sk-ecdsa"},
		{"2049 rondas", rondas(2049), nil, ErrUnsupported, "openssh", "other"},
		{"dek cifrado desconocido", dek("ROT13-CBC,00112233445566778899AABBCCDDEEFF"), frase, ErrInvalid, "pem-legacy", ""},
		{"dek iv corto", dek("AES-256-CBC,0011"), frase, ErrInvalid, "pem-legacy", ""},
		{"dek iv de DES en AES", dek("AES-128-CBC,0011223344556677"), frase, ErrInvalid, "pem-legacy", ""},
		{"dek sin coma", dek("AES-256-CBC"), frase, ErrInvalid, "pem-legacy", ""},
		{"basura", []byte("esto no es una llave"), nil, ErrInvalid, "other", ""},
		{"pem roto", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("no es der")}), nil, ErrInvalid, "pkcs8", ""},
		{"pkcs8 cifrada", pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")}), frase, ErrUnsupported, "pkcs8-encrypted", "other"},
		{"curva P-224", func() []byte {
			d, err := x509.MarshalECPrivateKey(ecKey(t, elliptic.P224()))
			return der(t, "EC PRIVATE KEY", d, err, nil)
		}(), nil, ErrUnsupported, "", "ecdsa-p224"},
	}
	for _, c := range tests {
		t.Run(c.nombre, func(t *testing.T) {
			out, _, err := Import(bytes.Clone(c.pem), c.pass)
			if out != nil {
				t.Fatal("devolvió una llave")
			}
			f, ty, got := tipo(err)
			if got != c.want || (c.format != "" && f != c.format) || ty != c.typ {
				t.Fatalf("err=%v formato=%q tipo=%q", err, f, ty)
			}
			// El error no cita la llave ni la frase.
			for _, n := range []string{string(frase), "otra"} {
				if strings.Contains(err.Error(), n) {
					t.Fatalf("el error cita %q", n)
				}
			}
		})
	}
	t.Run("rsa 512", func(t *testing.T) {
		_, _, err := Import(k512, nil)
		if _, ty, got := tipo(err); got != ErrUnsupported || ty != "rsa-small" {
			t.Fatalf("RSA 512 se aceptó o falló distinto: %v", err)
		}
	})
	t.Run("rsa 1024 pasa con weak", func(t *testing.T) {
		_, info, err := Import(openssh(t, rsaKey(t, 1024), "", nil), nil)
		if err != nil || !info.Weak || info.Bits != 1024 {
			t.Fatalf("%+v %v", info, err)
		}
	})
}

// Llaves de ssh-keygen real: OpenSSH con frase (ed25519) y PKCS#1 con cifrado PEM legado AES-128-CBC (RSA).
func TestImportLlavesDeSSHKeygen(t *testing.T) {
	for _, c := range []struct{ f, algo string }{{"k_ed25519", "ssh-ed25519"}, {"k_rsa", "ssh-rsa"}} {
		raw, err := os.ReadFile("testdata/" + c.f)
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := os.ReadFile("testdata/" + c.f + ".pub")
		want, _, _, _, err := ssh.ParseAuthorizedKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := Import(bytes.Clone(raw), nil); !errors.Is(err, ErrPassphraseRequired) {
			t.Fatalf("%s sin frase: %v", c.f, err)
		}
		if _, _, err := Import(bytes.Clone(raw), []byte("mala")); !errors.Is(err, ErrPassphraseWrong) {
			t.Fatalf("%s frase mala: %v", c.f, err)
		}
		_, info, err := Import(bytes.Clone(raw), []byte("frase-de-prueba"))
		if err != nil || info.Algorithm != c.algo || info.Fingerprint != ssh.FingerprintSHA256(want) {
			t.Fatalf("%s: %+v %v", c.f, info, err)
		}
	}
}

// Una frase de más con una llave sin cifrar se ignora.
func TestImportIgnoraFraseDeMasSiNoEstaCifrada(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := Import(openssh(t, ed, "", nil), []byte("sobra")); err != nil {
		t.Fatal(err)
	}
}

// Check es la política única: Parse (la frontera de la bóveda) rechaza lo que Import rechaza.
func TestParseAplicaLaPoliticaDeCheck(t *testing.T) {
	t.Setenv("GODEBUG", "rsa1024min=0")
	k, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Skip(err)
	}
	if Parse(openssh(t, k, "", nil)) == nil {
		t.Fatal("RSA de 512 bits pasó la frontera")
	}
	if err := Parse(openssh(t, rsaKey(t, 1024), "", nil)); err != nil {
		t.Fatalf("RSA 1024: %v", err)
	}
}

func FuzzImport(f *testing.F) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	b, _ := ssh.MarshalPrivateKey(ed, "")
	enc, _ := ssh.MarshalPrivateKeyWithPassphrase(ed, "", frase)
	f.Add(pem.EncodeToMemory(b), []byte(nil))
	f.Add(pem.EncodeToMemory(enc), frase)
	f.Add([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"), []byte("x"))
	f.Fuzz(func(t *testing.T, p, pass []byte) {
		out, _, err := Import(bytes.Clone(p), bytes.Clone(pass))
		if err != nil {
			var e *Error
			if out != nil || !errors.As(err, &e) {
				t.Fatalf("error sin tipar o con llave: %v", err)
			}
			return
		}
		if Parse(out) != nil {
			t.Fatal("lo importado no pasa la frontera")
		}
	})
}

// Proc-Type ENCRYPTED sin un DEK-Info válido de RSA o EC es inválido antes de pedir la frase.
func TestProcTypeCifradoSinDEKValidoEsInvalido(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	d, err := x509.MarshalPKCS8PrivateKey(ed)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []map[string]string{{"Proc-Type": "4,ENCRYPTED"}, {"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00112233445566778899aabbccddeeff"}} {
		p := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: h, Bytes: d})
		if _, _, err := Import(p, nil); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%v: %v", h, err)
		}
	}
}
