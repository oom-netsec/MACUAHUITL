package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func codeOf(err error) codes.Code { return status.Code(err) }

func (h *harness) kinds(t *testing.T) map[string]string {
	t.Helper()
	r, err := h.vault.ListCredentials(ctx(t), &v1.ListCredentialsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, c := range r.Credentials {
		m[c.Label] = c.Kind
	}
	return m
}

func (h *harness) keygen(t *testing.T, label string) *v1.GenerateKeyCredentialResponse {
	t.Helper()
	r, err := h.vault.GenerateKeyCredential(ctx(t), &v1.GenerateKeyCredentialRequest{Label: label, Username: "pi"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func fp(t *testing.T, line string) string {
	t.Helper()
	f := strings.Fields(line)
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}

func TestKeygenServicio(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t) // "lab", con contraseña
	r := h.keygen(t, "pi")
	if !strings.HasPrefix(r.PublicKey, "ssh-ed25519 ") || !strings.Contains(r.PublicKey, " macuahuitl@") {
		t.Fatalf("pública: %q", r.PublicKey)
	}
	if k := h.kinds(t); k["pi"] != "key" || k["lab"] != "password" {
		t.Fatalf("kinds: %v", k)
	}
	if _, err := h.vault.GenerateKeyCredential(ctx(t), &v1.GenerateKeyCredentialRequest{Label: "macuahuitl:x", Username: "u"}); codeOf(err) != codes.InvalidArgument {
		t.Fatalf("reservada: %v", err)
	}
	g, err := h.vault.GetCredentialPublicKey(ctx(t), &v1.GetCredentialPublicKeyRequest{Id: r.Id})
	if err != nil || fp(t, g.PublicKey) != fp(t, r.PublicKey) {
		t.Fatalf("pubkey: %v", err)
	}
	// Una credencial sin llave: FailedPrecondition.
	lab := ""
	for _, c := range func() []*v1.CredentialInfo {
		x, _ := h.vault.ListCredentials(ctx(t), &v1.ListCredentialsRequest{})
		return x.Credentials
	}() {
		if c.Label == "lab" {
			lab = c.Id
		}
	}
	if _, err := h.vault.GetCredentialPublicKey(ctx(t), &v1.GetCredentialPublicKeyRequest{Id: lab}); codeOf(err) != codes.FailedPrecondition {
		t.Fatalf("sin llave: %v", err)
	}
	a := h.auditText(t)
	if !strings.Contains(a, `"action":"credential.keygen"`) || !strings.Contains(a, "type=ssh-ed25519 fingerprint="+fp(t, r.PublicKey)) || !strings.Contains(a, `"action":"credential.pubkey"`) {
		t.Fatalf("auditoría:\n%s", a)
	}
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// diskText concatena todos los archivos bajo las carpetas de datos y estado (bóveda, .bak, auditoría en disco).
func diskText(t *testing.T, dirs ...string) string {
	t.Helper()
	var b strings.Builder
	for _, d := range dirs {
		filepath.WalkDir(d, func(p string, e os.DirEntry, err error) error {
			if err == nil && !e.IsDir() {
				if raw, err := os.ReadFile(p); err == nil {
					b.Write(raw)
				}
			}
			return nil
		})
	}
	return b.String()
}

// needles saca de la privada guardada la semilla (cruda, hex, base64 std y raw) y cada línea del cuerpo del PEM salvo la primera.
func needles(t *testing.T, pemBytes []byte) []string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(string(pemBytes)), "\n")
	body := lines[1 : len(lines)-1]
	der, err := base64.StdEncoding.DecodeString(strings.Join(body, ""))
	if err != nil {
		t.Fatal(err)
	}
	// La semilla va tras la segunda aparición de la pública (sección privada: pública, luego string de 64 B = semilla ‖ pública).
	pub := der[bytes.Index(der, []byte("ssh-ed25519"))+len("ssh-ed25519")+4:][:32]
	first := bytes.Index(der, pub)
	i := first + 32 + bytes.Index(der[first+32:], pub) + 32 + 4
	seed := der[i : i+32]
	if bytes.Equal(seed, pub) {
		t.Fatal("la prueba no halló la semilla")
	}
	n := []string{string(seed), hex.EncodeToString(seed), base64.StdEncoding.EncodeToString(seed), base64.RawStdEncoding.EncodeToString(seed)}
	return append(n, body[1:]...)
}

func TestKeygenNoDejaLaPrivadaEnClaro(t *testing.T) {
	var errOut lockedBuf
	h := newHarness(t, func(o *Options) { o.ErrOut = &errOut })
	h.ready(t)
	r := h.keygen(t, "pi")
	cur := func() []string { // la privada guardada ahora; se toma antes de cada paso porque la regeneración destruye la vieja
		c, err := h.core.vault.Get(r.Id)
		if err != nil {
			t.Fatal(err)
		}
		defer c.SSHKey.Destroy()
		return needles(t, c.SSHKey.Bytes())
	}
	ns := cur()
	if _, err := h.vault.GetCredentialPublicKey(ctx(t), &v1.GetCredentialPublicKeyRequest{Id: r.Id}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.vault.RegenerateKeyCredential(ctx(t), &v1.RegenerateKeyCredentialRequest{Id: r.Id, Confirm: true}); err != nil {
		t.Fatal(err)
	}
	ns = append(ns, cur()...)
	if len(ns) < 12 {
		t.Fatalf("pocas agujas: %d", len(ns))
	}
	for name, text := range map[string]string{"bóveda en disco": diskText(t, h.p.Data, h.p.State, h.p.Config), "auditoría": h.auditText(t), "ErrOut": errOut.String()} {
		if text == "" && name != "ErrOut" { // ErrOut solo escribe si se pierde una entrada de auditoría
			t.Fatalf("%s vacío: la prueba no mira nada", name)
		}
		if strings.Contains(text, "PRIVATE KEY") {
			t.Fatalf("PEM en %s", name)
		}
		for _, n := range ns {
			if strings.Contains(text, n) {
				t.Fatalf("la privada (%.8q…) aparece en %s", n, name)
			}
		}
	}
}

func TestRegenerarLlaveServicio(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	k := h.keygen(t, "pi")
	if _, err := h.vault.RegenerateKeyCredential(ctx(t), &v1.RegenerateKeyCredentialRequest{Id: k.Id}); codeOf(err) != codes.FailedPrecondition {
		t.Fatalf("sin confirm: %v", err)
	}
	if g, _ := h.vault.GetCredentialPublicKey(ctx(t), &v1.GetCredentialPublicKeyRequest{Id: k.Id}); fp(t, g.PublicKey) != fp(t, k.PublicKey) {
		t.Fatal("sin confirm cambió la llave")
	}
	r, err := h.vault.RegenerateKeyCredential(ctx(t), &v1.RegenerateKeyCredentialRequest{Id: k.Id, Confirm: true})
	if err != nil || fp(t, r.PublicKey) == fp(t, k.PublicKey) {
		t.Fatalf("regenerar: %v", err)
	}
	g, _ := h.vault.GetCredentialPublicKey(ctx(t), &v1.GetCredentialPublicKeyRequest{Id: k.Id})
	if fp(t, g.PublicKey) != fp(t, r.PublicKey) {
		t.Fatal("no persistió la nueva")
	}
	a := h.auditText(t)
	if !strings.Contains(a, "old="+fp(t, k.PublicKey)+" new="+fp(t, r.PublicKey)) || !strings.Contains(a, `"action":"credential.keyrotate"`) {
		t.Fatalf("auditoría:\n%s", a)
	}
	// Sobre una password.
	pw, _ := h.vault.PutCredential(ctx(t), &v1.PutCredentialRequest{Label: "otra", Username: "u", Password: []byte("x")})
	if _, err := h.vault.RegenerateKeyCredential(ctx(t), &v1.RegenerateKeyCredentialRequest{Id: pw.Id, Confirm: true}); codeOf(err) != codes.FailedPrecondition {
		t.Fatalf("password: %v", err)
	}
}

func TestPutCredentialRechazaLlaves(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	_, err := h.vault.PutCredential(ctx(t), &v1.PutCredentialRequest{Label: "ext", Username: "u", SshPrivateKey: []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n")})
	if codeOf(err) != codes.InvalidArgument {
		t.Fatalf("llave: %v", err)
	}
	if _, ok := h.kinds(t)["ext"]; ok {
		t.Fatal("guardó algo")
	}
	k := h.keygen(t, "pi")
	_, err = h.vault.PutCredential(ctx(t), &v1.PutCredentialRequest{Id: k.Id, Label: "pi", Username: "u", Password: []byte("x")})
	if codeOf(err) != codes.FailedPrecondition {
		t.Fatalf("reemplazo: %v", err)
	}
	if h.kinds(t)["pi"] != "key" {
		t.Fatal("la key cambió")
	}
}

func TestRespaldoLlevaLaLlave(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	k := h.keygen(t, "pi")
	path := filepath.Join(t.TempDir(), "r.mcvault")
	r, err := h.export(t, path, true)
	if err != nil || r.Count != 2 || r.SshKeysIncluded != 1 {
		t.Fatalf("export: %+v %v", r, err)
	}
	o := newHarness(t, nil)
	if _, err := o.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("otra-maestra")}); err != nil {
		t.Fatal(err)
	}
	pr, err := o.preview(t, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.vault.ApplyBackupImport(ctx(t), &v1.ApplyBackupImportRequest{Token: pr.Token}); err != nil {
		t.Fatal(err)
	}
	if o.kinds(t)["pi"] != "key" {
		t.Fatalf("kinds: %v", o.kinds(t))
	}
	infos, _ := o.vault.ListCredentials(ctx(t), &v1.ListCredentialsRequest{})
	for _, c := range infos.Credentials {
		if c.Label == "pi" {
			g, err := o.vault.GetCredentialPublicKey(ctx(t), &v1.GetCredentialPublicKeyRequest{Id: c.Id})
			if err != nil || fp(t, g.PublicKey) != fp(t, k.PublicKey) {
				t.Fatalf("la pública restaurada difiere: %v", err)
			}
		}
	}
	if a := h.auditText(t); !strings.Contains(a, "ssh_keys_included=1") {
		t.Fatalf("auditoría del export:\n%s", a)
	}
}
