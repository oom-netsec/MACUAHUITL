package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"crypto/sha256"
	"encoding/base64"
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

func TestKeygenNoDejaLaPrivadaEnClaro(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	r := h.keygen(t, "pi")
	c, err := h.core.vault.Get(r.Id)
	if err != nil {
		t.Fatal(err)
	}
	pem := string(c.SSHKey.Bytes())
	c.Password.Destroy()
	c.Enable.Destroy()
	c.SSHKey.Destroy()
	raw, err := os.ReadFile(filepath.Join(h.p.Data, "vault.mcv"))
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Split(strings.Trim(strings.SplitN(pem, "-----\n", 2)[1], "\n"), "\n-----END")[0]
	for name, text := range map[string]string{"bóveda": string(raw), "auditoría": h.auditText(t)} {
		if strings.Contains(text, "PRIVATE KEY") || strings.Contains(text, strings.SplitN(body, "\n", 2)[0]) {
			t.Fatalf("la privada aparece en %s", name)
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
