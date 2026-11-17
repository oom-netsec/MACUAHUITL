package core

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

func rsaPKCS1(t *testing.T, bits int) (pemBytes, d []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), k.D.Bytes()
}

func (h *harness) importKey(t *testing.T, label string, pem, pass []byte) (*v1.ImportKeyCredentialResponse, error) {
	return h.vault.ImportKeyCredential(ctx(t), &v1.ImportKeyCredentialRequest{Label: label, Username: "pi", PrivateKey: pem, Passphrase: pass})
}

// 47d: dos llaves importadas por el servicio (ed25519 con frase y RSA 2048 sin frase) autentican por publickey con transport.OpenSSH
// contra el simulador SSH del repo, que autoriza solo esa pública; la otra y una generada no entran.
func TestImportarLlavesAutenticanPorPublickey(t *testing.T) {
	var errOut lockedBuf
	h := newHarness(t, func(o *Options) { o.ErrOut = &errOut })
	h.ready(t)
	frase := []byte("frase-secreta-del-dueno")
	edPEM, seed := simulator.EncryptedEd25519(t, frase)
	rsaPEM, rsaD := rsaPKCS1(t, 2048)
	agujas := []string{string(frase), hex.EncodeToString(seed), base64.StdEncoding.EncodeToString(seed), base64.RawStdEncoding.EncodeToString(seed),
		string(rsaD), base64.StdEncoding.EncodeToString(rsaD)}
	for _, p := range [][]byte{edPEM, rsaPEM} {
		ls := strings.Split(strings.TrimSpace(string(p)), "\n")
		agujas = append(agujas, ls[2:len(ls)-1]...)
	}

	// Sin frase: key_passphrase_required (FailedPrecondition); con otra: key_passphrase_wrong (InvalidArgument); nada se guardó.
	_, err := h.importKey(t, "ed", bytes.Clone(edPEM), nil)
	if r, _ := reasonOf(err); codeOf(err) != codes.FailedPrecondition || r != "vault.err.key_passphrase_required" {
		t.Fatalf("sin frase: %v", err)
	}
	_, err = h.importKey(t, "ed", bytes.Clone(edPEM), []byte("otra"))
	if r, _ := reasonOf(err); codeOf(err) != codes.InvalidArgument || r != "vault.err.key_passphrase_wrong" {
		t.Fatalf("frase mala: %v", err)
	}
	if k := h.kinds(t); len(k) != 1 {
		t.Fatalf("se guardó algo: %v", k)
	}
	ed1, err := h.importKey(t, "ed", edPEM, append([]byte(nil), frase...))
	if err != nil {
		t.Fatal(err)
	}
	rs, err := h.importKey(t, "rsa", rsaPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ed1.Algorithm != "ssh-ed25519" || ed1.Bits != 256 || ed1.Weak || fp(t, ed1.PublicKey) != ed1.Fingerprint {
		t.Fatalf("ed: %+v", ed1)
	}
	if rs.Algorithm != "ssh-rsa" || rs.Bits != 2048 || !rs.Weak || fp(t, rs.PublicKey) != rs.Fingerprint || !strings.Contains(rs.PublicKey, " macuahuitl@") {
		t.Fatalf("rsa: %+v", rs)
	}

	// origin en la lista y huella en GetCredentialPublicKey.
	gen := h.keygen(t, "gen")
	l, _ := h.vault.ListCredentials(ctx(t), &v1.ListCredentialsRequest{})
	got := map[string]string{}
	for _, c := range l.Credentials {
		got[c.Label] = c.Origin
	}
	if got["ed"] != "imported" || got["rsa"] != "imported" || got["gen"] != "generated" || got["lab"] != "" {
		t.Fatalf("origin: %v", got)
	}
	if g, err := h.vault.GetCredentialPublicKey(ctx(t), &v1.GetCredentialPublicKeyRequest{Id: rs.Id}); err != nil || g.Fingerprint != rs.Fingerprint || g.PublicKey != rs.PublicKey {
		t.Fatalf("GetCredentialPublicKey: %+v %v", g, err)
	}

	// weak solo en la RSA.
	if ed1.Weak || !rs.Weak {
		t.Fatal("weak mal puesto")
	}
	// Autenticación: cada una entra con su pública y solo con ella.
	for _, c := range []struct {
		n  string
		r  *v1.ImportKeyCredentialResponse
		ot string
	}{{"ed", ed1, rs.PublicKey}, {"rsa", rs, ed1.PublicKey}} {
		log, err := h.openKeyLog(t, c.r.Id, c.r.PublicKey)
		if err != nil {
			t.Fatalf("%s no autentica: %v", c.n, err)
		}
		for _, m := range log {
			if m != "none" && m != "publickey" {
				t.Fatalf("%s: método de autenticación inesperado %q en %v", c.n, m, log)
			}
		}
		if !strings.Contains(strings.Join(log, ","), "publickey") {
			t.Fatalf("%s: sin publickey: %v", c.n, log)
		}
		if err := h.openKey(t, c.r.Id, c.ot); err == nil {
			t.Fatalf("%s entró con una pública ajena", c.n)
		}
		if err := h.openKey(t, c.r.Id, gen.PublicKey); err == nil {
			t.Fatalf("%s entró con la pública de otra llave", c.n)
		}
	}

	// Ni la privada, ni la frase, ni el PEM en la bóveda en disco, la auditoría o los logs.
	a := h.auditText(t)
	if !strings.Contains(a, `"action":"credential.keyimport"`) || !strings.Contains(a, "type=ssh-rsa bits=2048 fingerprint="+rs.Fingerprint) {
		t.Fatalf("auditoría:\n%s", a)
	}
	for name, text := range map[string]string{"bóveda en disco": diskText(t, h.p.Data, h.p.State, h.p.Config), "auditoría": a, "ErrOut": errOut.String()} {
		if strings.Contains(text, "PRIVATE KEY") {
			t.Fatalf("PEM en %s", name)
		}
		for _, n := range agujas {
			if len(n) > 4 && strings.Contains(text, n) {
				t.Fatalf("material de la llave (%.8q…) en %s", n, name)
			}
		}
	}

	// Rekey de una importada: queda generated y la pública cambia.
	r, err := h.vault.RegenerateKeyCredential(ctx(t), &v1.RegenerateKeyCredentialRequest{Id: rs.Id, Confirm: true})
	if err != nil || !strings.HasPrefix(r.PublicKey, "ssh-ed25519 ") || r.PreviousOrigin != "imported" {
		t.Fatalf("rekey: %+v %v", r, err)
	}
	l, _ = h.vault.ListCredentials(ctx(t), &v1.ListCredentialsRequest{})
	for _, c := range l.Credentials {
		if c.Id == rs.Id && c.Origin != "generated" {
			t.Fatalf("origin tras rekey: %s", c.Origin)
		}
	}

	// El respaldo .mcvault conserva origin y la llave autentica restaurada.
	path := filepath.Join(t.TempDir(), "r.mcvault")
	if _, err := h.export(t, path, true); err != nil {
		t.Fatal(err)
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
	l, _ = o.vault.ListCredentials(ctx(t), &v1.ListCredentialsRequest{})
	for _, c := range l.Credentials {
		switch c.Label {
		case "ed":
			if c.Origin != "imported" {
				t.Fatalf("origin restaurado de ed: %q", c.Origin)
			}
			if err := o.openKey(t, c.Id, ed1.PublicKey); err != nil {
				t.Fatalf("la importada restaurada no autentica: %v", err)
			}
		case "rsa":
			if c.Origin != "generated" {
				t.Fatalf("origin restaurado de rsa (rekey): %q", c.Origin)
			}
		}
	}
}

func TestImportarLlaveRechazos(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	for _, c := range []struct {
		n      string
		label  string
		pem    []byte
		code   codes.Code
		reason string
		md     string
	}{
		{"basura", "a", []byte("basura"), codes.InvalidArgument, "vault.err.key_import_invalid", "format"},
		{"tope", "b", bytes.Repeat([]byte("a"), 64<<10+1), codes.InvalidArgument, "vault.err.field_too_long", ""},
		{"reservada", "macuahuitl:x", []byte("x"), codes.InvalidArgument, "", ""},
	} {
		_, err := h.importKey(t, c.label, c.pem, nil)
		r, md := reasonOf(err)
		if codeOf(err) != c.code || (c.reason != "" && r != c.reason) {
			t.Errorf("%s: %v (reason %q)", c.n, err, r)
		}
		if _, ok := md[c.md]; c.md != "" && !ok {
			t.Errorf("%s: falta la metadata %s: %v", c.n, c.md, md)
		}
	}
	// DSA: key_unsupported con el tipo en la metadata.
	_, err := h.importKey(t, "d", pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte("x")}), nil)
	if r, md := reasonOf(err); codeOf(err) != codes.InvalidArgument || r != "vault.err.key_import_unsupported" || md["type"] != "ssh-dss" || md["format"] == "" {
		t.Fatalf("dsa: %v %v", err, md)
	}
	if len(h.kinds(t)) != 1 {
		t.Fatal("se guardó algo")
	}
}
