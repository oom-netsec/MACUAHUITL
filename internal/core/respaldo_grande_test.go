package core

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

// llenar mete n credenciales por lotes chicos (cada secreto abierto ocupa memoria bloqueada: no retener todos a la vez). campo da los bytes de cada secreto.
func llenar(t *testing.T, h *harness, n, campo int) {
	t.Helper()
	f := bytes.Repeat([]byte{'x'}, campo)
	for i := 0; i < n; i += 10 {
		var cs []vault.Credential
		for j := i; j < min(i+10, n); j++ {
			c := vault.Credential{Label: fmt.Sprintf("c%04d", j), Username: "u", Password: secret.New(bytes.Clone(f))}
			cs = append(cs, c)
		}
		_, err := h.core.vault.PutBatch(cs)
		for _, c := range cs {
			c.Password.Destroy()
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func vacia(t *testing.T) *harness {
	o := newHarness(t, nil)
	if _, err := o.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("otra-maestra")}); err != nil {
		t.Fatal(err)
	}
	return o
}

// Un respaldo de 2000 credenciales se previsualiza y se aplica sin pánico ni tope por memoria bloqueada.
func TestRespaldoGrandeDosMilCredenciales(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	llenar(t, h, 2000, 1)
	path := filepath.Join(t.TempDir(), "r.mcvault")
	if r, err := h.export(t, path, true); err != nil || r.Count != 2001 {
		t.Fatalf("export: %+v %v", r, err)
	}
	o := vacia(t)
	pr, err := o.preview(t, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(pr.Items) != 2001 {
		t.Fatalf("items %d", len(pr.Items))
	}
	res, err := o.vault.ApplyBackupImport(ctx(t), &v1.ApplyBackupImportRequest{Token: pr.Token})
	if err != nil || res.Created != 2001 {
		t.Fatalf("apply: %+v %v", res, err)
	}
	if l := o.labels(t); len(l) != 2001 {
		t.Fatalf("quedaron %d", len(l))
	}
}

// 43 entradas de 3x64 KiB (antes rechazo por cota) y 4 vistas previas grandes a la vez.
func TestRespaldoGrandeCamposMaximosYVariasPendientes(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	f := bytes.Repeat([]byte{'x'}, vault.MaxFieldBytes)
	for i := 0; i < 43; i++ {
		// Una llave de 64 KiB no es una llave SSH válida: solo Password y Enable llevan relleno.
		c := vault.Credential{Label: fmt.Sprintf("g%02d", i), Password: secret.New(bytes.Clone(f)), Enable: secret.New(bytes.Clone(f))}
		_, err := h.core.vault.Put(c)
		c.Password.Destroy()
		c.Enable.Destroy()
		if err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "r.mcvault")
	if r, err := h.export(t, path, true); err != nil || r.Count != 44 {
		t.Fatalf("export: %+v %v", r, err)
	}
	o := vacia(t)
	var toks []string
	for i := 0; i < 4; i++ {
		pr, err := o.preview(t, path)
		if err != nil {
			t.Fatalf("preview %d: %v", i, err)
		}
		toks = append(toks, pr.Token)
	}
	res, err := o.vault.ApplyBackupImport(ctx(t), &v1.ApplyBackupImportRequest{Token: toks[3]})
	if err != nil || res.Created != 44 {
		t.Fatalf("apply: %+v %v", res, err)
	}
}
