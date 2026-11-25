package core

import (
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// La vista previa del import no compara contraseñas: una credencial del respaldo idéntica a la viva y otra con la misma
// etiqueta y otra contraseña salen igual («conflicto_etiqueta»). Si no, un respaldo armado con N candidatas probaría la
// contraseña de la viva sin la maestra.
func TestRespaldoPreviewNoComparaContrasenas(t *testing.T) {
	h, path := bovedaConRespaldo(t, nil) // trae «core» con PW-CORE
	_ = h
	o := newHarness(t, nil)
	o.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("otra-maestra")})
	o.put(t, "core", "USR-CORE", "PW-CORE") // idéntica (mismo usuario, contraseña y enable)
	o.put(t, "borde", "USR-BORDE", "OTRA")  // misma etiqueta, otra contraseña
	pr, err := o.preview(t, path)
	if err != nil {
		t.Fatal(err)
	}
	e := estados(pr)
	if e["core"] != "conflicto_etiqueta" || e["borde"] != "conflicto_etiqueta" {
		t.Fatalf("estados = %v", e)
	}
	var tc, tb string
	for _, i := range pr.Items {
		switch i.Label {
		case "core":
			tc = i.TargetId
		case "borde":
			tb = i.TargetId
		}
	}
	if tc == "" || tb == "" {
		t.Fatalf("target_id vacío: %q %q", tc, tb)
	}
}

// Con dos credenciales vivas de la misma etiqueta, el conflicto apunta a la del mismo usuario: «reemplazar» no pisa
// la otra (el usuario ya es público en ListCredentials; no abre ningún oráculo).
func TestRespaldoConflictoApuntaAlMismoUsuario(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	h.put(t, "dup", "u1", "PW-UNO")
	h.put(t, "dup", "u2", "PW-DOS")
	path := filepath.Join(t.TempDir(), "d.mcvault")
	if _, err := h.vault.ExportBackup(ctx(t), &v1.ExportBackupRequest{Path: path, Passphrase: []byte(fraseResp), Confirm: true}); err != nil {
		t.Fatal(err)
	}
	vivos := map[string]string{} // usuario -> id vivo
	l, _ := h.vault.ListCredentials(ctx(t), &v1.ListCredentialsRequest{})
	for _, c := range l.Credentials {
		if c.Label == "dup" {
			vivos[c.Username] = c.Id
		}
	}
	pr, err := h.preview(t, path)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range pr.Items {
		if i.Label == "dup" && i.TargetId != vivos[i.Username] {
			t.Fatalf("%s apunta a %s, quería %s", i.Username, i.TargetId, vivos[i.Username])
		}
	}
}
