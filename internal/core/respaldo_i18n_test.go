package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// Fase 30d: los errores del respaldo de la bóveda llevan código y salen en el idioma pedido; con es el texto es
// el de siempre (los textos de la columna es son los de antes del catálogo).
func TestRespaldoErroresEsYEn(t *testing.T) {
	h, path := bovedaConRespaldo(t, nil)
	ajeno := filepath.Join(t.TempDir(), "x.mcvault")
	os.WriteFile(ajeno, []byte(strings.Repeat("no soy un respaldo ", 20)), 0o600)
	// destino con un conflicto de etiqueta para las decisiones
	o := newHarness(t, nil)
	o.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("otra-maestra")})
	o.put(t, "core", "USR-CORE", "OTRA")
	pr, err := o.preview(t, path)
	if err != nil {
		t.Fatal(err)
	}
	core := itemID(t, pr, "core")
	cases := []struct {
		name, reason, es, en string
		call                 func(loc string) error
	}{
		{"sin confirmar", "respaldo.err.confirm", "el respaldo contiene todas tus credenciales en un solo archivo: quien tenga el archivo y la frase las tiene todas; confirma para continuar",
			"the backup contains all your credentials in a single file: whoever has the file and the passphrase has them all; confirm to continue",
			func(loc string) error {
				_, err := h.vault.ExportBackup(con(t, loc), &v1.ExportBackupRequest{Path: filepath.Join(t.TempDir(), "n"), Passphrase: []byte(fraseResp)})
				return err
			}},
		{"ruta relativa", "respaldo.err.path_abs", "la ruta debe ser absoluta", "the path must be absolute",
			func(loc string) error {
				_, err := h.vault.PreviewBackupImport(con(t, loc), &v1.PreviewBackupImportRequest{Path: "relativa", Passphrase: []byte(fraseResp)})
				return err
			}},
		{"frase mala", "respaldo.err.wrong_phrase", "la frase del respaldo es incorrecta (o el archivo está alterado)", "the backup passphrase is wrong (or the file has been tampered with)",
			func(loc string) error {
				_, err := h.vault.PreviewBackupImport(con(t, loc), &v1.PreviewBackupImportRequest{Path: path, Passphrase: []byte("incorrecta-incorrecta")})
				return err
			}},
		{"ajeno", "vault.err.not_backup", "vault: no es un respaldo de bóveda de MACUAHUITL", "vault: not a MACUAHUITL vault backup",
			func(loc string) error {
				_, err := h.vault.PreviewBackupImport(con(t, loc), &v1.PreviewBackupImportRequest{Path: ajeno, Passphrase: []byte(fraseResp)})
				return err
			}},
		{"frase corta", "vault.err.short_phrase", "vault: la frase del respaldo debe tener al menos 12 caracteres", "vault: the backup passphrase must be at least 12 characters long",
			func(loc string) error {
				_, err := h.vault.ExportBackup(con(t, loc), &v1.ExportBackupRequest{Path: filepath.Join(t.TempDir(), "n"), Passphrase: []byte("corta"), Confirm: true})
				return err
			}},
		{"token", "respaldo.err.token", "token de importación desconocido; abre el respaldo de nuevo", "unknown import token; open the backup again",
			func(loc string) error {
				_, err := o.vault.ApplyBackupImport(con(t, loc), &v1.ApplyBackupImportRequest{Token: "no-existe"})
				return err
			}},
	}
	dec := func(loc string, d ...*v1.VaultBackupDecision) error {
		_, err := o.vault.ApplyBackupImport(con(t, loc), &v1.ApplyBackupImportRequest{Token: pr.Token, Decisions: d})
		return err
	}
	for _, c := range []struct {
		name, reason, es, en string
		d                    []*v1.VaultBackupDecision
	}{
		{"id ajeno", "respaldo.err.decision_unknown", "decisión para una credencial que no está en el respaldo", "decision for a credential that is not in the backup", []*v1.VaultBackupDecision{{Id: "zz", Action: "omitir"}}},
		{"repetida", "respaldo.err.decision_dup", `decisión repetida para "core"`, `repeated decision for "core"`, []*v1.VaultBackupDecision{{Id: core, Action: "omitir"}, {Id: core, Action: "omitir"}}},
		{"acción", "respaldo.err.action", `acción "fusionar" desconocida; usa renombrar, reemplazar u omitir`, `unknown action "fusionar"; use renombrar, reemplazar or omitir`, []*v1.VaultBackupDecision{{Id: core, Action: "fusionar"}}},
		{"sin decidir", "respaldo.err.undecided", `falta decidir qué hacer con "core": renombrar, reemplazar u omitir`, `you still need to decide what to do with "core": renombrar, reemplazar or omitir`, nil},
	} {
		c := c
		cases = append(cases, struct {
			name, reason, es, en string
			call                 func(loc string) error
		}{c.name, c.reason, c.es, c.en, func(loc string) error { return dec(loc, c.d...) }})
	}
	for _, c := range cases {
		for _, loc := range []string{"es", "en"} {
			err := c.call(loc)
			st, _ := status.FromError(err)
			want := c.es
			if loc == "en" {
				want = c.en
			}
			if st == nil || st.Message() != want {
				t.Errorf("%s/%s: %v, quería %q", c.name, loc, err, want)
				continue
			}
			ok := false
			for _, d := range st.Details() {
				if ei, is := d.(*errdetails.ErrorInfo); is && ei.Reason == c.reason {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s/%s: sin reason %s (%v)", c.name, loc, c.reason, st.Details())
			}
		}
	}
	// La bóveda cerrada y el archivo inexistente no pierden su texto.
	if _, err := h.vault.PreviewBackupImport(con(t, "en"), &v1.PreviewBackupImportRequest{Path: filepath.Join(t.TempDir(), "no"), Passphrase: []byte(fraseResp)}); status.Code(err) != 5 {
		t.Errorf("inexistente: %v", err)
	}
}
