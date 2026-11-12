package assist

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

var enSinEspanol = regexp.MustCompile(`[áéíóúñ¿¡«»]|\b(el equipo|la reversa|no se pudo|puerto|solo)\b`)

// Las negativas de rotar y restaurar: es es el de siempre (centinela + motivo), el centinela se sigue reconociendo y en sale traducido.
func TestNegativasRotarYRestaurarEsYEn(t *testing.T) {
	_, err := CredRotatePlan("SW1", CredRotateChange{User: "tech", NewSecret: "Abcdefgh1234", ConnectedUser: "TECH"}, nil)
	const wantEs = `assist: no se puede rotar esa credencial: el usuario "tech" es el de la sesión que ejecuta el cambio; conéctate con otra credencial para poder revertir`
	if err == nil || err.Error() != wantEs || !errors.Is(err, ErrRotateRefused) {
		t.Fatalf("es: %v", err)
	}
	var c i18n.Coded
	if !errors.As(err, &c) || c.Reason() != "assist.rotate_refused" || len(c.Metadata()) != 0 {
		t.Fatalf("coded: %#v", c)
	}
	if en := c.Localize(i18n.En); !strings.HasPrefix(en, "assist: that credential cannot be rotated: the user \"tech\"") || enSinEspanol.MatchString(en) {
		t.Fatalf("en: %q", en)
	}

	_, err = RestoreDiffPlan("SW1", RestoreChange{BackupMasked: true}, map[string]string{})
	if err == nil || !errors.Is(err, ErrRestoreRefused) || !strings.HasPrefix(err.Error(), "assist: no se puede restaurar ese respaldo: el respaldo se tomó con secretos enmascarados") {
		t.Fatalf("restore es: %v", err)
	}
	errors.As(err, &c)
	if en := c.Localize(i18n.En); !strings.HasPrefix(en, "assist: that backup cannot be restored: the backup was taken with masked secrets") {
		t.Fatalf("restore en: %q", en)
	}
}

// La negativa de un puerto pasa a negativa de snippet conservando el motivo y su traducción.
func TestRefusalOfConservaElMotivoEnEn(t *testing.T) {
	r := refusalOf(refuse("assist.port_refused.usa_vlan_de_acceso_dinamica", "port", "Gi1/0/1"))
	sr, ok := r.(*SnippetRefusal)
	if !ok || sr.Detail != "Gi1/0/1 usa VLAN de acceso dinámica (VMPS)" {
		t.Fatalf("%#v", r)
	}
	if en := sr.Localize(i18n.En); en != "assist: the device does not support this snippet: Gi1/0/1 uses a dynamic access VLAN (VMPS)" {
		t.Fatalf("en: %q", en)
	}
	if got := sr.Error(); got != "assist: el equipo no admite este snippet: Gi1/0/1 usa VLAN de acceso dinámica (VMPS)" {
		t.Fatalf("es: %q", got)
	}
}

// El post-check: cada fallo en es es el de siempre y tiene su versión en en.
func TestEvalExpectEsYEn(t *testing.T) {
	ex := []Expect{{Command: "show x", Line: "a", Present: true}, {Command: "show x", Line: "b", Present: false}, {Command: "show y", Line: "c", Present: true}}
	outs := map[string]string{"show x": "b\n"}
	es := EvalExpect(ex, outs)
	want := []string{`en "show x" debía aparecer "a"`, `en "show x" no debía aparecer "b"`, `"show y" no corrió`}
	if strings.Join(es, "|") != strings.Join(want, "|") {
		t.Fatalf("es: %q", es)
	}
	var en []string
	for _, f := range evalExpect(ex, outs) {
		en = append(en, f.In(i18n.En))
	}
	if strings.Join(en, "|") != `"a" should appear in "show x"|"b" should not appear in "show x"|"show y" did not run` {
		t.Fatalf("en: %q", en)
	}
}

// Las notas llevan su clave y, con sus argumentos, reproducen el texto es; en sale en inglés.
func TestNotasDelPlanTienenClave(t *testing.T) {
	n := note("assist.note.port_mode_same", "port", "Gi1/0/1", "mode", "access")
	if n.In(i18n.Es) != "Gi1/0/1: ya estaba en modo access (sin cambios)" || n.In(i18n.En) != "Gi1/0/1: was already in mode access (no changes)" {
		t.Fatalf("%q / %q", n.In(i18n.Es), n.In(i18n.En))
	}
	// La frase de la IP de origen cambia con el idioma, la IP no.
	v := note("assist.note.vty_acl", "acl", "MGMT", "ip1", "10.0.0.5", "what1", "2")
	if !strings.Contains(v.In(i18n.Es), "10.0.0.5 (la IP local de la sesión)") || !strings.Contains(v.In(i18n.En), "10.0.0.5 (the session's local IP (app side))") {
		t.Fatalf("%q", v.In(i18n.En))
	}
}

// withPrefix conserva el motivo del error de dentro y antepone la palabra en el idioma pedido.
func TestWithPrefixLocaliza(t *testing.T) {
	err := withPrefix("assist.err.description_invalid", vbad("ascii", "value", "á"))
	var c i18n.Coded
	if !errors.As(err, &c) || c.Reason() != "assist.err.description_invalid" || c.Metadata()["field"] != "description" {
		t.Fatalf("reason %v", c)
	}
	if _, ok := c.Metadata()["why"]; ok {
		t.Fatalf("la metadata no es la de assist.invalid_value: %v", c.Metadata())
	}
	if !strings.HasPrefix(err.Error(), "descripción: ") || !strings.HasPrefix(c.Localize(i18n.En), "description: ") {
		t.Fatalf("%q / %q", err.Error(), c.Localize(i18n.En))
	}
}
