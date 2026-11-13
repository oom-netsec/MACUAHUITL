package patrol

import (
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
)

// Un error del catálogo con causa (un comando rechazado) conserva su causa en es y sale en inglés con en.
func TestFieldErrOfConCausa(t *testing.T) {
	_, err := playbook.Ephemeral("ios-xe", "configure terminal")
	fe := fieldErrOf("custom_commands", err).(*FieldError)
	if want := `patrol: custom_commands: playbook: comando no permitido en una recolección (solo lectura): "configure terminal" (no es un comando de lectura)`; fe.Error() != want {
		t.Errorf("es: %q", fe.Error())
	}
	if want := `patrol: custom_commands: playbook: command not allowed in a collection (read-only): "configure terminal" (not a read command)`; fe.Localize("en") != want {
		t.Errorf("en: %q", fe.Localize("en"))
	}
	if fe.Reason() != "playbook.err.denied_cmd" || fe.Metadata()["field"] != "custom_commands" || fe.Metadata()["cmd"] != "configure terminal" {
		t.Errorf("reason %q metadata %v", fe.Reason(), fe.Metadata())
	}
	if cr := fe.Metadata()["cause_reason"]; !strings.HasPrefix(cr, "playbook.why.") {
		t.Errorf("sin cause_reason: %v", fe.Metadata())
	}
}
