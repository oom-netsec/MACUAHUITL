package core

import (
	"slices"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
)

// Un playbook de <config>/playbooks (propio o importado) no es gemelo del oficial por tener Pack vacío: cada origen
// solo se empareja consigo mismo.
func TestPlaybookDelUsuarioNoEsGemeloDelOficial(t *testing.T) {
	h := newHarness(t, nil)
	idx := slices.IndexFunc(h.core.basePbs, func(p playbook.Playbook) bool { return p.Platform == "ios-xe" })
	if idx < 0 {
		t.Fatal("la base no trae playbooks ios-xe")
	}
	base := h.core.basePbs[idx]
	file := strings.TrimPrefix(base.ID, "ios-xe/")
	h.userPlaybookFile(t, file+".yaml", file, "ios") // ios/<file>, hermano del oficial ios-xe/<file>
	h.restart(t)
	if tw := playbook.Twin(h.core.catalog(), base.ID, "ios"); tw != nil {
		t.Fatalf("el ios/%s del usuario no es gemelo del oficial %s: %+v", file, base.ID, tw)
	}
	// Entre playbooks del usuario sí hay gemelo.
	h.userPlaybookFile(t, "otro.yaml", "otro", "ios")
	h.userPlaybookFile(t, "otro-xe.yaml", "otro", "ios-xe")
	h.restart(t)
	if tw := playbook.Twin(h.core.catalog(), "ios-xe/otro", "ios"); tw == nil || tw.ID != "ios/otro" {
		t.Fatalf("gemelo entre playbooks del usuario: %+v", tw)
	}
}

// Un archivo de <config>/playbooks que reemplaza un ID de la base conserva su Pack (""): sigue emparejándose como antes.
func TestPlaybookDelUsuarioQueReemplazaALaBaseConservaPack(t *testing.T) {
	h := newHarness(t, nil)
	base := h.core.basePbs[slices.IndexFunc(h.core.basePbs, func(p playbook.Playbook) bool { return p.Platform == "ios-xe" })]
	file := strings.TrimPrefix(base.ID, "ios-xe/")
	h.userPlaybookFile(t, file+".yaml", file, "ios-xe") // mismo ID que el de la base
	h.userPlaybookFile(t, "nuevo-propio.yaml", "nuevo-propio", "ios-xe")
	h.restart(t)
	pack := map[string]string{}
	for _, p := range h.core.catalog() {
		pack[p.ID] = p.Pack
	}
	if pack[base.ID] != "" {
		t.Errorf("el que reemplaza a la base debía conservar Pack vacío: %q", pack[base.ID])
	}
	if pack["ios-xe/nuevo-propio"] != playbook.PackUsuario {
		t.Errorf("uno nuevo del usuario debía ser PackUsuario: %q", pack["ios-xe/nuevo-propio"])
	}
}
