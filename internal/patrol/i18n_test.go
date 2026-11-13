package patrol

import (
	"errors"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
)

// FieldError es un error con código: el español es el de siempre y el inglés sale del catálogo.
func TestFieldErrorEsUnErrorConCodigo(t *testing.T) {
	err := ValidateWith(Spec{}, nil, nil, nil)
	var c i18n.Coded
	if !errors.As(err, &c) {
		t.Fatalf("no es i18n.Coded: %v", err)
	}
	if err.Error() != "patrol: targets: sin equipos" || c.Localize(i18n.En) != "patrol: targets: no devices" || c.Reason() != "patrol.field.no_targets" || c.Metadata()["field"] != "targets" {
		t.Fatalf("%q %q %q %v", err.Error(), c.Localize(i18n.En), c.Reason(), c.Metadata())
	}
	err = ValidateWith(Spec{Targets: []Target{{Address: "192.0.2.1"}}, DefaultCredentialID: "c", WindowHours: 200}, nil, nil, nil)
	if !errors.As(err, &c) || c.Localize(i18n.En) != "patrol: window_hours: must be between 1 and 96, it is 200" || c.Metadata()["n"] != "200" {
		t.Fatalf("%v %v", err, c)
	}
}

// El playbook de otra plataforma se rechaza con código (paso «platform» del Login Test).
func TestPlaybookDeOtraPlataformaTieneCodigo(t *testing.T) {
	pb := []playbook.Playbook{{ID: "x", Platform: "nx-os"}}
	_, _, err := commands(Spec{PlaybookIDs: []string{"x"}}, "ios-xe", pb, nil)
	if err == nil || err.Error() != "patrol: el playbook x es para nx-os y el equipo es ios-xe" || i18n.In(i18n.En, err) != "patrol: playbook x is for nx-os and the device is ios-xe" {
		t.Fatalf("%v", err)
	}
}

// Flota mixta: el playbook elegido corre en su gemelo de la plataforma detectada si existe (ios/x en un IOS clásico,
// ios-xe/x en un IOS-XE); sin gemelo, IOS clásico sigue usando el de ios-xe.
func TestPlaybookGemeloPorPlataforma(t *testing.T) {
	cmd := func(s string) []playbook.Command { return []playbook.Command{{Text: s}} }
	pbs := []playbook.Playbook{{ID: "ios-xe/cpu", Platform: "ios-xe", Commands: cmd("show xe")},
		{ID: "ios/cpu", Platform: "ios", Commands: cmd("show clasico")}, {ID: "ios-xe/solo", Platform: "ios-xe", Commands: cmd("show solo")},
		{ID: "nx-os/cpu", Platform: "nx-os", Commands: cmd("show nx")}}
	for _, c := range []struct{ id, det, want string }{
		{"ios-xe/cpu", "ios", "show clasico"}, {"ios/cpu", "ios-xe", "show xe"}, {"ios-xe/cpu", "ios-xe", "show xe"},
		{"ios/cpu", "ios", "show clasico"}, {"ios-xe/solo", "ios", "show solo"}, {"nx-os/cpu", "nx-os", "show nx"},
	} {
		out, _, err := commands(Spec{PlaybookIDs: []string{c.id}}, c.det, pbs, nil)
		if err != nil || len(out) != 1 || out[0].Text != c.want {
			t.Errorf("%s en %s: %v %v, quiero %q", c.id, c.det, out, err, c.want)
		}
	}
	if _, _, err := commands(Spec{PlaybookIDs: []string{"nx-os/cpu"}}, "ios-xe", pbs, nil); err == nil { // fuera de la familia IOS no hay gemelo
		t.Error("nx-os/cpu en ios-xe debía fallar por plataforma")
	}
}
