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
