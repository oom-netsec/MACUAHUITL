package listen

import (
	"errors"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Regresión: el texto en es de cada rechazo de dirección es el de siempre; con en sale traducido y el campo es addr.
func TestValidateAddrTextoEsYEn(t *testing.T) {
	for _, tc := range []struct {
		addr, es, en string
		any          bool
	}{
		{"x", `dirección de escucha inválida "x": address x: missing port in address`, `invalid listen address "x": address x: missing port in address`, false},
		{"1.2.3.4:abc", `puerto inválido "abc"`, `invalid port "abc"`, false},
		{"1.2.3.4:80", "el puerto 80 es privilegiado; escucha en uno alto y, si el equipo no permite cambiar el destino, redirige con nftables (docs/plans/2026-11-04-fase-12-visibilidad.md)", "", false},
		{"host:2055", `el host debe ser una IP local, no "host"`, `the host must be a local IP, not "host"`, false},
		{"0.0.0.0:2055", "escuchar en todas las interfaces requiere pedirlo explícitamente", "listening on all interfaces must be requested explicitly", false},
	} {
		err := ValidateAddr(tc.addr, tc.any)
		var c i18n.Coded
		if err == nil || !errors.As(err, &c) {
			t.Fatalf("%s: %v", tc.addr, err)
		}
		if err.Error() != tc.es {
			t.Errorf("%s: es = %q", tc.addr, err.Error())
		}
		if tc.en != "" && c.Localize(i18n.En) != tc.en {
			t.Errorf("%s: en = %q", tc.addr, c.Localize(i18n.En))
		}
		if c.Reason() != "ingest.invalid" || c.Metadata()["field"] != "addr" {
			t.Errorf("%s: %s %v", tc.addr, c.Reason(), c.Metadata())
		}
	}
}
