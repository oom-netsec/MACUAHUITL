package cli

import "testing"

func TestStateText(t *testing.T) {
	for in, want := range map[string]string{
		"nuevo": "new", "nueva": "new", "igual": "same", "conflicto": "conflict",
		"conflicto_etiqueta": "label_conflict", "conflicto_id": "id_conflict", "conflicto_nombre": "name_conflict",
		"reservada": "reserved", "fusionar": "merge", "desconocido": "desconocido", "": "",
	} {
		if got := StateText(in); got != want {
			t.Errorf("StateText(%q) = %q; quiero %q", in, got, want)
		}
	}
}

func TestScriptValueWireYText(t *testing.T) {
	pares := [][2]string{{"management", "gestion"}, {"security", "seguridad"}, {"diagnostics", "diagnostico"}, {"other", "otro"}, {"any", "cualquiera"}}
	for _, p := range pares {
		if got := ScriptValueWire(p[0]); got != p[1] {
			t.Errorf("ScriptValueWire(%q) = %q; quiero %q", p[0], got, p[1])
		}
		if got := ScriptValueWire(p[1]); got != p[1] { // el alias en español pasa tal cual
			t.Errorf("ScriptValueWire(%q) = %q; quiero el mismo", p[1], got)
		}
		if got := ScriptValueText(p[1]); got != p[0] {
			t.Errorf("ScriptValueText(%q) = %q; quiero %q", p[1], got, p[0])
		}
		if got := ScriptValueText(p[0]); got != p[0] {
			t.Errorf("ScriptValueText(%q) = %q; quiero el mismo", p[0], got)
		}
	}
	for _, v := range []string{"l2", "l3", "qos", "etherchannel", "wireless", "ios-xe", "", "zzz"} {
		if ScriptValueWire(v) != v || ScriptValueText(v) != v {
			t.Errorf("%q debe pasar tal cual", v)
		}
	}
}

// --tech Management o « security » también se traducen: el usuario no tiene por qué saber que el cable es en minúsculas.
func TestScriptValueWireIgnoraMayusculasYEspacios(t *testing.T) {
	for in, want := range map[string]string{"Management": "gestion", " security ": "seguridad", "ANY": "cualquiera", "IOS-XE": "ios-xe"} {
		if got := ScriptValueWire(in); got != want {
			t.Errorf("ScriptValueWire(%q) = %q, quiero %q", in, got, want)
		}
	}
}
