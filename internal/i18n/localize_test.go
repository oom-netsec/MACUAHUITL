package i18n

import "testing"

type leaf struct {
	Detail   string `json:"detail"`
	DetailTx Text   `json:"-"`
	Plain    string `json:"plain"`
}

type root struct {
	Rows     []leaf   `json:"rows"`
	One      *leaf    `json:"one,omitempty"`
	Warnings []string `json:"warnings"`
	// sidecar de lista: misma longitud que Warnings
	WarningsTx []Text `json:"-"`
	skip       leaf
}

func sample() *root {
	r := &root{
		Rows: []leaf{{Detail: "uno", DetailTx: Tx("test.l2", "n", 2)}, {Detail: "sin clave"}},
		One:  &leaf{Detail: "x", DetailTx: Tx("test.l1")},
	}
	r.Warnings = []string{"a", "b"}
	r.WarningsTx = []Text{Tx("test.l1"), {}}
	return r
}

func init() {
	add(map[string]entry{
		"test.l1":   {Es: "uno", En: "one"},
		"test.l2":   {Es: "dos {n}", En: "two {n}", Args: []string{"n"}},
		"test.nest": {Es: "{title} ({round})", En: "{title} ({round})", Args: []string{"title", "round"}},
	})
}

func TestLocalizeEsNoTocaYDaClaves(t *testing.T) {
	r := sample()
	keys := Localize(r, Es)
	if r.Rows[0].Detail != "uno" || r.Warnings[0] != "a" {
		t.Fatalf("es no debe cambiar el texto: %+v", r)
	}
	for _, p := range []string{"rows.0.detail", "one.detail", "warnings.0"} {
		if _, ok := keys[p]; !ok {
			t.Errorf("falta la ruta %s en %v", p, keys)
		}
	}
	if _, ok := keys["rows.1.detail"]; ok {
		t.Error("un texto sin clave no debe aparecer")
	}
	if k := keys["rows.0.detail"]; k.Key != "test.l2" || k.Args["n"] != "2" {
		t.Errorf("clave = %+v", k)
	}
}

func TestLocalizeEnReemplazaSoloLoQueTieneClave(t *testing.T) {
	r := sample()
	Localize(r, En)
	if r.Rows[0].Detail != "two 2" || r.One.Detail != "one" || r.Warnings[0] != "one" {
		t.Errorf("en: %+v", r)
	}
	if r.Rows[1].Detail != "sin clave" || r.Warnings[1] != "b" || r.Rows[0].Plain != "" {
		t.Errorf("lo demás debe quedar igual: %+v", r)
	}
}

func TestTextAnidadoUnionYLiteral(t *testing.T) {
	titulo := Lit("CPU alta", "High CPU")
	if titulo.In(Es) != "CPU alta" || titulo.In(En) != "High CPU" || titulo.Empty() {
		t.Errorf("literal: %q %q", titulo.In(Es), titulo.In(En))
	}
	if sinEn := Lit("solo es", ""); sinEn.In(En) != "solo es" {
		t.Errorf("sin inglés cae al español: %q", sinEn.In(En))
	}
	anidado := Tx("test.nest", "round", 3).With("title", titulo)
	if anidado.In(Es) != "CPU alta (3)" || anidado.In(En) != "High CPU (3)" {
		t.Errorf("anidado: %q %q", anidado.In(Es), anidado.In(En))
	}
	u := Join("; ", Tx("test.l1"), Tx("test.l2", "n", 4))
	if u.In(Es) != "uno; dos 4" || u.In(En) != "one; two 4" || u.Empty() {
		t.Errorf("unión: %q %q", u.In(Es), u.In(En))
	}
	if !Join("; ").Empty() {
		t.Error("una unión sin partes está vacía")
	}
	// solo lo que tiene clave viaja como clave; el literal y la unión solo se traducen
	r := &struct {
		T   string `json:"t"`
		TTx Text   `json:"-"`
	}{T: "CPU alta", TTx: titulo}
	if keys := Localize(r, En); len(keys) != 0 || r.T != "High CPU" {
		t.Errorf("literal: %v %q", keys, r.T)
	}
}
