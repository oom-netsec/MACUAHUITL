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
		"test.l1": {Es: "uno", En: "one"},
		"test.l2": {Es: "dos {n}", En: "two {n}", Args: []string{"n"}},
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
