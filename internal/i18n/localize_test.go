package i18n

import (
	"errors"
	"testing"
)

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
		"test.wrap": {Es: "línea {line}: {cause}", En: "line {line}: {cause}", Args: []string{"line", "cause"}},
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

func TestWrapYFromErr(t *testing.T) {
	inner := New("test.l2", A("n", 7))
	w := Wrap("test.wrap", inner, A("line", 3))
	if w.Error() != "línea 3: dos 7" || w.Localize(En) != "line 3: two 7" || !errors.Is(w, inner) {
		t.Errorf("wrap: %q %q", w.Error(), w.Localize(En))
	}
	// la causa sin código sale tal cual en los dos idiomas
	plain := Wrap("test.wrap", errors.New("boom"), A("line", 1))
	if plain.Error() != "línea 1: boom" || plain.Localize(En) != "line 1: boom" {
		t.Errorf("sin código: %q %q", plain.Error(), plain.Localize(En))
	}
	if md := w.Metadata(); md["line"] != "3" || md["cause"] != "" {
		t.Errorf("metadata: %v", md)
	}
	tx := FromErr(w)
	if tx.In(Es) != "línea 3: dos 7" || tx.In(En) != "line 3: two 7" || tx.Empty() {
		t.Errorf("FromErr: %q %q", tx.In(Es), tx.In(En))
	}
	if !FromErr(nil).Empty() {
		t.Error("nil está vacío")
	}
}

type base struct {
	Note   string `json:"note"`
	NoteTx Text   `json:"-"`
}

type withEmbed struct {
	base
	Pub
}

type Pub struct {
	Detail   string `json:"detail"`
	DetailTx Text   `json:"-"`
}

type node struct {
	Msg   string `json:"msg"`
	MsgTx Text   `json:"-"`
	Next  *node  `json:"next,omitempty"`
}

// Un campo anónimo sin tag no pone segmento en la ruta (su JSON queda aplanado, así que la ruta también).
func TestLocalizeAnonimosYNoAsignables(t *testing.T) {
	v := &withEmbed{base: base{"a", Tx("test.l1")}, Pub: Pub{"b", Tx("test.l1")}}
	keys := Localize(v, En)
	if _, ok := keys["detail"]; !ok || len(keys) != 2 || keys["note"].Key != "test.l1" || v.Detail != "one" || v.Note != "one" {
		t.Errorf("%v %+v", keys, v)
	}
	// un valor (no puntero) no se puede cambiar: ni claves ni cambios
	l := leaf{Detail: "uno", DetailTx: Tx("test.l1")}
	if k := Localize(l, En); len(k) != 0 || l.Detail != "uno" {
		t.Errorf("valor: %v %q", k, l.Detail)
	}
	val := sample()
	if err := CheckLocalizable(l); err == nil {
		t.Error("un valor con textos no es localizable")
	}
	if err := CheckLocalizable(val); err != nil {
		t.Error(err)
	}
}

func TestLocalizeCicloDePunteros(t *testing.T) {
	a := &node{Msg: "uno", MsgTx: Tx("test.l1")}
	a.Next = a
	keys := Localize(a, En)
	if len(keys) != 1 || a.Msg != "one" {
		t.Errorf("%v %+v", keys, a)
	}
}

func TestCheckLocalizableRechazaMapasEInterfaces(t *testing.T) {
	type conMapa struct {
		M map[string]leaf
		N leaf
	}
	type conIface struct {
		I any
		N leaf
	}
	type sinTextos struct {
		M map[string]string
		I any
	}
	for name, v := range map[string]any{"mapa": &conMapa{}, "interfaz": &conIface{}} {
		if CheckLocalizable(v) == nil {
			t.Errorf("%s con textos debía rechazarse", name)
		}
	}
	if err := CheckLocalizable(&sinTextos{}); err != nil {
		t.Errorf("mapas e interfaces sin textos son datos: %v", err)
	}
}

func BenchmarkLocalizeEsSinTextos(b *testing.B) {
	type row struct {
		A, B string
		N    int
	}
	rows := make([]row, 50000)
	r := &struct{ Rows []row }{rows}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Localize(r, Es)
	}
}

func BenchmarkLocalizeEsConTextos(b *testing.B) {
	rows := make([]leaf, 50000)
	for i := range rows {
		rows[i] = leaf{Detail: "uno", DetailTx: Tx("test.l1")}
	}
	r := &struct{ Rows []leaf }{rows}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Localize(r, Es)
	}
}

// Un tipo que se contiene a sí mismo por puntero se traduce en toda su cadena.
func TestLocalizeListaEnlazada(t *testing.T) {
	a := &node{Msg: "uno", MsgTx: Tx("test.l1")}
	a.Next = &node{Msg: "dos", MsgTx: Tx("test.l1")}
	keys := Localize(a, En)
	if a.Next.Msg != "one" || keys["next.msg"].Key != "test.l1" {
		t.Errorf("%v %+v", keys, a.Next)
	}
}

// Una causa con código aporta su reason y su metadata (la línea) a la metadata del error que la envuelve, y
// KeyArgs trae la causa para la plantilla.
func TestWrapMetadataYKeyArgs(t *testing.T) {
	inner := Wrap("test.wrap", New("test.l2", A("n", 7)), A("line", 3))
	outer := Wrap("test.wrap", inner, A("line", 9))
	md := outer.Metadata()
	if md["line"] != "9" || md["cause_reason"] != "test.wrap" {
		t.Errorf("metadata: %v", md)
	}
	if k, args := FromErr(outer).KeyArgs(); k != "test.wrap" || args["line"] != "9" || args["cause"] != "línea 3: dos 7" {
		t.Errorf("KeyArgs: %q %v", k, args)
	}
	if md := inner.Metadata(); md["cause_reason"] != "test.l2" || md["n"] != "7" {
		t.Errorf("metadata interna: %v", md)
	}
}

func TestUsedKeysIncluyeAnidadosYUniones(t *testing.T) {
	r := &struct {
		T   string `json:"t"`
		TTx Text   `json:"-"`
	}{TTx: Join("; ", Tx("test.l1"), Tx("test.nest", "round", 1).With("title", Tx("test.l2", "n", 1)))}
	u := UsedKeys(r)
	for _, k := range []string{"test.l1", "test.nest", "test.l2"} {
		if !u[k] {
			t.Errorf("falta %s en %v", k, u)
		}
	}
}
