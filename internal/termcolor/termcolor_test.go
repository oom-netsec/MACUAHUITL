package termcolor

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestClassifyCases(t *testing.T) {
	b, _ := os.ReadFile("cases.json")
	var cases []struct {
		Line  string
		Spans [][2]string
	}
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		var got [][2]string
		for _, s := range Classify(c.Line) {
			got = append(got, [2]string{c.Line[s.Start:s.End], s.Cat})
		}
		if len(got) != len(c.Spans) {
			t.Errorf("%q: %v, quería %v", c.Line, got, c.Spans)
			continue
		}
		for i := range got {
			if got[i] != c.Spans[i] {
				t.Errorf("%q: %v, quería %v", c.Line, got, c.Spans)
			}
		}
	}
}

func TestPalettesCoverAllCategories(t *testing.T) {
	// Las categorías salen de las reglas (más las de severidad syslog): una categoría nueva sin color falla aquí.
	need := []string{"ok", "bad", "warn", "info", "dim"}
	for _, c := range cats {
		if c != "mnem" {
			need = append(need, c)
		}
	}
	for _, p := range palettes {
		for _, c := range need {
			if p.Cats[c] == "" {
				t.Errorf("paleta %s sin %s", p.ID, c)
			}
		}
	}
	if len(palettes) < 5 {
		t.Fatal("faltan paletas")
	}
}

func TestColorizeKeepsTextAndSetsColor(t *testing.T) {
	in := "Gi1/0/1 is up\nsin color"
	for _, tc := range []bool{false, true} {
		out := Colorize(in, Lookup("p1"), tc)
		if strip(out) != in {
			t.Fatalf("texto alterado: %q", out)
		}
		if !strings.Contains(out, "\x1b[") {
			t.Fatal("sin ANSI")
		}
	}
	if !strings.Contains(Colorize("up", Lookup("p1"), true), "\x1b[38;2;") {
		t.Fatal("sin truecolor")
	}
	if strings.Contains(Colorize("up", Lookup("p1"), false), "38;2") {
		t.Fatal("truecolor sin pedirlo")
	}
	if Colorize("nada", Lookup("p1"), false) != "nada" {
		t.Fatal("línea sin tramos debe quedar intacta")
	}
}

func strip(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func TestEnabledRespectsNoColorAndFlags(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for _, c := range []struct {
		tty, flag, json bool
		env             map[string]string
		want            bool
	}{
		{true, false, false, nil, true},
		{false, false, false, nil, false},
		{true, true, false, nil, false},
		{true, false, true, nil, false},
		{true, false, false, map[string]string{"NO_COLOR": "1"}, false},
		{true, false, false, map[string]string{"TERM": "dumb"}, false},
	} {
		if got := Enabled(c.tty, c.flag, c.json, env(c.env)); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
	if !Truecolor(env(map[string]string{"COLORTERM": "truecolor"})) || Truecolor(env(nil)) {
		t.Fatal("COLORTERM")
	}
}

func TestPrefsFromJSON(t *testing.T) {
	// Un campo antiguo no reconocido se ignora sin romper la lectura.
	if p := PrefsFromJSON(`{"palette":"p3","crt":true}`); p != "p3" {
		t.Fatal(p)
	}
	if p := PrefsFromJSON(`basura`); p != DefaultPalette {
		t.Fatal(p)
	}
	if p := PrefsFromJSON(`{"palette":"inexistente"}`); p != DefaultPalette {
		t.Fatal(p)
	}
}

func TestPrefsFromJSONIdsAntiguos(t *testing.T) {
	for old, want := range map[string]string{"securecrt-dark": "consola-oscura", "securecrt-light": "consola-clara"} {
		if p := PrefsFromJSON(`{"palette":"` + old + `"}`); p != want {
			t.Fatal(old, p)
		}
	}
}
