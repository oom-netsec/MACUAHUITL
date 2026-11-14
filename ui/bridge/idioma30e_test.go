package bridge

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// Fase 30e: las validaciones propias del puente salen en el idioma de la app; con es las de siempre; sin Localize, inglés.
func TestValidacionesDelPuenteEsYEn(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "a.txt")
	cases := []struct {
		name, es, en string
		call         func(b *Bridge) error
	}{
		{"ronda", "ronda -1 inválida", "invalid round -1", func(b *Bridge) error { _, e := b.DriftRun("j", -1, ""); return e }},
		{"rondas", "rondas 0 y 2 inválidas", "invalid rounds 0 and 2", func(b *Bridge) error { _, e := b.AnalysisDiff("j", 0, 2, ""); return e }},
		{"instante", `instante "x" inválido: usa RFC 3339 (2026-11-04T10:09:18Z)`, `invalid instant "x": use RFC 3339 (2026-11-04T10:09:18Z)`,
			func(b *Bridge) error { _, e := b.AnalysisTimeline("j", "x", 0, "", ""); return e }},
		{"fase", `fase "x" desconocida`, `unknown phase "x"`, func(b *Bridge) error { _, e := b.ChangeCapture("c", "x", nil, nil); return e }},
		{"calculadora", `calculadora "x" desconocida`, `unknown calculator "x"`, func(b *Bridge) error { _, e := b.Calc("x", "{}"); return e }},
		{"umbral", "umbral inválido", "invalid threshold", func(b *Bridge) error { _, e := b.ForensicLeaks("j", "", -1, 0); return e }},
		{"guardar ruta", "guardar: la ruta debe ser absoluta", "save: the path must be absolute", func(b *Bridge) error { return b.WriteFile("r.txt", "x", "utf8", false) }},
		{"guardar codificación", `guardar: codificación "x" desconocida`, `save: unknown encoding "x"`, func(b *Bridge) error { return b.WriteFile(abs, "x", "x", false) }},
		{"herramienta", `herramienta "x" desconocida`, `unknown tool "x"`, func(b *Bridge) error { _, e := b.DiagRun("x", nil, nil); return e }},
		{"ejecución", `ejecución "x" no existe o ya terminó`, `run "x" does not exist or has already finished`, func(b *Bridge) error { return b.DiagCancel("x") }},
		{"puerto", "puerto 70000 inválido", "invalid port 70000", func(b *Bridge) error { _, e := b.SnmpGet(SnmpTargetDTO{Host: "h", Port: 70000}, nil); return e }},
		{"fuera de rango", "ratePerSource fuera de rango: 4294967396", "ratePerSource out of range: 4294967396",
			func(b *Bridge) error {
				_, e := b.SyslogStart("127.0.0.1:0", "udp", false, false, SyslogOptions{RatePerSource: 4294967396})
				return e
			}},
		{"consola", `consola "x" no existe o ya terminó`, `console "x" does not exist or has already finished`, func(b *Bridge) error { return b.ConsoleSend("x", "y") }},
		{"ruta absoluta", "la ruta debe ser absoluta", "the path must be absolute", func(b *Bridge) error { return b.RemoveEmptyFile("r") }},
	}
	for _, c := range cases {
		for _, loc := range []struct {
			lang     string
			localize bool
			want     string
		}{{"es", true, c.es}, {"en", false, c.en}, {"en", true, c.en}} {
			if !loc.localize { // sin Localize el puente no manda idioma: sale el de omisión, inglés
				prev := i18n.SetDefault(i18n.En)
				t.Cleanup(func() { i18n.SetDefault(prev) })
			}
			b, _ := i18nBridge(t, loc.lang, loc.localize)
			err := c.call(b)
			if err == nil || err.Error() != loc.want {
				t.Errorf("%s %s/%v: %v, quería %q", c.name, loc.lang, loc.localize, err, loc.want)
			}
		}
	}
}

// Sin núcleo, con el idioma ya leído, «núcleo desconectado» sale en inglés; errors.Is sigue valiendo.
func TestDesconectadoEnIngles(t *testing.T) {
	b, _ := i18nBridge(t, "en", true)
	if b.language() != "en" { // lee y guarda el idioma
		t.Fatal("no leyó el idioma")
	}
	b.conn = nil
	b.dial = func() (*ipc.ClientConn, error) { return nil, errors.New("sin socket") }
	_, err := b.GetPreference("terminal")
	if !errors.Is(err, ErrDisconnected) || err.Error() != "core disconnected" {
		t.Fatalf("%v", err)
	}
}
