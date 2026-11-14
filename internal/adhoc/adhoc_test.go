package adhoc

import (
	"errors"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/capture"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
)

func TestCommandsPasanPorCheckDenied(t *testing.T) {
	ok, err := Commands("show version\n\n! comentario\nshow ip interface brief | include up\n")
	if err != nil || len(ok) != 2 || ok[1] != "show ip interface brief | include up" {
		t.Fatalf("ok = %q, %v", ok, err)
	}
	// Cada uno cambia o escribe algo: el lote entero se rechaza antes de tocar un equipo.
	for _, bad := range []string{
		"configure terminal", "conf t", "reload", "write memory", "wr", "delete flash:x", "clear counters",
		"show version\nconf t", "show run | redirect flash:x", "tclsh", "copy run start", "show version\rreload",
	} {
		if _, err := Commands(bad); !errors.Is(err, playbook.ErrDenied) {
			t.Errorf("%q: err = %v, quería ErrDenied", bad, err)
		}
	}
	if _, err := Commands("  \n! nada\n"); err == nil {
		t.Error("sin comandos debe fallar")
	}
	if _, err := Commands(strings.Repeat("show clock\n", MaxCommands+1)); err == nil {
		t.Error("demasiados comandos debe fallar")
	}
}

func devices() []capture.Device {
	return []capture.Device{
		{Address: "192.0.2.1", Hostname: "SW1", State: "completed", Outputs: map[string]string{"show clock": "10:00:00\n", "show ver | inc up": "SW1 uptime | 3 days\nline2\n"}},
		{Address: "192.0.2.2", Hostname: "SW2", State: "failed", Detail: "tiempo agotado", Outputs: map[string]string{}},
	}
}

func TestBuildTablaConsolidada(t *testing.T) {
	r := Build(devices(), []string{"show clock", "show ver | inc up"})
	if len(r.Rows) != 4 {
		t.Fatalf("filas = %d", len(r.Rows))
	}
	if !r.Rows[0].OK || r.Rows[0].Output != "10:00:00" || r.Rows[2].OK || r.Rows[2].Note != "tiempo agotado" {
		t.Fatalf("rows = %+v", r.Rows)
	}
	csv := r.CSV()
	if !strings.HasPrefix(csv, "equipo,direccion,comando,estado,salida\n") || !strings.Contains(csv, `SW1,192.0.2.1,show clock,ok,10:00:00`) ||
		!strings.Contains(csv, "\"SW1 uptime | 3 days\nline2\"") {
		t.Fatalf("csv = %q", csv)
	}
	md := r.Markdown()
	if !strings.Contains(md, "| SW1 | 192.0.2.1 | `show clock` | ok | 10:00:00 |") || !strings.Contains(md, `SW1 uptime \| 3 days<br>line2`) ||
		!strings.Contains(md, "tiempo agotado") {
		t.Fatalf("md = %q", md)
	}
	txt := r.Text()
	if !strings.Contains(txt, "== SW1 (192.0.2.1) ==") || !strings.Contains(txt, "SIN SALIDA") || !strings.Contains(txt, "2 equipos, 1 con salida completa") {
		t.Fatalf("text = %q", txt)
	}
}

func TestCSVNeutralizaFormulas(t *testing.T) {
	r := Build([]capture.Device{{Address: "a", Hostname: "h", State: "completed", Outputs: map[string]string{"show x": "=HYPERLINK(\"x\")"}}}, []string{"show x"})
	if !strings.Contains(r.CSV(), "'=HYPERLINK") {
		t.Fatalf("csv = %q", r.CSV())
	}
}

func TestCSVNeutralizaTodasLasCeldas(t *testing.T) {
	r := Build([]capture.Device{{Address: "@a", Hostname: "=h", State: "completed", Outputs: map[string]string{"show x": "\rfila", "show y": "\tfila"}}}, []string{"show x", "show y", "-cmd"})
	got := r.CSV()
	for _, want := range []string{"'=h,'@a,show x,ok,\"'\rfila\"", "'=h,'@a,show y,ok,'\tfila", "'-cmd"} {
		if !strings.Contains(got, want) {
			t.Errorf("falta %q en %q", want, got)
		}
	}
}

func TestMarkdownEscapaHTMLYComillas(t *testing.T) {
	r := Build([]capture.Device{{Address: "a<b", Hostname: "h&<img>", State: "completed", Outputs: map[string]string{"show x `y`": "<script>a&b</script>"}}}, []string{"show x `y`"})
	got := r.Markdown()
	for _, bad := range []string{"<script>", "<img>", "a<b", "`y`"} {
		if strings.Contains(got, bad) {
			t.Errorf("sin escapar %q en %q", bad, got)
		}
	}
	for _, want := range []string{"&lt;script&gt;a&amp;b&lt;/script&gt;", "h&amp;&lt;img&gt;", "a&lt;b", "&#96;y&#96;"} {
		if !strings.Contains(got, want) {
			t.Errorf("falta %q en %q", want, got)
		}
	}
}

// Un equipo que terminó bien y no trae el comando lo rechazó; el estado crudo (completed) no va en la nota.
func TestBuildSinSalidaNoMezclaElEstado(t *testing.T) {
	devs := []capture.Device{
		{Hostname: "SW1", Address: "192.0.2.1", State: "completed", Outputs: map[string]string{}},
		{Hostname: "SW2", Address: "192.0.2.2", State: "failed", Outputs: map[string]string{}},
	}
	r := Build(devs, []string{"show environment all"})
	if r.Rows[0].Note != "sin salida (comando inválido en el equipo)" || r.Rows[1].Note != "sin salida (equipo failed)" {
		t.Fatalf("notas = %q, %q", r.Rows[0].Note, r.Rows[1].Note)
	}
}

// Fase 30e: el máximo de comandos es un error con código: es, el de siempre; en, en inglés.
func TestMaximoDeComandosTieneCodigo(t *testing.T) {
	_, err := Commands(strings.Repeat("show version\n", MaxCommands+1))
	const es, en = "adhoc: 51 comandos; el máximo es 50. El tope es de diseño", "adhoc: 51 commands; the maximum is 50. The cap is by design"
	if err == nil || !strings.HasPrefix(err.Error(), es) || !strings.Contains(err.Error(), "divide el lote en tandas de 50 comandos o menos") {
		t.Fatalf("es: %v", err)
	}
	if got := i18n.English(err); !strings.HasPrefix(got, en) || !strings.Contains(got, "split the batch into runs of 50 commands or fewer") {
		t.Fatalf("en: %q", got)
	}
}
