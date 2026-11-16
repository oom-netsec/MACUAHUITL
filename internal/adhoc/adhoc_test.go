package adhoc

import (
	"errors"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/capture"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/mask"
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
	csv := r.CSV(i18n.Es)
	if !strings.HasPrefix(csv, "equipo,direccion,comando,estado,salida\n") || !strings.Contains(csv, `SW1,192.0.2.1,show clock,ok,10:00:00`) ||
		!strings.Contains(csv, "\"SW1 uptime | 3 days\nline2\"") {
		t.Fatalf("csv = %q", csv)
	}
	md := r.Markdown(i18n.Es)
	if !strings.Contains(md, "| SW1 | 192.0.2.1 | `show clock` | ok | 10:00:00 |") || !strings.Contains(md, `SW1 uptime \| 3 days<br>line2`) ||
		!strings.Contains(md, "tiempo agotado") {
		t.Fatalf("md = %q", md)
	}
	txt := r.Text(i18n.Es)
	if !strings.Contains(txt, "== SW1 (192.0.2.1) ==") || !strings.Contains(txt, "SIN SALIDA") || !strings.Contains(txt, "2 equipos, 1 con salida completa") {
		t.Fatalf("text = %q", txt)
	}
	// En inglés, con el plural del catálogo (antes salía en español y con «1 equipos»).
	if en := r.Text(i18n.En); !strings.Contains(en, "NO OUTPUT") || !strings.Contains(en, "2 devices, 1 with complete output") || strings.Contains(en, "equipos") {
		t.Fatalf("text en = %q", en)
	}
	one := Build(devices()[:1], []string{"show clock"})
	if es, en := one.Text(i18n.Es), one.Text(i18n.En); !strings.Contains(es, "1 equipo, 1 con salida completa") || !strings.Contains(en, "1 device, 1 with complete output") {
		t.Fatalf("singular: %q / %q", es, en)
	}
}

func TestCSVNeutralizaFormulas(t *testing.T) {
	r := Build([]capture.Device{{Address: "a", Hostname: "h", State: "completed", Outputs: map[string]string{"show x": "=HYPERLINK(\"x\")"}}}, []string{"show x"})
	if !strings.Contains(r.CSV(i18n.Es), "'=HYPERLINK") {
		t.Fatalf("csv = %q", r.CSV(i18n.Es))
	}
}

func TestCSVNeutralizaTodasLasCeldas(t *testing.T) {
	r := Build([]capture.Device{{Address: "@a", Hostname: "=h", State: "completed", Outputs: map[string]string{"show x": "\rfila", "show y": "\tfila"}}}, []string{"show x", "show y", "-cmd"})
	got := r.CSV(i18n.Es)
	for _, want := range []string{"'=h,'@a,show x,ok,\"'\rfila\"", "'=h,'@a,show y,ok,'\tfila", "'-cmd"} {
		if !strings.Contains(got, want) {
			t.Errorf("falta %q en %q", want, got)
		}
	}
}

func TestMarkdownEscapaHTMLYComillas(t *testing.T) {
	r := Build([]capture.Device{{Address: "a<b", Hostname: "h&<img>", State: "completed", Outputs: map[string]string{"show x `y`": "<script>a&b</script>"}}}, []string{"show x `y`"})
	got := r.Markdown(i18n.Es)
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
	if r.Rows[0].Note != "comando inválido en el equipo" || r.Rows[1].Note != "equipo failed" {
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

// En inglés todo el informe va en inglés: notas, estado, encabezados del CSV y del Markdown. La nota es el motivo
// («command invalid on the device»), sin repetir «no output», que ya dice el estado o la línea de texto.
func TestInformeEnIngles(t *testing.T) {
	devs := []capture.Device{{Address: "192.0.2.1", Hostname: "SW1", State: "completed", Outputs: map[string]string{"show clock": "10:00\n"}},
		{Address: "192.0.2.3", Hostname: "SW3", State: "skipped", Outputs: map[string]string{}}}
	r := Build(devs, []string{"show clock", "show nada"})
	es := r.Text(i18n.Es)
	if !strings.Contains(es, "SIN SALIDA: comando inválido en el equipo") || strings.Contains(es, "SIN SALIDA: sin salida") || !strings.Contains(es, "SIN SALIDA: equipo skipped") {
		t.Fatalf("es = %q", es)
	}
	keys := i18n.Localize(&r, i18n.En)
	if len(keys) == 0 {
		t.Fatal("las notas no llevan texto de catálogo")
	}
	en, csv, md := r.Text(i18n.En), r.CSV(i18n.En), r.Markdown(i18n.En)
	if !strings.Contains(en, "NO OUTPUT: command invalid on the device") || !strings.Contains(en, "NO OUTPUT: device skipped") || strings.Contains(en, "equipo") {
		t.Fatalf("en = %q", en)
	}
	if !strings.HasPrefix(csv, "device,address,command,state,output\n") || !strings.Contains(csv, "no output,command invalid on the device") {
		t.Fatalf("csv en = %q", csv)
	}
	if !strings.HasPrefix(md, "| Device | Address | Command | State | Output |") || !strings.Contains(md, "| no output | command invalid on the device |") {
		t.Fatalf("md en = %q", md)
	}
}

// Un equipo partial muestra lo que sí salió y, en el comando cortado, el detalle del corte (no «inválido»).
func TestBuildEquipoParcial(t *testing.T) {
	d := capture.Device{Address: "a", Hostname: "h", State: "partial", Detail: "1 comando cortado", Cut: []string{"show tcp brief"}, Outputs: map[string]string{"show clock": "10:00"}}
	r := Build([]capture.Device{d}, []string{"show clock", "show tcp brief", "show nada"})
	// solo el cortado lleva el detalle del corte; un comando inválido que no se cortó conserva su nota
	if !r.Rows[0].OK || r.Rows[1].OK || r.Rows[1].Note != "1 comando cortado" || r.Rows[2].Note != "comando inválido en el equipo" {
		t.Fatalf("rows = %+v", r.Rows)
	}
}

// La cabecera de la evidencia y los cortados van pasados por mask.Cmd: el comando personalizado con «password 7 …» sale
// distinto en el disco y Build debe encontrarlo igual (no «comando inválido»).
func TestBuildComandoQueMaskCmdCambia(t *testing.T) {
	const c = "show run | i password 7 0822455D0A16 | count"
	m := mask.Cmd("ios-xe", c)
	if m == c {
		t.Fatalf("mask.Cmd no cambia %q: la prueba no prueba nada", c)
	}
	d := capture.Device{Address: "a", Hostname: "h", Platform: "ios-xe", State: "partial", Detail: "1 comando cortado", Cut: []string{m + "x"},
		Outputs: map[string]string{capture.Key(m): "Number of lines which match regexp = 3"}}
	r := Build([]capture.Device{d}, []string{c})
	if !r.Rows[0].OK {
		t.Fatalf("row = %+v", r.Rows[0])
	}
	d = capture.Device{Address: "a", Hostname: "h", Platform: "ios-xe", State: "partial", Detail: "1 comando cortado", Cut: []string{m}, Outputs: map[string]string{}}
	if r = Build([]capture.Device{d}, []string{c}); r.Rows[0].Note != "1 comando cortado" {
		t.Fatalf("el cortado enmascarado no se reconoce: %+v", r.Rows[0])
	}
}

// Dos comandos del lote que mask.Cmd enmascara igual: la salida guardada bajo la clave enmascarada no se sabe de cuál es,
// así que ninguna de las dos filas la toma (antes la fila A mostraba la salida de B).
func TestBuildClaveEnmascaradaAmbigua(t *testing.T) {
	a, b := "show run | include key 7 0822455D0A16", "show run | include key 7 045802150C2E"
	if mask.Cmd("ios-xe", a) != mask.Cmd("ios-xe", b) {
		t.Fatal("la prueba necesita dos comandos que se enmascaren igual")
	}
	d := capture.Device{Address: "a", Hostname: "h", Platform: "ios-xe", State: "completed", Outputs: map[string]string{capture.Key(mask.Cmd("ios-xe", a)): "salida de B"}}
	r := Build([]capture.Device{d}, []string{a, b})
	for _, row := range r.Rows {
		if row.OK || row.Output != "" || !strings.Contains(row.Note, "ambiguo") {
			t.Fatalf("row = %+v", row)
		}
	}
	// Con un solo comando del lote la clave enmascarada sí vale.
	if r = Build([]capture.Device{d}, []string{a}); !r.Rows[0].OK {
		t.Fatalf("row = %+v", r.Rows[0])
	}
}

// El mismo comando pegado dos veces no es ambiguo: las dos filas toman la misma salida.
func TestBuildComandoRepetidoNoEsAmbiguo(t *testing.T) {
	a := "show run | include key 7 0822455D0A16"
	d := capture.Device{Address: "a", Hostname: "h", Platform: "ios-xe", State: "completed", Outputs: map[string]string{capture.Key(mask.Cmd("ios-xe", a)): "salida"}}
	for _, row := range Build([]capture.Device{d}, []string{a, a}).Rows {
		if !row.OK || row.Output != "salida" {
			t.Fatalf("row = %+v", row)
		}
	}
}
