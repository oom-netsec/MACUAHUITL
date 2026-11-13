package fleet

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Regresión: el CSV y el Markdown del inventario en español son los de antes de la fase 30d.
func TestInventarioCSVMarkdownEspanolRegresion(t *testing.T) {
	r := load(t).Inventory()
	got := map[string]string{"csv": r.CSV(), "markdown": r.Markdown()}
	const file = "testdata/inventario_es.golden.json"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		b, _ := json.MarshalIndent(got, "", " ")
		if err := os.WriteFile(file, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	json.Unmarshal(raw, &want)
	for k, g := range got {
		if g != want[k] || g == "" {
			t.Errorf("%s cambió:\n got: %s\nwant: %s", k, g, want[k])
		}
	}
}

// Con en, el texto de cada informe, el sello de antigüedad, el encabezado y el tipo del CSV/Markdown salen en inglés;
// los datos no cambian. Cubre todos los informes del caso de regresión.
func TestTextoDeFlotaEnIngles(t *testing.T) {
	f := load(t)
	en := f.In("en")
	spanishWords := regexp.MustCompile(`(?i)\b(AVISO|Búsqueda|Rastreo|Camino|vía|ruta|LLEGÓ|CORTE|CABE|libre|usada|usado|hace|ahora|VIEJO|Tablero|Sin alertas|equipos|coincidencia|necesitan|Interfaces con problema|contadores|Puerto de acceso|sin dato)\b`)
	// como el servicio: primero los datos en inglés (Localize) y luego el texto
	loc := func(v any) { i18n.Localize(v, "en") }
	fi, tr, p1, p2, he, su, c1, c2 := f.Find("10.1.10.20"), f.Trace("10.1.10.20"), f.Path("10.1.10.20", "10.1.20.50"), f.Path("10.1.10.20", "172.31.0.1"), f.Health(), f.Summary(), f.Capacity(1<<30), f.Capacity(1<<40)
	for _, v := range []any{&fi, &tr, &p1, &p2, &he, &su, &c1, &c2} {
		loc(v)
	}
	texts := map[string]string{"find": en.FindText(fi), "trace": en.TraceText(tr), "path": en.PathText(p1), "path2": en.PathText(p2),
		"health": en.HealthText(he), "summary": en.SummaryText(su), "cap": en.CapacityText(c1), "capbig": en.CapacityText(c2)}
	for n, tx := range texts {
		if m := spanishWords.FindString(tx); m != "" {
			t.Errorf("%s: queda %q en\n%s", n, m, tx)
		}
	}
	if !strings.Contains(texts["find"], "Search \"10.1.10.20\"") || !strings.Contains(texts["summary"], "Dashboard:") || !strings.Contains(texts["cap"], "Flash: 1.0 GiB needed") && !strings.Contains(texts["cap"], "needed") {
		t.Errorf("faltan encabezados en inglés:\n%s\n%s\n%s", texts["find"], texts["summary"], texts["cap"])
	}
	if s := en.Stamp(now.Add(-30 * time.Hour)); s != "2026-11-04 03:00Z (30 h ago) OLD DATA" {
		t.Errorf("stamp: %q", s)
	}
	if es := f.Stamp(now.Add(-30 * time.Hour)); es != "2026-11-04 03:00Z (hace 30 h) DATO VIEJO" {
		t.Errorf("stamp es: %q", es)
	}
	r := f.Inventory()
	csv, md := r.CSVIn("en"), r.MarkdownIn("en")
	if !strings.HasPrefix(csv, "Device,Type,Name,Description,PID,VID,Serial,Model,Version,Source,Evidence\n") || !strings.Contains(csv, "ACC1,device,") || !strings.Contains(csv, "ACC1,module,") || !strings.Contains(csv, "ACC1,sfp,") {
		t.Errorf("csv en:\n%s", csv)
	}
	if !strings.HasPrefix(md, "| Device | Type |") || strings.Contains(md, "equipo") {
		t.Errorf("md en:\n%s", md)
	}
	if r.CSVIn("es") != r.CSV() || r.MarkdownIn("es") != r.Markdown() {
		t.Error("es debe ser idéntico")
	}
}

// Fase 30d: el tipo del inventario y la fuente «carpeta de Patrol» del texto salen en el idioma pedido; el JSON no cambia.
func TestInventarioYFuenteDelTextoEnIngles(t *testing.T) {
	f := load(t)
	en := f.In("en")
	inv := f.Inventory()
	if txt := en.InventoryText(inv); !strings.Contains(txt, "device") || strings.Contains(txt, "equipo") {
		t.Errorf("inventario en:\n%s", txt)
	}
	r := f.Find("dist1")
	if txt := en.FindText(r); !strings.Contains(txt, "Patrol folder") || strings.Contains(txt, "carpeta de Patrol") {
		t.Errorf("find en:\n%s", txt)
	}
	if txt := f.FindText(r); !strings.Contains(txt, "carpeta de Patrol") {
		t.Errorf("find es:\n%s", txt)
	}
}

// Sin idioma (loc vacío) el tipo sale como en es; un tipo sin traducción sale tal cual.
func TestInvCellsLocVacioYTipoDesconocido(t *testing.T) {
	if got, want := invCells("", InvRow{Kind: "equipo"})[1], invCells(i18n.Es, InvRow{Kind: "equipo"})[1]; got != want {
		t.Errorf("loc vacío: %q, quería %q", got, want)
	}
	if got := invCells("en", InvRow{Kind: "raro"})[1]; got != "raro" {
		t.Errorf("tipo desconocido: %q", got)
	}
}
