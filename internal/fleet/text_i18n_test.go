package fleet

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// spanish encuentra palabras sueltas de español en un texto que ya debe estar en inglés.
var spanish = regexp.MustCompile(`(?i)[áéíóúñ¿¡]|\b(sin|ningún|equipo|equipos|tiene|vecino|saltos?|flota|origen|destino|tabla|rastreo|aparece|solo|bucle|libre|usada|hay|corta|ignora|salida|puerto|ruta a|las|los|del|reinicio|previas|evidencia|sincronizado|una|con|por|para)\b`)

// Con en, cada texto con clave sale en inglés y su clave dice lo mismo que el español; lo demás no se toca.
func TestLocalizarFlotaEnYClaves(t *testing.T) {
	_, ptrs := regCases(t)
	var checked int
	for name, v := range ptrs {
		es := i18n.Localize(v, i18n.Es)
		before, _ := json.Marshal(v)
		for path, tx := range es {
			if tx.Key == "" || tx.In(i18n.Es) == "" {
				t.Errorf("%s %s: clave vacía", name, path)
			}
		}
		keys := i18n.Localize(v, i18n.En)
		if len(keys) != len(es) {
			t.Errorf("%s: %d claves con es y %d con en", name, len(es), len(keys))
		}
		after, _ := json.Marshal(v)
		// "equipo" como kind de inventario es un código cerrado que la vista ya mapea
		if m := spanish.FindString(strings.ReplaceAll(string(after), `"kind":"equipo"`, "")); m != "" {
			t.Errorf("%s: queda español sin clave en el JSON en inglés: %q\n%s", name, m, after)
		}
		if len(es) > 0 && string(before) == string(after) {
			t.Errorf("%s: con en el JSON no cambió", name)
		}
		for _, tx := range keys {
			if m := spanish.FindString(tx.In(i18n.En)); m != "" {
				t.Errorf("%s: español en %q (%s)", name, tx.In(i18n.En), m)
			}
			checked++
		}
	}
	if checked < 40 {
		t.Errorf("solo %d textos con clave revisados", checked)
	}
}

// Cada aviso de un resultado trae su clave (mismo largo y orden) y cada clave rinde el texto en español.
func TestAvisosDeFlotaTodosTienenClave(t *testing.T) {
	_, ptrs := regCases(t)
	for name, v := range ptrs {
		var warn []string
		var tx []i18n.Text
		switch r := v.(type) {
		case *FindResult:
			warn, tx = r.Warnings, r.WarningsTx
		case *TraceResult:
			warn, tx = r.Warnings, r.WarningsTx
		case *PathResult:
			warn, tx = r.Warnings, r.WarningsTx
		case *HealthResult:
			warn, tx = r.Warnings, r.WarningsTx
		case *SummaryResult:
			warn, tx = r.Warnings, r.WarningsTx
		case *CapacityResult:
			warn, tx = r.Warnings, r.WarningsTx
		case *InventoryResult:
			warn, tx = r.Warnings, r.WarningsTx
		default:
			continue
		}
		if len(warn) != len(tx) {
			t.Errorf("%s: %d avisos y %d claves", name, len(warn), len(tx))
			continue
		}
		for i := range warn {
			if tx[i].In(i18n.Es) != warn[i] {
				t.Errorf("%s: aviso %q no coincide con su clave %s: %q", name, warn[i], tx[i].Key, tx[i].In(i18n.Es))
			}
		}
	}
}
