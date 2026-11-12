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
		// "equipo" (kind de inventario) y "trunk-sin-vecino" (fin del rastreo) son códigos cerrados que la vista ya mapea
		if m := spanish.FindString(strings.NewReplacer(`"kind":"equipo"`, "", `"end":"trunk-sin-vecino"`, "").Replace(string(after))); m != "" {
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

// Si los avisos de carga traen menos textos de catálogo que avisos, ninguno se pierde.
func TestNewWSConservaAvisosSinTexto(t *testing.T) {
	f := &Fleet{Warnings: []string{"uno", "dos", "tres"}, WarnTx: []i18n.Text{i18n.Tx("fleet.warn.system", "error", "uno")}}
	w := f.newWS()
	if len(w.list) != 3 || len(w.txs) != 3 || w.txs[0].Key != "fleet.warn.system" || w.txs[1].In(i18n.Es) != "dos" || w.txs[2].In(i18n.En) != "tres" {
		t.Errorf("%v %v", w.list, w.txs)
	}
}

// Los escenarios de la regresión recorren todas las claves de avisos, motivos, notas y filas de la flota
// (salvo las que ningún dato de prueba alcanza, con su motivo).
func TestEscenariosCubrenTodasLasClavesDeFlota(t *testing.T) {
	_, ptrs := regCases(t)
	used := map[string]bool{}
	for _, v := range ptrs {
		for _, tx := range i18n.Localize(v, i18n.Es) {
			used[tx.Key] = true
		}
	}
	sinDatos := map[string]string{
		"fleet.warn.read_error":       "un error de E/S a mitad de un archivo no se puede fabricar en una prueba portable",
		"fleet.warn.zip_entry":        "una entrada de zip que no abre exige un zip corrupto por dentro",
		"fleet.reason.rec_not_ip":     "el siguiente salto siempre es una IP legible",
		"fleet.reason.rec_no_nexthop": "una ruta sin siguiente salto ni interfaz no sale del parser",
		"fleet.warn.dir_unreadable":   "exige un usuario sin privilegios (se omite si corre como root)",
	}
	for _, prefix := range []string{"fleet.warn.", "fleet.reason.", "fleet.note.", "fleet.value.", "fleet.detail.", "fleet.evidence."} {
		for _, k := range i18n.Codes() {
			if strings.HasPrefix(k, prefix) && !used[k] {
				if _, ok := sinDatos[k]; !ok {
					t.Errorf("ningún escenario de la regresión produce %s", k)
				}
			}
		}
	}
}
