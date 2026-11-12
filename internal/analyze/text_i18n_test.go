package analyze

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// spanish encuentra palabras sueltas de español en un texto que ya debe estar en inglés.
var spanish = regexp.MustCompile(`(?i)[áéíóúñ¿¡]|\b(sin|ningún|equipo|equipos|hay|ronda|rondas|línea|líneas|umbral|libre|bajó|desde|hace|arriba|recargó|aviso|evidencia|por qué|qué hacer|hallazgos|veces|cambios|solo|comando|comandos|mensaje|mensajes|del|las|los|una|para|con)\b`)

func labReports(t *testing.T) (Report, DiffReport, DiffReport, TimelineReport) {
	t.Helper()
	b := load(t)
	rep := Analyze(b, rules(t), Options{})
	d12, err := Diff(b, 1, 2, "")
	if err != nil {
		t.Fatal(err)
	}
	d23, err := Diff(b, 2, 3, "")
	if err != nil {
		t.Fatal(err)
	}
	evs, warns := BundleEvents(b, rep.Findings)
	tl := TimelineReport{Dir: b.Dir, Around: time.Date(2026, 11, 4, 10, 9, 18, 0, time.UTC), Window: "30s",
		Events: Timeline(evs, TimelineOptions{}), Warnings: append(append([]Warning{}, b.Warnings...), warns...)}
	return rep, d12, d23, tl
}

// sinKB quita las fichas de la base de mensajes (kb), que son de msgkb y se traducen en otra fase.
func sinKB(j []byte) string {
	return regexp.MustCompile(`"kb":"(\\.|[^"\\])*"`).ReplaceAllString(string(j), "")
}

// cerrados quita los códigos cerrados en español que la fase no migra: la fuente de un evento (log-equipo,
// auditoria), el cambio de un vecino (cambió, apareció, desapareció) y las claves de vecino y grupo HSRP.
func cerrados(s string) string {
	s = regexp.MustCompile(`"rule":"[^"]*"`).ReplaceAllString(s, "") // el id de la regla es un código estable
	return strings.NewReplacer("log-equipo", "", "auditoria", "", "cambió", "", "apareció", "", "desapareció", "", " por ", " ", " grupo ", " ").Replace(s)
}

func TestLocalizarAnalisisEn(t *testing.T) {
	rep, d12, d23, tl := labReports(t)
	for name, v := range map[string]any{"analyze": &rep, "diff12": &d12, "diff23": &d23, "timeline": &tl} {
		before, _ := json.Marshal(v)
		es := i18n.Localize(v, i18n.Es)
		if mid, _ := json.Marshal(v); string(mid) != string(before) {
			t.Fatalf("%s: con es el JSON cambió", name)
		}
		i18n.Localize(v, i18n.En)
		after, _ := json.Marshal(v)
		if len(es) > 0 && string(after) == string(before) {
			t.Errorf("%s: con en el JSON no cambió", name)
		}
		if m := spanish.FindString(cerrados(sinKB(after))); m != "" {
			t.Errorf("%s: queda español en el JSON en inglés (%q):\n%s", name, m, after)
		}
		for path, tx := range es {
			if tx.In(i18n.Es) == "" {
				t.Errorf("%s %s: clave vacía", name, path)
			}
		}
	}
	// el texto en inglés tampoco deja español
	rep, d12, _, tl = labReports(t)
	i18n.Localize(&rep, i18n.En)
	i18n.Localize(&d12, i18n.En)
	i18n.Localize(&tl, i18n.En)
	for name, txt := range map[string]string{"analyze": rep.TextIn(i18n.En), "diff": d12.TextIn(i18n.En), "timeline": tl.TextIn(i18n.En)} {
		for _, ln := range strings.Split(txt, "\n") {
			if i := strings.Index(ln, "  ["); i > 0 && strings.HasSuffix(ln, "]") {
				ln = ln[:i] // ficha de msgkb
			}
			if m := spanish.FindString(cerrados(ln)); m != "" {
				t.Errorf("%s: español en %q (%s)", name, ln, m)
			}
		}
	}
}

// El español no cambia: cada texto con clave rinde exactamente el que está en el JSON.
func TestClavesDeAnalisisCoincidenConElEspañol(t *testing.T) {
	rep, d12, _, tl := labReports(t)
	var n int
	for _, v := range []any{&rep, &d12, &tl} {
		raw, _ := json.Marshal(v)
		var doc any
		json.Unmarshal(raw, &doc)
		for path, tx := range i18n.Localize(v, i18n.Es) {
			cur := doc
			for _, p := range strings.Split(path, ".") {
				switch x := cur.(type) {
				case map[string]any:
					cur = x[p]
				case []any:
					var i int
					for _, c := range p {
						i = i*10 + int(c-'0')
					}
					cur = x[i]
				}
			}
			if cur != tx.In(i18n.Es) {
				t.Errorf("%s: json %q, clave %s da %q", path, cur, tx.Key, tx.In(i18n.Es))
			}
			n++
		}
	}
	if n == 0 {
		t.Error("ninguna clave")
	}
}

func TestReglasPorDefectoTienenInglés(t *testing.T) {
	for _, r := range rules(t) {
		if r.TitleEn == "" || r.ExplanationEn == "" || r.ActionEn == "" {
			t.Errorf("%s: falta title_en, explanation_en o action_en", r.ID)
		}
		if m := spanish.FindString(r.TitleEn + " " + r.ExplanationEn + " " + r.ActionEn); m != "" {
			t.Errorf("%s: español en el inglés (%s)", r.ID, m)
		}
	}
}

// Las frases que los datos de prueba no alcanzan: el español del catálogo es el texto de antes de la fase, y
// con en sale sin español.
func TestFrasesDeAnalisisFueraDeLosDatosDePrueba(t *testing.T) {
	for _, c := range []struct {
		tx   i18n.Text
		es   string
		want string // el inglés
	}{
		{i18n.Tx("analyze.detail.stp_changes", "name", "VLAN0010", "n", 4), "VLAN0010: 4 cambios", "VLAN0010: 4 changes"},
		{i18n.Tx("analyze.warn.format"), "formato inesperado: sin datos para esta regla", "unexpected format: no data for this rule"},
		{i18n.Tx("analyze.warn.format_missing", "what", "uptime is"), `formato inesperado: sin datos para esta regla (falta "uptime is")`, `unexpected format: no data for this rule ("uptime is" is missing)`},
		{i18n.Tx("analyze.warn.format_no_pool"), "formato inesperado: sin datos para esta regla (falta el pool Processor)", "unexpected format: no data for this rule (the Processor pool is missing)"},
		{i18n.Tx("analyze.warn.format_no_ifaces"), "formato inesperado: sin datos para esta regla (ninguna interfaz reconocida)", "unexpected format: no data for this rule (no interface recognized)"},
		{i18n.Tx("analyze.warn.format_no_nbrs"), "formato inesperado: sin datos para esta regla (falta la tabla de vecinos)", "unexpected format: no data for this rule (the neighbor table is missing)"},
		{i18n.Tx("analyze.warn.format_no_groups"), "formato inesperado: sin datos para esta regla (falta la tabla de grupos)", "unexpected format: no data for this rule (the group table is missing)"},
		{i18n.Tx("analyze.warn.rejected"), "el equipo rechazó el comando; sin datos para las reglas que lo usan", "the device rejected the command; no data for the rules that use it"},
		{i18n.Tx("analyze.warn.over_total", "mib", 512), "el paquete supera el tope de 512 MiB descomprimidos: se leyó parcialmente y los hallazgos pueden estar incompletos (usa --round o --device)", "the package exceeds the 512 MiB uncompressed limit: it was read partially and the findings may be incomplete (use --round or --device)"},
		{i18n.Tx("analyze.warn.trimmed", "bytes", 100), "salida recortada a 100 bytes", "output trimmed to 100 bytes"},
		{i18n.Tx("analyze.warn.no_outputs", "from", 1, "to", 2), "sin salidas en la ronda 1 o 2", "no outputs in round 1 or 2"},
		{i18n.Tx("analyze.warn.uptime_stamps", "n", 3), "3 mensaje(s) con marca de uptime, sin hora absoluta: se omiten (configura service timestamps log datetime msec)", "3 messages with an uptime stamp and no absolute time: omitted (configure service timestamps log datetime msec)"},
		{i18n.Tx("analyze.warn.log_no_zone"), "hora del log sin referencia de zona: sin show clock detail se toma como UTC (recolecta show clock detail o usa show-timezone)", "log time has no timezone reference: without show clock detail it is taken as UTC (collect show clock detail or use show-timezone)"},
		{i18n.Tx("analyze.warn.syslog_bad_lines", "name", "a.log", "n", 2), "a.log: 2 línea(s) sin el formato del receptor syslog", "a.log: 2 lines not in the syslog receiver format"},
		{i18n.Tx("analyze.warn.syslog_cap", "mib", 64, "file", "a.log"), "syslog: tope de 64 MiB leído; el resto de a.log y los archivos siguientes se omiten", "syslog: 64 MiB limit read; the rest of a.log and the following files are omitted"},
		{i18n.Tx("analyze.warn.audit", "error", "x"), "auditoría: x", "audit: x"},
		{i18n.Tx("analyze.event.by", "actor", "ana"), "por ana", "by ana"},
		{i18n.Tx("analyze.event.local_to_utc", "offset", "-06:00"), "hora local del equipo pasada a UTC con show clock detail (desfase -06:00)", "device local time converted to UTC with show clock detail (offset -06:00)"},
		{i18n.Tx("analyze.event.local_raw", "zone", "CST"), "hora local del equipo (CST), sin convertir a UTC", "device local time (CST), not converted to UTC"},
		{i18n.Tx("analyze.event.rst", "client", "a", "server", "b"), "RST a → b", "RST a → b"},
		{i18n.Tx("analyze.event.retransmit", "client", "a", "server", "b"), "retransmisión a → b", "retransmission a → b"},
		{i18n.Tx("analyze.event.dns_slow", "name", "x.com", "type", "A", "latency", "2s", "client", "a", "server", "b"), "DNS lento x.com A (2s) a → b", "slow DNS x.com A (2s) a → b"},
		{i18n.Tx("analyze.event.dns_error", "rcode", "NXDOMAIN", "name", "x.com", "type", "A"), "DNS NXDOMAIN x.com A", "DNS NXDOMAIN x.com A"},
		{i18n.Tx("analyze.event.dns_none", "name", "x.com", "type", "A", "client", "a", "server", "b"), "DNS sin respuesta x.com A a → b", "DNS unanswered x.com A a → b"},
		{i18n.Tx("analyze.event.icmp_unreach", "code", 3, "from", "a", "target", "b"), "ICMP inalcanzable (código 3) de a para b", "ICMP unreachable (code 3) from a for b"},
		{i18n.Tx("analyze.event.icmp_ttl", "from", "a", "target", "b"), "ICMP TTL excedido de a para b", "ICMP TTL exceeded from a for b"},
		{i18n.Tx("analyze.diff.only_in", "round", 2), "solo en la ronda 2", "only in round 2"},
		{i18n.Tx("analyze.diff.too_big", "a", 9, "b", 8), "demasiado distinto para comparar línea a línea (9 contra 8 líneas)", "too different to compare line by line (9 against 8 lines)"},
		{i18n.Tx("analyze.diff.more_lines", "n", 5), "5 líneas más sin mostrar", "5 more lines not shown"},
	} {
		if got := c.tx.In(i18n.Es); got != c.es {
			t.Errorf("%s en español: %q, quería %q", c.tx.Key, got, c.es)
		}
		if got := c.tx.In(i18n.En); got != c.want {
			t.Errorf("%s en inglés: %q, quería %q", c.tx.Key, got, c.want)
		}
	}
}
