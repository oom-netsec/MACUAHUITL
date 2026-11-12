package analyze

// Adaptadores sobre internal/parse/iosxe (ADR 0008): los parsers viven allá;
// aquí solo queda la forma que piden las reglas y el diff.

import (
	"regexp"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

func lines(text string) []string { return strings.Split(strings.TrimRight(text, "\n"), "\n") }

// ospfHeaderRe localiza el encabezado de la tabla para citarlo como evidencia.
var ospfHeaderRe = regexp.MustCompile(`^Neighbor ID\s+Pri\s+State`)

func ospfKey(n iosxe.OSPFNeighbor) string { return n.ID + " por " + n.Interface }
func hsrpKey(g iosxe.HSRPGroup) string    { return g.Interface + " grupo " + g.Group }

// CounterNames son los contadores que entiende iface_counter y el diff.
var CounterNames = []string{"crc", "input_errors", "output_errors", "output_drops", "input_drops", "resets"}

type ifaceCounters struct {
	Name   string
	Values map[string]int64
	Lines  map[string]string
}

// parseInterfaces presenta show interfaces como contadores por nombre; solo
// están los que la salida trajo (un contador ausente no es un cero).
func parseInterfaces(text string) ([]ifaceCounters, bool) {
	ifs, ok := iosxe.ParseInterfaces(text)
	var out []ifaceCounters
	for _, i := range ifs {
		c := ifaceCounters{Name: i.Raw, Values: map[string]int64{}, Lines: map[string]string{}}
		for name, v := range map[string]struct {
			key string
			n   int64
		}{
			"crc": {"crc", i.CRC}, "input_errors": {"input_errors", i.InErrors}, "output_errors": {"output_errors", i.OutErrors},
			"output_drops": {"drops", i.OutDrops}, "input_drops": {"input_drops", i.InDrops}, "resets": {"resets", i.Resets},
		} {
			if ln, ok := i.Evidence[v.key]; ok {
				c.Values[name], c.Lines[name] = v.n, ln
			}
		}
		out = append(out, c)
	}
	return out, ok
}

type uptimeInfo struct {
	D       time.Duration
	Line    string
	Reasons []string
}

// parseUptime solo da ok si la línea "uptime is" trae alguna unidad de tiempo.
func parseUptime(text string) (uptimeInfo, bool) {
	v, ok := iosxe.ParseVersion(text)
	if !ok || !v.UptimeKnown {
		return uptimeInfo{}, false
	}
	return uptimeInfo{D: v.Uptime, Line: v.UptimeLine, Reasons: v.Reasons}, true
}
