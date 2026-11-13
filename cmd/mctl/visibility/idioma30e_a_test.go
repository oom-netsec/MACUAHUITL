package visibility

import (
	"bytes"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
)

const sampleJSON = `{"Time":"2026-11-06T10:00:00Z","System":{"sysName":"SW1"},"CPU":[{"Index":"1","FiveSec":3,"OneMin":2,"FiveMin":1}],"Memory":[{"Name":"proc","UsedPct":41.25}],"Errors":["sin datos"]}`
const flowsJSON = `{"Flows":5,"Bytes":900,"Errors":1,"Talkers":[{"Key":"10.0.0.1","Bytes":900,"Flows":5}],"Conversations":[{"Key":"a-b","Bytes":1,"Flows":1}],"Ports":[{"Key":"443","Bytes":1,"Flows":1}],"Protocols":[{"Key":"tcp","Bytes":1,"Flows":1}],"Exporters":[{"Exporter":"10.0.0.9","Flows":5,"Bytes":900,"Errors":0}],"LastError":"boom"}`

func render(lang string) string {
	cli.SetLang(lang)
	defer cli.SetLang("")
	var b bytes.Buffer
	c := &cli.Env{Out: &b}
	printSample(c, sampleJSON)
	printFlows(c, flowsJSON, true)
	return b.String()
}

func TestMuestrasYFlujosPorIdioma(t *testing.T) {
	for lang, wants := range map[string][]string{
		"": {"  CPU 1: 5 s 3%  1 min 2%  5 min 1%", "  memoria proc: 41.2% usada", "  aviso: sin datos", "5 flujos, 900 bytes, 1 paquetes con error",
			"Conversaciones:", "Puertos:", "Protocolos:", "exportador 10.0.0.9: 5 flujos, 900 bytes, 0 errores", "último error: boom", "B        5 flujos"},
		"en": {"  CPU 1: 5 s 3%  1 min 2%  5 min 1%", "  memory proc: 41.2% used", "  warning: sin datos", "5 flows, 900 bytes, 1 packets with errors",
			"Conversations:", "Ports:", "Protocols:", "exporter 10.0.0.9: 5 flows, 900 bytes, 0 errors", "last error: boom", "B        5 flows"},
	} {
		out := render(lang)
		for _, w := range wants {
			if !strings.Contains(out, w) {
				t.Errorf("lang %q: falta %q en:\n%s", lang, w, out)
			}
		}
	}
}
