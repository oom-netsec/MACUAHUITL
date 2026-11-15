package change

import (
	"bytes"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
)

const informe = `{"devices":[
 {"address":"10.0.0.1","hostname":"SW1","config_diff":["+ interface Gi0/1 > shutdown","- ntp server 1.1.1.1"]},
 {"address":"10.0.0.2","hostname":"SW2","config_diff":[]}]}`

func TestRenderDiff(t *testing.T) {
	var b bytes.Buffer
	c := &cli.Env{Out: &b}
	if err := printDiff(c, informe, "", false); err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"SW1 (10.0.0.1)", "+ interface Gi0/1 > shutdown", "- ntp server 1.1.1.1", "SW2 (10.0.0.2)"} {
		if !strings.Contains(b.String(), w) {
			t.Errorf("falta %q en:\n%s", w, b.String())
		}
	}
	b.Reset()
	if err := printDiff(c, informe, "10.0.0.2", false); err != nil || strings.Contains(b.String(), "SW1") || !strings.Contains(b.String(), "SW2") {
		t.Fatalf("--device debía dejar solo SW2: %v\n%s", err, b.String())
	}
	b.Reset()
	if err := printDiff(c, informe, "sw1", true); err != nil || !strings.Contains(b.String(), `"hostname":"SW1"`) || strings.Contains(b.String(), "SW2") {
		t.Fatalf("--json filtrado: %v\n%s", err, b.String())
	}
	if err := printDiff(c, informe, "nada", false); err == nil {
		t.Fatal("un --device sin coincidencias debe fallar")
	}
}
