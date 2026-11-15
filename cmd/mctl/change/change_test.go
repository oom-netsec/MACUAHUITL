package change

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// listaFalsa devuelve en cada consulta el siguiente estado de la captura PRE.
type listaFalsa struct {
	estados []string
	n       int
}

func (l *listaFalsa) list(context.Context) (*v1.ListChangesResponse, error) {
	s := l.estados[min(l.n, len(l.estados)-1)]
	l.n++
	return &v1.ListChangesResponse{Changes: []*v1.ChangeSummary{{ChangeId: "c1", PreJobId: "j1", PreState: s}}}, nil
}

func TestEsperarCaptura(t *testing.T) {
	pre := v1.ChangePhase_CHANGE_PHASE_PRE
	l := &listaFalsa{estados: []string{"armed", "armed", "completed"}}
	if err := waitCapture(context.Background(), l.list, "c1", pre, time.Millisecond); err != nil || l.n != 3 {
		t.Fatalf("debía esperar hasta completed: err=%v consultas=%d", err, l.n)
	}
	for _, mal := range []string{"failed", "cancelled"} {
		l := &listaFalsa{estados: []string{"armed", mal}}
		if err := waitCapture(context.Background(), l.list, "c1", pre, time.Millisecond); err == nil || !strings.Contains(err.Error(), mal) {
			t.Fatalf("%s debía fallar diciendo el estado: %v", mal, err)
		}
	}
}

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
