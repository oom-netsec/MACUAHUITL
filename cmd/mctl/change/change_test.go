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

// Un trabajo completed puede traer equipos que fallaron: la espera lo dice y nombra el equipo.
func TestRevisarEquipos(t *testing.T) {
	ok := &v1.RunDevice{Target: &v1.Target{Address: "10.0.0.1"}, State: v1.DeviceState_DEVICE_STATE_COMPLETED}
	mal := &v1.RunDevice{Target: &v1.Target{Address: "10.0.0.2"}, State: v1.DeviceState_DEVICE_STATE_FAILED, Detail: "timeout"}
	if err := checkDevices("pre", []*v1.RunDevice{ok}); err != nil {
		t.Fatalf("todo bien no debe fallar: %v", err)
	}
	err := checkDevices("pre", []*v1.RunDevice{ok, mal})
	if err == nil || !strings.Contains(err.Error(), "10.0.0.2") || strings.Contains(err.Error(), "10.0.0.1") || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("debía nombrar solo al equipo fallido: %v", err)
	}
	part := &v1.RunDevice{Target: &v1.Target{Address: "10.0.0.4"}, State: v1.DeviceState_DEVICE_STATE_PARTIAL, CutCommands: 1}
	if err := checkDevices("pre", []*v1.RunDevice{ok, part}); err != nil || partialDevices([]*v1.RunDevice{ok, part}) != "10.0.0.4" {
		t.Fatalf("un equipo parcial no es falla y se avisa: %v", err)
	}
	skip := &v1.RunDevice{Target: &v1.Target{Address: "10.0.0.3"}, State: v1.DeviceState_DEVICE_STATE_SKIPPED}
	if err := checkDevices("post", []*v1.RunDevice{ok, skip}); err != nil {
		t.Fatalf("un equipo excluido a propósito no es falla: %v", err)
	}
}

const informeSinCaptura = `{"devices":[
 {"address":"10.0.0.1","hostname":"SW1","config_diff":[],"findings":[{"facet":"captura","level":"regression","detail":"no está en la captura POST"}]},
 {"address":"10.0.0.2","hostname":"SW2","config_diff":[],"findings":[]}]}`

func TestDiffSinCaptura(t *testing.T) {
	var b bytes.Buffer
	err := printDiff(&cli.Env{Out: &b}, informeSinCaptura, "", false)
	if err == nil {
		t.Fatal("un equipo sin captura debe dar código distinto de 0")
	}
	out := b.String()
	if !strings.Contains(out, "SW1") || !strings.Contains(out, "no está en la captura POST") || strings.Contains(out[:strings.Index(out, "SW2")], cli.T("mctl.change.diff_none")) {
		t.Fatalf("SW1 no debe decir «sin diferencias»:\n%s", out)
	}
	if !strings.Contains(out, "SW2") || !strings.Contains(out, cli.T("mctl.change.diff_none")) {
		t.Fatalf("SW2 sí:\n%s", out)
	}
}

func TestDiffDeviceExacto(t *testing.T) {
	rep := `{"devices":[{"address":"10.0.0.1","hostname":"SW1","config_diff":[]},{"address":"10.0.0.10","hostname":"CORE","config_diff":[]}]}`
	var b bytes.Buffer
	if err := printDiff(&cli.Env{Out: &b}, rep, "10.0.0.1", false); err != nil || strings.Contains(b.String(), "CORE") {
		t.Fatalf("10.0.0.1 no debe traer 10.0.0.10: %v\n%s", err, b.String())
	}
}

func TestHostOnly(t *testing.T) {
	for in, want := range map[string]string{"10.0.0.1:2222": "10.0.0.1", "10.0.0.1": "10.0.0.1", "[2001:db8::1]:22": "2001:db8::1", "2001:db8::1": "2001:db8::1", "sw1:22": "sw1"} {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, quiero %q", in, got, want)
		}
	}
}

// Si alguna captura se recogió sin enmascarar, el diff lo dice antes de los equipos y lo conserva en --json.
func TestDiffAvisaSinEnmascarar(t *testing.T) {
	var b bytes.Buffer
	c := &cli.Env{Out: &b}
	if err := printDiff(c, informe, "", false); err != nil || strings.Contains(b.String(), cli.T("evidence.unmasked")) {
		t.Fatalf("avisó sin motivo: %v\n%s", err, b.String())
	}
	sin := strings.Replace(informe, `{"devices"`, `{"unmasked":true,"devices"`, 1)
	b.Reset()
	if err := printDiff(c, sin, "", false); err != nil || !strings.HasPrefix(b.String(), cli.T("drift.text.warning", "message", cli.T("evidence.unmasked"))) {
		t.Fatalf("falta el aviso al inicio: %v\n%s", err, b.String())
	}
	b.Reset()
	if err := printDiff(c, sin, "sw1", true); err != nil || !strings.Contains(b.String(), `"unmasked":true`) {
		t.Fatalf("--json sin unmasked: %v\n%s", err, b.String())
	}
}
