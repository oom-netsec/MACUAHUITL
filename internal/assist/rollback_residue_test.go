package assist

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// QA 3560CX: el equipo agrega solo «spanning-tree portfast edge» al aplicar y la reversa no lo quita. Eso no es «revertido»:
// la ejecución se detiene con las líneas que sobran y el equipo sigue entre los cambiados.
func TestRollbackLeavingResidueIsNotRolledBack(t *testing.T) {
	const cmd = "show running-config interface GigabitEthernet1/0/1"
	base := "Building configuration...\n!\ninterface GigabitEthernet1/0/1\n switchport access vlan 10\nend"
	var mu sync.Mutex
	cur := base
	ex := &fakeExec{}
	ex.onConfigure = func(_ string, lines []string) {
		mu.Lock()
		defer mu.Unlock()
		vlan := strings.TrimPrefix(lines[len(lines)-1], "switchport access vlan ")
		cur = "interface GigabitEthernet1/0/1\n switchport access vlan " + vlan + "\n spanning-tree portfast edge\nend"
	}
	ex.readFunc = func(string, string) string { mu.Lock(); defer mu.Unlock(); return cur }
	p := okPlan()
	p.Devices[0].Baseline = map[string]string{cmd: base}
	r, _ := newRun(t, p, ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "close")
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "rollback-1")
	r.Confirm("rollback-1")
	wait(t, r, Failed)
	sn := r.Snapshot()
	if !strings.Contains(sn.Reason, "sobra «spanning-tree portfast edge»") || len(sn.Changed) != 1 || !sn.CanRollback {
		t.Fatalf("%+v", sn)
	}
	if !strings.Contains(sn.ReasonEN, `extra "spanning-tree portfast edge"`) || strings.Contains(sn.ReasonEN, "sobra") {
		t.Fatalf("motivo en inglés: %q", sn.ReasonEN)
	}
	// Reintentar no lo toma por un cambio ajeno: manda la reversa otra vez y vuelve a avisar.
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "rollback-1")
	r.Confirm("rollback-1")
	wait(t, r, Failed)
	if ex.count("cfg SW1: switchport access vlan 10") != 2 || !strings.Contains(r.FailReason(), "sobra") {
		t.Fatalf("reversas %d, motivo %q", ex.count("cfg SW1: switchport access vlan 10"), r.FailReason())
	}
	r.Abort()
	wait(t, r, Aborted)
	if len(r.Changed()) != 1 {
		t.Fatalf("cambiados %v", r.Changed())
	}
}

// El orden de las líneas y lo volátil no cuentan como residuo; lo que falta sí.
func TestResidueDiff(t *testing.T) {
	base := "Building configuration...\nCurrent configuration : 120 bytes\n!\ninterface Gi1\n description a\n shutdown\ninterface Gi2\n shutdown\nend"
	same := "!\ninterface Gi2\n shutdown\ninterface Gi1\n shutdown\n description a\nend"
	if d := residue(base, same); d != "" {
		t.Fatalf("diferencia %q", d)
	}
	// Un « shutdown» de otra interfaz no tapa el que falta.
	got := residue(base, "interface Gi1\n description a\n shutdown\ninterface Gi2\n spanning-tree portfast edge\nend")
	if !strings.Contains(got, "sobra «spanning-tree portfast edge» en interface Gi2") || !strings.Contains(got, "falta «shutdown» en interface Gi2") {
		t.Fatalf("diferencia %q", got)
	}
}

// residueDevice es un equipo cuyo running-config de Gi1/0/1 lleva la VLAN de la última línea mandada y, tras el primer
// cambio, el portfast que IOS agrega solo. set reemplaza a mano lo que muestra.
type residueDevice struct {
	mu  sync.Mutex
	cur string
}

const residueBase = "Building configuration...\n!\ninterface GigabitEthernet1/0/1\n switchport access vlan 10\nend"

func (d *residueDevice) set(s string) { d.mu.Lock(); d.cur = s; d.mu.Unlock() }

func residueRun(t *testing.T) (*Run, *fakeExec, *residueDevice) {
	t.Helper()
	d := &residueDevice{cur: residueBase}
	ex := &fakeExec{}
	ex.onConfigure = func(_ string, lines []string) {
		vlan := strings.TrimPrefix(lines[len(lines)-1], "switchport access vlan ")
		d.set("interface GigabitEthernet1/0/1\n switchport access vlan " + vlan + "\n spanning-tree portfast edge\nend")
	}
	ex.readFunc = func(string, string) string { d.mu.Lock(); defer d.mu.Unlock(); return d.cur }
	p := okPlan()
	p.Devices[0].Baseline = map[string]string{"show running-config interface GigabitEthernet1/0/1": residueBase}
	r, _ := newRun(t, p, ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "close")
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "rollback-1")
	return r, ex, d
}

// Revisión 2: si el ingeniero quita a mano lo que sobró, el reintento ve el equipo en su línea base y lo cuenta como revertido
// (sin mandar la reversa otra vez), en vez de tomarlo por un cambio ajeno.
func TestRollbackAfterManualFixCountsAsReverted(t *testing.T) {
	r, ex, d := residueRun(t)
	r.Confirm("rollback-1")
	wait(t, r, Failed)
	d.set(residueBase)
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "rollback-1")
	r.Confirm("rollback-1")
	wait(t, r, RolledBack)
	if n := ex.count("cfg SW1: switchport access vlan 10"); n != 1 || len(r.Changed()) != 0 {
		t.Fatalf("reversas %d, cambiados %v", n, r.Changed())
	}
}

// Revisión 3: si no se puede releer el equipo tras la reversa, no se da por revertido sin verificar.
func TestRollbackUnverifiedIsNotRolledBack(t *testing.T) {
	r, ex, d := residueRun(t)
	ex.onConfigure = func(string, []string) { // esta reversa sí lo deja limpio, pero ya no se puede releer
		d.set(residueBase)
		ex.mu.Lock()
		ex.readErr = func(string) error { return errors.New("platform: la sesión se cortó") }
		ex.mu.Unlock()
	}
	r.Confirm("rollback-1")
	wait(t, r, Failed)
	if !strings.Contains(r.FailReason(), "no se pudo verificar") || len(r.Changed()) != 1 {
		t.Fatalf("motivo %q, cambiados %v", r.FailReason(), r.Changed())
	}
	ex.mu.Lock()
	ex.readErr = nil
	ex.mu.Unlock()
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "rollback-1")
	r.Confirm("rollback-1")
	wait(t, r, RolledBack)
}

// Revisión 1: las reglas de mask anclan al inicio de línea; el residuo las aplica a cada línea antes de meterla al mensaje.
func TestResidueMasksSecrets(t *testing.T) {
	got := residue("hostname SW1\nline vty 0 4\n login\nend",
		"hostname SW1\nsnmp-server community S3cr3t RO\nline vty 0 4\n login\n password 7 0822455D0A16\nend")
	if strings.Contains(got, "S3cr3t") || strings.Contains(got, "0822455D0A16") || !strings.Contains(got, "sobra «snmp-server community") ||
		!strings.Contains(got, "en line vty 0 4") {
		t.Fatalf("residuo %q", got)
	}
}

// Revisión 5: una salida que no llegó no se lee como «falta todo»: es una reversa sin verificar.
func TestResidueMissingOutputIsUnverified(t *testing.T) {
	r, ex, d := residueRun(t)
	ex.onConfigure = func(string, []string) {
		d.set(residueBase)
		ex.mu.Lock()
		ex.omit = "show running-config interface GigabitEthernet1/0/1"
		ex.mu.Unlock()
	}
	r.Confirm("rollback-1")
	wait(t, r, Failed)
	if !strings.Contains(r.FailReason(), "no se pudo verificar") || strings.Contains(r.FailReason(), "falta") {
		t.Fatalf("motivo %q", r.FailReason())
	}
}

// Fase 30e: el residuo sale en el idioma pedido; las líneas de configuración no se traducen.
func TestResidueEnElIdioma(t *testing.T) {
	base := "interface Gi1\n description a\n shutdown\ninterface Gi2\n shutdown\nend"
	got := "interface Gi1\n description a\n shutdown\ninterface Gi2\n spanning-tree portfast edge\nend"
	if d := residueT(base, got).In(i18n.En); d != `missing "shutdown" in interface Gi2, extra "spanning-tree portfast edge" in interface Gi2` {
		t.Errorf("en: %q", d)
	}
	if d := residueT(base, got).In(i18n.Es); d != "falta «shutdown» en interface Gi2, sobra «spanning-tree portfast edge» en interface Gi2" {
		t.Errorf("es: %q", d)
	}
	many := ""
	for i := 0; i < 8; i++ {
		many += fmt.Sprintf("hostname H%d\n", i)
	}
	if d := residueT("", many).In(i18n.En); !strings.HasSuffix(d, ", and 3 more") {
		t.Errorf("más: %q", d)
	}
	if d := residueT("", many).In(i18n.Es); !strings.HasSuffix(d, ", y 3 más") {
		t.Errorf("más es: %q", d)
	}
}

func TestResiduePiezasSueltasEnEn(t *testing.T) {
	if got := i18n.Tx("assist.residue.hidden").In(i18n.En); got != "(hidden line)" {
		t.Errorf("%q", got)
	}
	if got := i18n.Tx("assist.residue.err_disabled", "port", "Gi1").In(i18n.En); !strings.HasPrefix(got, "Gi1 ended up err-disabled;") {
		t.Errorf("%q", got)
	}
}
