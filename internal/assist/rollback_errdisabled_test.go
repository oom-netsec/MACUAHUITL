package assist

import (
	"context"
	"strings"
	"sync"
	"testing"
)

const (
	edCfg    = "show running-config interface GigabitEthernet1/0/1"
	edStatus = "show interfaces GigabitEthernet1/0/1 status"
	edBase   = "Building configuration...\n!\ninterface GigabitEthernet1/0/1\n switchport access vlan 10\nend"
)

func edRow(status string) string {
	return "Port      Name               Status       Vlan       Duplex  Speed Type\n" +
		"Gi1/0/1                      " + status + strings.Repeat(" ", 13-len(status)) + "10         a-full  a-1000 10/100/1000BaseTX\n"
}

// edDevice: el running-config vuelve idéntico tras la reversa; lo que cambia es el estado del puerto, que fija cada prueba.
type edDevice struct {
	mu      sync.Mutex
	applied bool
	status  string
}

func (d *edDevice) set(s string) { d.mu.Lock(); d.status = s; d.mu.Unlock() }

// edRun llega hasta la confirmación de la reversa. before es el estado del puerto en la línea base; afterRollback el que tendrá tras la reversa.
func edRun(t *testing.T, before, afterRollback string) (*Run, *edDevice) {
	t.Helper()
	d := &edDevice{status: before}
	ex := &fakeExec{}
	n := 0
	ex.onConfigure = func(string, []string) {
		d.mu.Lock()
		defer d.mu.Unlock()
		n++
		d.applied = n == 1
		if n > 1 {
			d.status = afterRollback
		}
	}
	ex.readFunc = func(_, cmd string) string {
		d.mu.Lock()
		defer d.mu.Unlock()
		switch cmd {
		case edStatus:
			return edRow(d.status)
		default:
			if d.applied {
				return "interface GigabitEthernet1/0/1\n switchport access vlan 20\nend"
			}
			return edBase
		}
	}
	p := okPlan()
	dp := &p.Devices[0]
	dp.Pre, dp.Post = []string{edCfg, edStatus}, []string{edCfg, edStatus}
	dp.Expect[0].Command = edCfg
	dp.Baseline = map[string]string{edCfg: edBase, edStatus: edRow(before)}
	r, _ := newRun(t, p, ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "close")
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "rollback-1")
	return r, d
}

// Una reversa «exitosa» que deja el puerto err-disabled no es una reversa cumplida: el ingeniero tiene que recuperarlo a mano.
func TestRollbackLeavingThePortErrDisabledIsNotRolledBack(t *testing.T) {
	r, d := edRun(t, "connected", "err-disabled")
	r.Confirm("rollback-1")
	wait(t, r, Failed)
	sn := r.Snapshot()
	if !strings.Contains(sn.Reason, "Gi1/0/1 quedó err-disabled") || !strings.Contains(sn.Reason, "shutdown/no shutdown a mano") || len(sn.Changed) != 1 || !sn.CanRollback {
		t.Fatalf("%+v", sn)
	}
	// El ingeniero lo recupera a mano: el reintento ve el equipo como en su línea base y lo cuenta como revertido.
	d.set("connected")
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "rollback-1")
	r.Confirm("rollback-1")
	wait(t, r, RolledBack)
	if len(r.Changed()) != 0 {
		t.Fatalf("cambiados %v", r.Changed())
	}
}

// Si el puerto ya estaba err-disabled antes del cambio, la reversa no lo causó; y cualquier otro estado distinto no es residuo.
func TestRollbackStatusOnlyMattersWhenItBecomesErrDisabled(t *testing.T) {
	for name, c := range map[string][2]string{"ya estaba err-disabled": {"err-disabled", "err-disabled"}, "connected a notconnect": {"connected", "notconnect"}, "queda connected": {"connected", "connected"}} {
		r, _ := edRun(t, c[0], c[1])
		r.Confirm("rollback-1")
		wait(t, r, RolledBack)
		if len(r.Changed()) != 0 {
			t.Errorf("%s: cambiados %v", name, r.Changed())
		}
	}
}

// El estado del puerto no entra a la comparación de «el equipo cambió desde el plan»: un enlace que sube o baja no caduca el plan.
func TestPortStatusDoesNotExpireThePlan(t *testing.T) {
	d := &edDevice{status: "notconnect"} // el plan se hizo con el puerto connected
	ex := &fakeExec{readFunc: func(_, cmd string) string {
		d.mu.Lock()
		defer d.mu.Unlock()
		if cmd == edStatus {
			return edRow(d.status)
		}
		if d.applied {
			return "interface GigabitEthernet1/0/1\n switchport access vlan 20\nend"
		}
		return edBase
	}}
	ex.onConfigure = func(string, []string) { d.mu.Lock(); d.applied = true; d.mu.Unlock() }
	p := okPlan()
	dp := &p.Devices[0]
	dp.Pre, dp.Post = []string{edCfg, edStatus}, []string{edCfg, edStatus}
	dp.Expect[0].Command = edCfg
	dp.Baseline = map[string]string{edCfg: edBase, edStatus: edRow("connected")}
	r, _ := newRun(t, p, ex)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "close")
}
