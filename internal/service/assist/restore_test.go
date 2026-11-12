package assist

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/backup"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

const restoreRunning = `version 15.2
hostname SW1
!
ntp server 10.0.0.1
logging host 10.0.0.9
!
ip access-list extended EDGE
 permit tcp any any eq 22
 permit icmp any any
!
interface GigabitEthernet1/0/1
 description PC-ventas
 switchport access vlan 10
 switchport mode access
!
interface GigabitEthernet1/0/2
 description libre
 switchport access vlan 20
 switchport mode access
 shutdown
!
interface Vlan1
 ip address 127.0.0.1 255.0.0.0
!
line vty 0 4
 transport input ssh
!
end
`

const restoreBackup = `version 15.2
hostname SW1
!
ntp server 10.0.0.2
!
ip access-list extended EDGE
 permit tcp any any eq 22
 permit icmp any any
!
interface GigabitEthernet1/0/1
 description PC-contabilidad
 switchport access vlan 30
 switchport mode access
!
interface GigabitEthernet1/0/2
 description libre
 switchport access vlan 20
 switchport mode access
!
interface Vlan1
 ip address 127.0.0.1 255.0.0.0
!
line vty 0 4
 transport input ssh
!
end
`

const deviceSerial = "FOC0001A0AA"

// saveBackup guarda un respaldo como lo hace el servicio de respaldos (ficha firmada con la llave de la bóveda, con la serie del equipo) y devuelve su id.
func (r *rig) saveBackup(text string, masked bool) string {
	return r.saveBackupWith(text, masked, true, func(*backup.Entry) {})
}

func (r *rig) saveBackupWith(text string, masked, sign bool, mod func(*backup.Entry)) string {
	r.t.Helper()
	r.backups++ // cada respaldo con su segundo: Save no pisa uno que ya existe
	st := backup.Store{Root: filepath.Join(r.d.Out, "respaldos")}
	if sign {
		key, err := service.BackupKey(r.d.V, true)
		if err != nil {
			r.t.Fatal(err)
		}
		st.Key = key
	}
	e := backup.Entry{Device: "SW1_127.0.0.1", Kind: backup.Running, At: time.Unix(1_700_000_000+r.backups, 0).UTC(), Masked: masked, Serial: deviceSerial}
	mod(&e)
	e, _, err := st.Save(e, text)
	if err != nil {
		r.t.Fatal(err)
	}
	return e.ID
}

func (r *rig) restore(id string, mod func(*v1.PlanRestoreRequest)) (*v1.PlanRestoreResponse, error) {
	req := &v1.PlanRestoreRequest{Target: r.target, BackupId: id, AcceptedHostKeyFingerprints: []string{r.fp}}
	if mod != nil {
		mod(req)
	}
	return r.svc.PlanRestore(context.Background(), req)
}

const gi5 = "GigabitEthernet1/0/5"

func newRestoreRig(t *testing.T, running string, mod func(*simulator.Config)) *rig {
	// Gi1/0/5 no la toca ninguna restauración de estas pruebas: sirve para ver que el candado es del equipo entero.
	// El núcleo entra por 127.0.0.1 (Vlan1 lleva esa IP): show users y show tcp brief lo dicen como lo hace IOS.
	c := simulator.Config{Running: running, Commands: map[string]string{
		"show version": "Cisco IOS Software, C3560CX Software, Version 15.2(7)E\nProcessor board ID " + deviceSerial + "\n",
		"show users": "    Line       User       Host(s)              Idle       Location\n" +
			"*  2 vty 0     admin      idle                 00:00:00 127.0.0.1\n",
		"show tcp brief": "TCB       Local Address               Foreign Address             (state)\n" +
			"7F1A2B3C  127.0.0.1.22                127.0.0.1.51234             ESTAB\n",
		// Sin enrutamiento (un switch L2): la gestión es la IP local.
		"show ip route 127.0.0.1": "Default gateway is 127.0.0.2\n\nHost               Gateway           Last Use    Total Uses  Interface\nICMP redirect cache is empty\n",
	}, Interfaces: map[string][]string{gi1: {"description Impresora", "switchport access vlan 10", "switchport mode access"},
		gi5: {"switchport access vlan 10", "switchport mode access"}}}
	if mod != nil {
		mod(&c)
	}
	return newRig(t, c)
}

func TestRestoreDiffEndToEndLeavesRunningEqualToTheBackup(t *testing.T) {
	r := newRestoreRig(t, restoreRunning, nil)
	id := r.saveBackup(restoreBackup, false)
	res, err := r.restore(id, nil)
	if err != nil {
		t.Fatal(err)
	}
	dp := res.Plan.Devices[0]
	if res.Plan.Function != "restore-diff" || len(res.Refused) != 0 || len(dp.Rollback) == 0 {
		t.Fatalf("respuesta = %+v", res)
	}
	if len(r.rec.Lines()) != 0 {
		t.Fatalf("planear no configura nada: %q", r.rec.Lines())
	}
	run := r.start(res.PlanId)
	s := r.waitState(run, "waiting-confirm")
	if s.Pending.Id != "apply-1" || !reflect.DeepEqual(s.Pending.Lines, dp.Apply) {
		t.Fatalf("pendiente = %+v", s.Pending)
	}
	time.Sleep(30 * time.Millisecond)
	if len(r.rec.Lines()) != 0 {
		t.Fatalf("se configuró sin confirmar: %q", r.rec.Lines())
	}
	r.confirm(run, "apply-1")
	r.closeAndWait(run) // done implica que el post-check (Expect contra el running) se cumplió
	r.waitDone(run)
	if got, want := r.rec.Lines(), append(slices.Clone(dp.Apply), "end"); !reflect.DeepEqual(got, want) {
		t.Fatalf("el equipo recibió %q, esperaba %q", got, want)
	}
	// El equipo quedó igual al respaldo: no hay nada más que restaurar.
	if _, err := r.restore(id, nil); code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "ya coincide") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(r.d.AuditText(), "assist.line") || !strings.Contains(r.d.AuditText(), "backup="+id) {
		t.Error("la bitácora debe tener el plan con el respaldo y cada línea")
	}
}

func TestRestoreDiffRollbackBringsTheDeviceBack(t *testing.T) {
	r := newRestoreRig(t, restoreRunning, func(c *simulator.Config) {
		c.ConfigErrors = map[string]string{"switchport access vlan 30": "% Invalid input detected at '^' marker."}
	})
	id := r.saveBackup(restoreBackup, false)
	first, err := r.restore(id, nil)
	if err != nil {
		t.Fatal(err)
	}
	run := r.runToState(first.PlanId, "failed") // la línea rechazada detiene la ejecución a la mitad
	r.rollback(run)
	again, err := r.restore(id, nil)
	if err != nil || !reflect.DeepEqual(again.Plan.Devices[0].Apply, first.Plan.Devices[0].Apply) {
		t.Fatalf("tras la reversa el equipo debe estar como antes: %v\n%v\n%v", err, again, first)
	}
}

func TestRestoreRefusesMaskedTamperedAndForeignBackupsBeforeConnecting(t *testing.T) {
	r := newRestoreRig(t, restoreRunning, nil)
	before := r.attempts.Load()
	masked := r.saveBackup(strings.Replace(restoreBackup, "ntp server 10.0.0.2", "ntp server 10.0.0.2\nsnmp-server community <MASKED:snmp-community> RO", 1), true)
	if _, err := r.restore(masked, nil); code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "enmascarados") {
		t.Fatalf("masked: %v", err)
	}
	tampered := r.saveBackup(restoreBackup+"! x\n", false)
	e, _, _ := backup.Store{Root: filepath.Join(r.d.Out, "respaldos")}.Get(tampered)
	if err := os.WriteFile(e.Path(filepath.Join(r.d.Out, "respaldos")), []byte(restoreBackup+"ntp server 6.6.6.6\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.restore(tampered, nil); code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "ficha") {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := r.restore("SW1_127.0.0.1/20200101T000000Z-running", nil); code(err) != codes.NotFound {
		t.Fatalf("inexistente: %v", err)
	}
	if r.attempts.Load() != before {
		t.Fatal("rechazar un respaldo no debe abrir ninguna conexión")
	}
	// De otro equipo: la comprobación del hostname ocurre al leer el running.
	other := r.saveBackup(strings.Replace(restoreBackup, "hostname SW1", "hostname SW2", 1), false)
	if _, err := r.restore(other, nil); code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "SW2") {
		t.Fatalf("otro equipo: %v", err)
	}
}

func TestRestoreRefusalListComesBackAndNothingIsStored(t *testing.T) {
	r := newRestoreRig(t, restoreRunning, nil)
	id := r.saveBackup(strings.Replace(restoreBackup, "!\nntp server", "!\nvtp mode client\nntp server", 1), false)
	res, err := r.restore(id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.PlanId != "" || res.Plan != nil || len(res.Refused) == 0 || !strings.Contains(res.Refused[0].Line, "vtp") || res.Reason == "" {
		t.Fatalf("el plan se rechaza y se lista lo rechazado: %+v", res)
	}
	if _, err := r.svc.StartRun(context.Background(), &v1.StartRunRequest{PlanId: res.PlanId, Assisted: true}); code(err) != codes.NotFound {
		t.Fatalf("no hay plan que ejecutar: %v", err)
	}
	// Con el plan parcial se aplica solo lo permitido y se sigue listando lo demás.
	part, err := r.restore(id, func(q *v1.PlanRestoreRequest) { q.AllowPartial = true })
	if err != nil || part.PlanId == "" || len(part.Refused) != 1 {
		t.Fatalf("parcial: %v %+v", err, part)
	}
	for _, l := range part.Plan.Devices[0].Apply {
		if strings.Contains(l, "vtp") {
			t.Fatalf("lo rechazado no se aplica: %q", part.Plan.Devices[0].Apply)
		}
	}
	if len(r.rec.Lines()) != 0 {
		t.Fatal("planear no configura")
	}
}

func TestRestoreNeverTouchesTheInterfaceTheCoreIsConnectedThrough(t *testing.T) {
	r := newRestoreRig(t, restoreRunning, nil)
	// Vlan1 lleva 127.0.0.1, la dirección del equipo simulado: el respaldo la cambia.
	id := r.saveBackup(strings.Replace(restoreBackup, "ip address 127.0.0.1 255.0.0.0", "ip address 127.0.0.5 255.0.0.0", 1), false)
	res, err := r.restore(id, nil)
	if err != nil || res.PlanId != "" || len(res.Refused) == 0 || !strings.Contains(res.Refused[0].Why, "gestión") {
		t.Fatalf("%v %+v", err, res)
	}
	// Si ninguna interfaz lleva la dirección y no se indica cuál es, no se restaura nada.
	r2 := newRestoreRig(t, strings.Replace(restoreRunning, "127.0.0.1", "192.0.2.1", 1), nil)
	id2 := r2.saveBackup(strings.Replace(restoreBackup, "127.0.0.1", "192.0.2.1", 1), false)
	if _, err := r2.restore(id2, nil); code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "gestión") {
		t.Fatalf("sin interfaz de gestión identificada: %v", err)
	}
	if res, err := r2.restore(id2, func(q *v1.PlanRestoreRequest) { q.ManagementInterface = "vlan1" }); err != nil || res.PlanId == "" {
		t.Fatalf("indicada a mano: %v %+v", err, res)
	}
}

func TestRestoreLineCapAndWriteMemoryOnlyConfirmed(t *testing.T) {
	r := newRestoreRig(t, restoreRunning, nil)
	id := r.saveBackup(restoreBackup, false)
	if _, err := r.restore(id, func(q *v1.PlanRestoreRequest) { q.MaxLines = 2 }); code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "tope") {
		t.Fatalf("tope: %v", err)
	}
	if _, err := r.restore(id, func(q *v1.PlanRestoreRequest) { q.MaxLines = 5000 }); code(err) != codes.InvalidArgument {
		t.Fatalf("tope máximo: %v", err)
	}
	res, err := r.restore(id, func(q *v1.PlanRestoreRequest) { q.WriteMemory = true })
	if err != nil {
		t.Fatal(err)
	}
	run := r.start(res.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	if s := r.waitState(run, "waiting-confirm"); s.Pending.Id != "save-1" {
		t.Fatalf("pendiente = %+v", s.Pending)
	}
	for _, l := range r.rec.Lines() {
		if l == "!write memory" {
			t.Fatal("guardó sin confirmar")
		}
	}
	r.confirm(run, "save-1")
	r.waitState(run, "done")
}

func TestRestoreHoldsTheWholeDeviceAndStalePlansStopBeforeChanging(t *testing.T) {
	r := newRestoreRig(t, restoreRunning, nil)
	id := r.saveBackup(restoreBackup, false)
	a, err := r.restore(id, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.restore(id, nil)
	if err != nil {
		t.Fatal(err)
	}
	ports, err := r.plan(&v1.PlanPortsRequest{Vlan: 20, Interfaces: []string{gi5}})
	if err != nil {
		t.Fatal(err)
	}
	runA := r.start(a.PlanId)
	r.waitState(runA, "waiting-confirm")
	// Mientras la restauración vive, ninguna otra ejecución toca ese equipo.
	if _, err := r.svc.StartRun(context.Background(), &v1.StartRunRequest{PlanId: b.PlanId, Assisted: true}); code(err) != codes.FailedPrecondition {
		t.Fatalf("segundo restore: %v", err)
	}
	if _, err := r.svc.StartRun(context.Background(), &v1.StartRunRequest{PlanId: ports.PlanId, Assisted: true}); code(err) != codes.FailedPrecondition {
		t.Fatalf("puertos mientras se restaura: %v", err)
	}
	r.confirm(runA, "apply-1")
	r.closeAndWait(runA)
	r.waitDone(runA)
	// El plan B se hizo antes de que A cambiara el equipo: caducó y se detiene sin mandar nada.
	n := len(r.rec.Lines())
	runB := r.start(b.PlanId)
	s := r.waitState(runB, "failed")
	if !strings.Contains(s.FailReason, "cambió desde que se hizo el plan") || len(r.rec.Lines()) != n {
		t.Fatalf("plan caduco: %q %q", s.FailReason, r.rec.Lines()[n:])
	}
}

func TestRestoreIsRefusedWhileAnotherRunHoldsAPortOfTheDevice(t *testing.T) {
	r := newRestoreRig(t, restoreRunning, nil)
	id := r.saveBackup(restoreBackup, false)
	res, err := r.restore(id, nil)
	if err != nil {
		t.Fatal(err)
	}
	ports, err := r.plan(&v1.PlanPortsRequest{Vlan: 20, Interfaces: []string{gi5}})
	if err != nil {
		t.Fatal(err)
	}
	run := r.start(ports.PlanId)
	r.waitState(run, "waiting-confirm")
	if _, err := r.svc.StartRun(context.Background(), &v1.StartRunRequest{PlanId: res.PlanId, Assisted: true}); code(err) != codes.FailedPrecondition {
		t.Fatalf("restaurar con un puerto en curso: %v", err)
	}
	r.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run})
	r.waitDone(run)
}

// Fase 16c: la ficha firmada, la serie y el respaldo completo (antes de conectar, salvo la serie, que se compara con el equipo).
func TestRestoreRefusesUnsignedForgedOrForeignKeyBackupsBeforeConnecting(t *testing.T) {
	r := newRestoreRig(t, restoreRunning, nil)
	before := r.attempts.Load()
	unsigned := r.saveBackupWith(restoreBackup, false, false, func(*backup.Entry) {})
	if _, err := r.restore(unsigned, nil); code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "firma") {
		t.Fatalf("un respaldo viejo sin firma no se restaura: %v", err)
	}
	// La ficha firmada y luego editada a mano (se le quita el recorte o se le cambia la serie) deja de verificar.
	signed := r.saveBackupWith(restoreBackup, false, true, func(e *backup.Entry) { e.Truncated = true })
	e, _, _ := backup.Store{Root: filepath.Join(r.d.Out, "respaldos")}.Get(signed)
	meta := strings.TrimSuffix(e.Path(filepath.Join(r.d.Out, "respaldos")), ".cfg") + ".json"
	b, _ := os.ReadFile(meta)
	if err := os.WriteFile(meta, []byte(strings.Replace(string(b), `"truncated":true,`, "", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.restore(signed, nil); code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "firma") {
		t.Fatalf("ficha alterada: %v", err)
	}
	// Firmada con otra llave (otra bóveda).
	other := r.saveBackupWith(restoreBackup, false, false, func(*backup.Entry) {})
	e2, _, _ := backup.Store{Root: filepath.Join(r.d.Out, "respaldos")}.Get(other)
	cfg, _ := os.ReadFile(e2.Path(filepath.Join(r.d.Out, "respaldos")))
	meta2 := strings.TrimSuffix(e2.Path(filepath.Join(r.d.Out, "respaldos")), ".cfg") + ".json"
	fake := e2
	fake.Sig = fake.Sign([]byte("llave-de-otra-boveda-de-32-bytes!"))
	mb, _ := json.Marshal(fake)
	os.WriteFile(meta2, mb, 0o600)
	_ = cfg
	if _, err := r.restore(other, nil); code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "firma") {
		t.Fatalf("firma de otra llave: %v", err)
	}
	if r.attempts.Load() != before {
		t.Fatal("rechazar un respaldo no debe abrir ninguna conexión")
	}
}

func TestRestoreRefusesTheSameHostnameOnAnotherDeviceAndIncompleteBackups(t *testing.T) {
	r := newRestoreRig(t, restoreRunning, nil)
	// Mismo hostname, otro equipo: la serie de la ficha no es la de show version.
	foreign := r.saveBackupWith(restoreBackup, false, true, func(e *backup.Entry) { e.Serial = "FOC9999Z9ZZ" })
	if _, err := r.restore(foreign, nil); code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "serie") {
		t.Fatalf("otra serie: %v", err)
	}
	noSerial := r.saveBackupWith(restoreBackup, false, true, func(e *backup.Entry) { e.Serial = "" })
	if _, err := r.restore(noSerial, nil); code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "serie") {
		t.Fatalf("sin serie: %v", err)
	}
	cut := r.saveBackup(strings.TrimSuffix(restoreBackup, "end\n"), false)
	if _, err := r.restore(cut, nil); code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "end") {
		t.Fatalf("sin end: %v", err)
	}
	trunc := r.saveBackupWith(restoreBackup, false, true, func(e *backup.Entry) { e.Truncated = true })
	if _, err := r.restore(trunc, nil); code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "recortado") {
		t.Fatalf("recortado: %v", err)
	}
	if len(r.rec.Lines()) != 0 {
		t.Fatal("planear no configura")
	}
}

// Las lecturas de Pre (el running con comunidades, llaves y hashes) salen del núcleo enmascaradas: eventos y bitácora.
func TestRestoreReadOutputIsMaskedInEventsAndAudit(t *testing.T) {
	run := strings.Replace(restoreRunning, "ntp server 10.0.0.1\n", "ntp server 10.0.0.1\nsnmp-server community COMUNIDAD42 RO\nusername admin privilege 15 secret 9 $9$HASHSECRETO\n", 1)
	r := newRestoreRig(t, run, nil)
	id := r.saveBackup(strings.Replace(restoreBackup, "ntp server 10.0.0.2\n", "ntp server 10.0.0.2\nsnmp-server community COMUNIDAD42 RO\nusername admin privilege 15 secret 9 $9$HASHSECRETO\n", 1), false)
	res, err := r.restore(id, nil)
	if err != nil {
		t.Fatal(err)
	}
	runID := r.start(res.PlanId)
	s := r.waitState(runID, "waiting-confirm")
	r.confirm(runID, s.Pending.Id)
	r.closeAndWait(runID)
	r.waitDone(runID)
	all := r.d.AuditText()
	rec, _ := r.svc.get(runID)
	evs, _ := rec.run.Events(0)
	for _, e := range evs {
		all += e.Text + "\n"
	}
	for _, secret := range []string{"COMUNIDAD42", "HASHSECRETO"} {
		if strings.Contains(all, secret) {
			t.Errorf("%s salió del núcleo en un evento o en la bitácora", secret)
		}
	}
	if !strings.Contains(all, "show running-config") {
		t.Error("la lectura sí queda registrada, pero enmascarada")
	}
}

// Un startup-config no es lo que corre el equipo: restaurarlo contra el running mezclaría dos cosas distintas.
func TestRestoreRefusesAStartupConfigBackupBeforeConnecting(t *testing.T) {
	r := newRestoreRig(t, restoreRunning, nil)
	before := r.attempts.Load()
	id := r.saveBackupWith(restoreBackup, false, true, func(e *backup.Entry) { e.Kind = backup.Startup })
	_, err := r.restore(id, nil)
	if code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "running-config") {
		t.Fatalf("un respaldo de startup se rechaza con un mensaje claro: %v", err)
	}
	if r.attempts.Load() != before {
		t.Fatal("no debe abrir ninguna conexión")
	}
}

// En un switch con ip routing el núcleo entra a Loopback0 (127.0.0.1) y el tráfico de regreso sale por Vlan20: el servicio pregunta por la
// salida (show ip cef hacia el origen) y el plan protege Vlan20 y su VLAN.
func TestRestoreRoutedSwitchAsksTheEgressAndProtectsItsVlan(t *testing.T) {
	routed := strings.Replace(restoreRunning, "hostname SW1\n", "hostname SW1\nip routing\n", 1)
	routed = strings.Replace(routed, "interface Vlan1\n ip address 127.0.0.1 255.0.0.0\n", "interface Loopback0\n ip address 127.0.0.1 255.0.0.0\n!\ninterface Vlan20\n ip address 10.20.0.1 255.255.255.0\n", 1)
	back := func(from, to string) string { return strings.Replace(routed, from, to, 1) }
	withCef := func(c *simulator.Config) {
		c.Commands["show ip cef 127.0.0.1"] = "127.0.0.0/8\n  nexthop 10.20.0.2 Vlan20\n"
	}
	r := newRestoreRig(t, routed, withCef)
	// Gi1/0/1 está en la VLAN 10: se restaura.
	if res, err := r.restore(r.saveBackup(back("PC-ventas", "PC-otra"), false), nil); err != nil || res.PlanId == "" {
		t.Fatalf("la VLAN 10 no es la de la salida: %v %+v", err, res)
	}
	// Gi1/0/2 está en la VLAN 20, la de la SVI de salida: no se toca.
	res, err := r.restore(r.saveBackup(back("description libre", "description libre2"), false), nil)
	if err != nil || res.PlanId != "" || len(res.Refused) == 0 || !strings.Contains(res.Refused[0].Why, "gestión") {
		t.Fatalf("la VLAN 20 es la de la salida: %v %+v", err, res)
	}
	// Sin respuesta de CEF ni de la ruta no hay certeza de la salida: se rechaza y pide --mgmt-if.
	r2 := newRestoreRig(t, routed, nil)
	_, err = r2.restore(r2.saveBackup(back("PC-ventas", "PC-otra"), false), nil)
	if code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "mgmt-if") {
		t.Fatalf("sin la salida: %v", err)
	}
	if _, err := r2.restore(r2.saveBackup(back("PC-ventas", "PC-otra2"), false), func(q *v1.PlanRestoreRequest) { q.ManagementInterface = "vlan20" }); err != nil {
		t.Fatalf("--mgmt-if: %v", err)
	}
}
