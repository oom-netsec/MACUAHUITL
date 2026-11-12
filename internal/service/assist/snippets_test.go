package assist

import (
	"context"
	"reflect"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

const (
	vtpOff   = "VTP Operating Mode              : Transparent\nVTP Domain Name                 : \n"
	briefHdr = "Interface              IP-Address      OK? Method Status                Protocol\n"
)

func (r *rig) snippet(s *v1.PlanSnippetRequest) (*v1.PlanSnippetResponse, error) {
	s.Target, s.AcceptedHostKeyFingerprints = r.target, []string{r.fp}
	return r.svc.PlanSnippet(context.Background(), s)
}

func vlanReq(id uint32, name string) *v1.PlanSnippetRequest {
	return &v1.PlanSnippetRequest{Snippet: &v1.PlanSnippetRequest_Vlan{Vlan: &v1.VlanSnippet{Id: id, Name: name}}}
}

func (r *rig) runToState(planID, state string) string {
	r.t.Helper()
	run := r.start(planID)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	if state == "done" {
		r.closeAndWait(run)
	}
	r.waitState(run, state)
	return run
}

func (r *rig) rollback(run string) {
	r.t.Helper()
	if _, err := r.svc.Rollback(context.Background(), &v1.RollbackRequest{RunId: run}); err != nil {
		r.t.Fatal(err)
	}
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "rollback-1")
	r.waitState(run, "rolled-back")
	r.waitDone(run)
}

func TestSnippetVlanEndToEndAndRollbackDeletesOnlyWhatItCreated(t *testing.T) {
	r := newRig(t, simulator.Config{Vlans: []int{1, 10}, VlanNames: map[int]string{10: "Usuarios"}, Commands: map[string]string{"show vtp status": vtpOff},
		ConfigErrors: map[string]string{"name Cuarentena": "% Invalid input detected at '^' marker."}})
	res, err := r.snippet(vlanReq(30, "Cuarentena"))
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Plan.Devices[0].Rollback; !reflect.DeepEqual(got, []string{"no vlan 30"}) {
		t.Fatalf("reversa = %v", got)
	}
	if n := len(r.rec.Lines()); n != 0 {
		t.Fatalf("planear no configura: %q", r.rec.Lines())
	}
	run := r.runToState(res.PlanId, "failed")
	r.rollback(run)
	if got := strings.Join(r.rec.Lines(), "|"); got != "vlan 30|name Cuarentena|end|no vlan 30|end" {
		t.Fatalf("el equipo recibió %s", got)
	}
	// La reversa dejó el equipo como estaba: crear la VLAN 30 sin nombre vuelve a ser un alta.
	again, err := r.snippet(vlanReq(30, ""))
	if err != nil || !reflect.DeepEqual(again.Plan.Devices[0].Rollback, []string{"no vlan 30"}) {
		t.Fatalf("%v %v", err, again)
	}
	// Una VLAN que ya existía solo se renombra, y su reversa restaura el nombre.
	ren, err := r.snippet(vlanReq(10, "Invitados"))
	if err != nil || !reflect.DeepEqual(ren.Plan.Devices[0].Rollback, []string{"vlan 10", "name Usuarios"}) {
		t.Fatalf("%v %v", err, ren)
	}
}

func TestSnippetVlanRefusesVTPAndInvalidInputBeforeAnyChange(t *testing.T) {
	r := newRig(t, simulator.Config{Vlans: []int{1, 10}, Commands: map[string]string{"show vtp status": "VTP Domain Name : CAMPUS\nVTP Operating Mode : Server\n"}})
	if _, err := r.snippet(vlanReq(30, "x")); code(err) != 9 { // FailedPrecondition
		t.Fatalf("VTP servidor: %v", err)
	}
	for _, bad := range []*v1.PlanSnippetRequest{vlanReq(1, "x"), vlanReq(1003, "x"), vlanReq(30, "con espacio"), {}} {
		if _, err := r.snippet(bad); code(err) != 3 { // InvalidArgument
			t.Errorf("%v: %v", bad, err)
		}
	}
	if len(r.rec.Lines()) != 0 {
		t.Fatalf("se configuró algo: %q", r.rec.Lines())
	}
}

func trunkReq(iface, op string, vlan uint32) *v1.PlanSnippetRequest {
	return &v1.PlanSnippetRequest{Snippet: &v1.PlanSnippetRequest_Trunk{Trunk: &v1.TrunkSnippet{Interface: iface, Op: op, Vlan: vlan}}}
}

func TestSnippetTrunkAddRemoveEndToEndNeverBare(t *testing.T) {
	const up = "GigabitEthernet1/0/48"
	r := newRig(t, simulator.Config{Interfaces: map[string][]string{
		up:  {"switchport mode trunk", "switchport trunk allowed vlan 10,20"},
		gi1: {"switchport mode access", "switchport access vlan 10"},
	}})
	res, err := r.snippet(trunkReq(up, "add", 30))
	if err != nil {
		t.Fatal(err)
	}
	run := r.runToState(res.PlanId, "done")
	r.waitDone(run)
	got := r.rec.Lines()
	if want := []string{"interface " + up, "switchport trunk allowed vlan add 30", "end"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("el equipo recibió %q", got)
	}
	for _, l := range got {
		if strings.HasPrefix(l, "switchport trunk allowed vlan") && !strings.HasPrefix(l, "switchport trunk allowed vlan add ") && !strings.HasPrefix(l, "switchport trunk allowed vlan remove ") {
			t.Fatalf("línea prohibida enviada: %q", l)
		}
	}
	// Con la VLAN 30 ya permitida, un segundo add no cambia nada y se rechaza; remove sí y su reversa es add.
	if _, err := r.snippet(trunkReq(up, "add", 30)); code(err) != 3 {
		t.Fatalf("add repetido: %v", err)
	}
	rm, err := r.snippet(trunkReq(up, "remove", 30))
	if err != nil || rm.Plan.Devices[0].Rollback[1] != "switchport trunk allowed vlan add 30" {
		t.Fatalf("%v %v", err, rm)
	}
	// Un puerto de acceso no es trunk.
	if _, err := r.snippet(trunkReq(gi1, "add", 30)); code(err) != 9 {
		t.Fatalf("puerto de acceso: %v", err)
	}
	// Ni "set", ni listas, ni VLAN fuera de rango llegan a conectarse.
	for _, bad := range []*v1.PlanSnippetRequest{trunkReq(up, "set", 30), trunkReq(up, "", 30), trunkReq(up, "add", 0), trunkReq(up, "add", 4095), trunkReq("Vlan10", "add", 30)} {
		if _, err := r.snippet(bad); code(err) != 3 {
			t.Errorf("%v: %v", bad, err)
		}
	}
}

func sviReq(vlan uint32, desc *string, addr string) *v1.PlanSnippetRequest {
	return &v1.PlanSnippetRequest{Snippet: &v1.PlanSnippetRequest_Svi{Svi: &v1.SviSnippet{Vlan: vlan, Description: desc, Address: addr, Mask: "255.255.255.0"}}}
}

func TestSnippetSVIEndToEndRollbackRemovesNewInterface(t *testing.T) {
	r := newRig(t, simulator.Config{
		Commands:     map[string]string{"show ip interface brief": briefHdr + "Vlan1                  unassigned      YES unset  up                    down\n"},
		ConfigErrors: map[string]string{"no shutdown": "% Invalid input detected at '^' marker."}})
	res, err := r.snippet(sviReq(99, ptr("Servidores"), "10.9.9.1"))
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Plan.Devices[0].Rollback; !reflect.DeepEqual(got, []string{"no interface Vlan99"}) {
		t.Fatalf("reversa = %v", got)
	}
	run := r.runToState(res.PlanId, "failed")
	r.rollback(run)
	want := "interface Vlan99|description Servidores|ip address 10.9.9.1 255.255.255.0|no shutdown|end|no interface Vlan99|end"
	if got := strings.Join(r.rec.Lines(), "|"); got != want {
		t.Fatalf("el equipo recibió %s", got)
	}
}

func TestSnippetSVIRefusesDeviceThatAlreadyHasThatIP(t *testing.T) {
	r := newRig(t, simulator.Config{
		Interfaces: map[string][]string{"Vlan99": {"ip address 10.1.1.1 255.255.255.0"}},
		Commands:   map[string]string{"show ip interface brief": briefHdr + "Vlan99                 10.1.1.1        YES manual up                    up\n"}})
	if _, err := r.snippet(sviReq(99, nil, "10.9.9.1")); code(err) != 9 {
		t.Fatalf("SVI con IP: %v", err)
	}
	if len(r.rec.Lines()) != 0 {
		t.Fatalf("se configuró algo: %q", r.rec.Lines())
	}
}

func TestSnippetLocksOneRunPerObject(t *testing.T) {
	r := newRig(t, simulator.Config{Vlans: []int{1}, Commands: map[string]string{"show vtp status": vtpOff}})
	a, err := r.snippet(vlanReq(30, "a"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.snippet(vlanReq(30, "b"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := r.snippet(vlanReq(31, "c"))
	if err != nil {
		t.Fatal(err)
	}
	run := r.start(a.PlanId)
	r.waitState(run, "waiting-confirm")
	if _, err := r.svc.StartRun(context.Background(), &v1.StartRunRequest{PlanId: b.PlanId, Assisted: true}); code(err) != 9 {
		t.Fatalf("la VLAN 30 ya tiene una ejecución viva: %v", err)
	}
	if _, err := r.svc.StartRun(context.Background(), &v1.StartRunRequest{PlanId: other.PlanId, Assisted: true}); err != nil {
		t.Fatalf("otra VLAN sí puede: %v", err)
	}
}

func TestSnippetStartNeedsAssistedFlag(t *testing.T) {
	r := newRig(t, simulator.Config{Vlans: []int{1}, Commands: map[string]string{"show vtp status": vtpOff}})
	res, _ := r.snippet(vlanReq(30, "a"))
	if _, err := r.svc.StartRun(context.Background(), &v1.StartRunRequest{PlanId: res.PlanId}); code(err) != 9 {
		t.Fatalf("sin assisted: %v", err)
	}
}

// ---- rotación de credenciales ----

const (
	oldPw  = "Viejo-Secreto.1"
	newSec = "Nuev0-Secreto.2026"
)

type rotRig struct {
	*rig
	tech string // credencial de la bóveda del usuario rotado
}

func newRotRig(t *testing.T, c simulator.Config) *rotRig {
	t.Helper()
	c.Users = map[string]string{"tech": oldPw}
	r := newRig(t, c)
	pw, en := secret.New([]byte(oldPw)), secret.New([]byte("en"))
	t.Cleanup(func() { pw.Destroy(); en.Destroy() }) // memguard tiene un tope de bloques: sin esto -count=30 se queda sin cerrojos
	id, err := r.d.V.Put(vault.Credential{Label: "tech", Username: "tech", Password: pw, Enable: en})
	if err != nil {
		t.Fatal(err)
	}
	return &rotRig{rig: r, tech: id}
}

func (r *rotRig) rotate(req *v1.PlanCredRotateRequest) (*v1.PlanCredRotateResponse, error) {
	req.Target, req.AcceptedHostKeyFingerprints = r.target, []string{r.fp}
	return r.svc.PlanCredRotate(context.Background(), req)
}

func (r *rotRig) vaultPw() string {
	r.t.Helper()
	c, err := r.d.V.Get(r.tech)
	if err != nil {
		r.t.Fatal(err)
	}
	defer c.Password.Destroy()
	defer c.Enable.Destroy()
	defer c.SSHKey.Destroy()
	return string(c.Password.Bytes())
}

// previous devuelve las contraseñas de las entradas "tech (anterior)" de la bóveda.
func (r *rotRig) previous() (pws []string) {
	r.t.Helper()
	infos, err := r.d.V.List()
	if err != nil {
		r.t.Fatal(err)
	}
	for _, i := range infos {
		if i.Label != "tech (anterior)" {
			continue
		}
		c, err := r.d.V.Get(i.ID)
		if err != nil {
			r.t.Fatal(err)
		}
		pws = append(pws, string(c.Password.Bytes()))
		c.Password.Destroy()
		c.Enable.Destroy()
		c.SSHKey.Destroy()
	}
	return pws
}

func (r *rotRig) noSecretAnywhere(extra ...string) {
	r.t.Helper()
	txt := r.d.AuditText()
	for _, s := range append([]string{newSec, oldPw, "$9$"}, extra...) {
		if strings.Contains(txt, s) {
			r.t.Errorf("la bitácora contiene %q", s)
		}
	}
}

func protoText(m interface{ String() string }) string { return m.String() }

func TestCredRotateEndToEndVerifiesNewLoginAndUpdatesVault(t *testing.T) {
	r := newRotRig(t, simulator.Config{})
	res, err := r.rotate(&v1.PlanCredRotateRequest{User: "tech", NewSecret: newSec, UpdateCredentialId: r.tech})
	if err != nil {
		t.Fatal(err)
	}
	if txt := protoText(res); strings.Contains(txt, newSec) || strings.Contains(txt, "$9$") {
		t.Fatalf("el plan que ve el cliente trae el secreto o el hash: %s", txt)
	}
	dp := res.Plan.Devices[0]
	if !strings.Contains(dp.Apply[0], "<oculto>") || !strings.Contains(dp.Rollback[0], "<oculto>") {
		t.Fatalf("el plan debe mostrar los secretos ocultos: %v %v", dp.Apply, dp.Rollback)
	}
	if len(r.rec.Lines()) != 0 || r.vaultPw() != oldPw {
		t.Fatal("planear no cambia ni el equipo ni la bóveda")
	}
	run := r.start(res.PlanId)
	s := r.waitState(run, "waiting-confirm")
	if txt := protoText(s); strings.Contains(txt, newSec) || strings.Contains(txt, "$9$") {
		t.Fatalf("el paso pendiente filtra: %s", txt)
	}
	r.confirm(run, "apply-1")
	// write memory es obligatorio en la rotación aunque la petición no lo pida; hasta guardarlo la bóveda no cambia.
	s = r.waitState(run, "waiting-confirm")
	if s.Pending == nil || s.Pending.Id != "save-1" {
		t.Fatalf("falta el paso write memory: %+v", s.Pending)
	}
	if r.vaultPw() != oldPw || len(r.previous()) != 0 {
		t.Fatal("antes de write memory la bóveda no cambia")
	}
	r.confirm(run, "save-1")
	r.waitState(run, "done")
	r.waitDone(run)
	if r.vaultPw() != newSec {
		t.Fatalf("la bóveda debe quedar con la credencial nueva que entró con una sesión nueva y se guardó en el equipo")
	}
	if prev := r.previous(); len(prev) != 1 || prev[0] != oldPw {
		t.Fatalf("la credencial anterior debe quedar como entrada aparte: %v", prev)
	}
	if got := strings.Join(r.rec.Lines(), "|"); !strings.Contains(got, "algorithm-type scrypt secret "+newSec) {
		t.Fatalf("el equipo no recibió la rotación: %s", got)
	}
	txt := r.d.AuditText()
	for _, w := range []string{"assist.verify", "assist.verify.session", "assist.vault.update"} {
		if !strings.Contains(txt, w) {
			t.Errorf("la bitácora no tiene %q", w)
		}
	}
	r.noSecretAnywhere()
	// Los eventos de la ejecución tampoco.
	st := &stream{ctx: context.Background()}
	if err := r.svc.WatchRun(&v1.WatchRunRequest{RunId: run}, st); err != nil {
		t.Fatal(err)
	}
	for _, e := range st.events {
		if t := protoText(e); strings.Contains(t, newSec) || strings.Contains(t, "$9$") {
			r.t.Fatalf("evento con secreto: %s", t)
		}
	}
	// Un plan nuevo ve que el equipo ya tiene el hash nuevo (la reversa de ese plan lo restauraría).
	if _, err := r.rotate(&v1.PlanCredRotateRequest{User: "tech", NewSecret: "Otro-Secreto.2027"}); err != nil {
		t.Fatal(err)
	}
}

func TestCredRotateLoginFailureLeavesVaultAndRollsBackThroughOriginalSession(t *testing.T) {
	// El equipo acepta la línea pero no cambia el acceso (AAA remoto): la sesión nueva no entra.
	r := newRotRig(t, simulator.Config{IgnoreUserChange: true})
	res, err := r.rotate(&v1.PlanCredRotateRequest{User: "tech", NewSecret: newSec, UpdateCredentialId: r.tech})
	if err != nil {
		t.Fatal(err)
	}
	run := r.start(res.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	s := r.waitState(run, "failed")
	if !strings.Contains(s.FailReason, "no entró") || strings.Contains(s.FailReason, newSec) {
		t.Fatalf("motivo: %q", s.FailReason)
	}
	if r.vaultPw() != oldPw {
		t.Fatal("la bóveda no se toca si la sesión nueva no entra")
	}
	if !s.CanRollback || len(s.Changed) != 1 {
		t.Fatalf("debe ofrecer la reversa por la sesión original: %+v", s)
	}
	r.rollback(run)
	if got := strings.Join(r.rec.Lines(), "|"); !strings.Contains(got, "secret 9 $9$") {
		t.Fatalf("la reversa usó el hash previo: %s", got)
	}
	if r.vaultPw() != oldPw {
		t.Fatal("la bóveda sigue con la credencial anterior")
	}
	r.noSecretAnywhere()
	if txt := protoText(r.state(run)); strings.Contains(txt, newSec) || strings.Contains(txt, "$9$") {
		t.Fatalf("estado filtra: %s", txt)
	}
}

func TestCredRotateSaveErrorLeavesVaultAndProposesRollback(t *testing.T) {
	// write memory responde %Error: el equipo no guardó nada, así que la bóveda no debe cambiar nunca.
	r := newRotRig(t, simulator.Config{WriteMemoryOutput: "%Error opening nvram:/startup-config (Permission denied)\n"})
	res, err := r.rotate(&v1.PlanCredRotateRequest{User: "tech", NewSecret: newSec, UpdateCredentialId: r.tech})
	if err != nil {
		t.Fatal(err)
	}
	run := r.start(res.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	r.waitState(run, "waiting-confirm") // save-1
	r.confirm(run, "save-1")
	s := r.waitState(run, "failed")
	if !s.CanRollback {
		t.Fatalf("debe ofrecer la reversa: %+v", s)
	}
	if r.vaultPw() != oldPw || len(r.previous()) != 0 {
		t.Fatal("si el equipo responde error la bóveda no debe cambiar")
	}
	r.rollback(run)
	if r.vaultPw() != oldPw || len(r.previous()) != 0 {
		t.Fatal("tras la reversa la bóveda sigue con la credencial anterior")
	}
	r.noSecretAnywhere()
}

func TestCredRotateRejectedSaveProposesRollbackAndLeavesVaultAlone(t *testing.T) {
	r := newRotRig(t, simulator.Config{})
	res, err := r.rotate(&v1.PlanCredRotateRequest{User: "tech", NewSecret: newSec, UpdateCredentialId: r.tech})
	if err != nil {
		t.Fatal(err)
	}
	run := r.start(res.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	r.waitState(run, "waiting-confirm") // save-1: el ingeniero lo rechaza
	if _, err := r.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run}); err != nil {
		t.Fatal(err)
	}
	s := r.waitState(run, "failed")
	if !s.CanRollback || len(s.Changed) != 1 {
		t.Fatalf("rechazar write memory no termina la ejecución: se propone la reversa: %+v", s)
	}
	if r.vaultPw() != oldPw || len(r.previous()) != 0 {
		t.Fatal("sin write memory la bóveda no cambia")
	}
	if strings.Contains(strings.Join(r.rec.Lines(), "|"), "write memory") {
		t.Fatal("no se mandó write memory")
	}
	r.rollback(run)
	if r.vaultPw() != oldPw || len(r.previous()) != 0 {
		t.Fatal("la bóveda sigue intacta tras la reversa")
	}
	r.noSecretAnywhere()
}

func TestCredRotateRefusesTheConnectedUserAndOtherBadRequests(t *testing.T) {
	r := newRotRig(t, simulator.Config{})
	admin := r.target.CredentialId
	cases := map[string]struct {
		req  *v1.PlanCredRotateRequest
		code int
	}{
		"el usuario de la sesión":    {&v1.PlanCredRotateRequest{User: "admin", NewSecret: newSec}, 9},
		"usuario inexistente":        {&v1.PlanCredRotateRequest{User: "nadie", NewSecret: newSec}, 9},
		"secreto corto":              {&v1.PlanCredRotateRequest{User: "tech", NewSecret: "corto"}, 3},
		"generado sin credencial":    {&v1.PlanCredRotateRequest{User: "tech"}, 3},
		"credencial de otro usuario": {&v1.PlanCredRotateRequest{User: "tech", NewSecret: newSec, UpdateCredentialId: admin}, 3},
		"usuario con espacio":        {&v1.PlanCredRotateRequest{User: "te ch", NewSecret: newSec}, 3},
		"credencial que no existe":   {&v1.PlanCredRotateRequest{User: "tech", NewSecret: newSec, UpdateCredentialId: "00"}, 5},
	}
	for name, c := range cases {
		if _, err := r.rotate(c.req); int(code(err)) != c.code {
			t.Errorf("%s: %v (código %d)", name, err, code(err))
		}
	}
	if len(r.rec.Lines()) != 0 {
		t.Fatalf("se configuró algo: %q", r.rec.Lines())
	}
	r.noSecretAnywhere()
}

func TestCredRotateGeneratedSecretIsOnlyInTheVault(t *testing.T) {
	r := newRotRig(t, simulator.Config{})
	res, err := r.rotate(&v1.PlanCredRotateRequest{User: "tech", UpdateCredentialId: r.tech})
	if err != nil {
		t.Fatal(err)
	}
	run := r.start(res.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "save-1")
	r.waitState(run, "done")
	r.waitDone(run)
	gen := r.vaultPw()
	if gen == oldPw || len(gen) < 20 {
		t.Fatalf("la bóveda debe tener el secreto generado: %q", gen)
	}
	r.noSecretAnywhere(gen)
	if txt := protoText(res); strings.Contains(txt, gen) {
		t.Fatal("el plan muestra el secreto generado")
	}
	st := &stream{ctx: context.Background()}
	r.svc.WatchRun(&v1.WatchRunRequest{RunId: run}, st)
	for _, e := range st.events {
		if strings.Contains(protoText(e), gen) {
			t.Fatalf("evento con el secreto generado: %v", e)
		}
	}
}

func TestCredRotateOneRunPerUser(t *testing.T) {
	r := newRotRig(t, simulator.Config{})
	a, _ := r.rotate(&v1.PlanCredRotateRequest{User: "tech", NewSecret: newSec})
	b, _ := r.rotate(&v1.PlanCredRotateRequest{User: "tech", NewSecret: "Otro-Secreto.2027"})
	run := r.start(a.PlanId)
	r.waitState(run, "waiting-confirm")
	if _, err := r.svc.StartRun(context.Background(), &v1.StartRunRequest{PlanId: b.PlanId, Assisted: true}); code(err) != 9 {
		t.Fatalf("el usuario ya tiene una ejecución viva: %v", err)
	}
}
