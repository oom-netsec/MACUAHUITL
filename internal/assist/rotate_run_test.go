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

// verifyExec suma al ejecutor de pruebas la sesión nueva con la credencial nueva.
type verifyExec struct {
	*fakeExec
	mu        sync.Mutex
	verifyErr error
	verified  int
	reverted  int
	saved     int    // veces que el motor avisó que write memory salió bien (la bóveda se actualiza ahí)
	saveText  string // respuesta de write memory; vacío = [OK]
	savedErr  error
	revertErr error // lo que devuelve Reverted
}

func (v *verifyExec) Save(_ context.Context, dev string) (string, error) {
	v.fakeExec.log("save " + dev)
	if v.saveText != "" {
		return v.saveText, errors.New("el equipo respondió " + v.saveText)
	}
	return "[OK]", nil
}

func (v *verifyExec) Saved(_ context.Context, dev string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.saved++
	v.fakeExec.log("saved " + dev)
	return "la bóveda quedó con la credencial nueva", v.savedErr
}

func (v *verifyExec) Verify(_ context.Context, dev string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.verified++
	v.fakeExec.log("verify " + dev)
	return "la sesión nueva con tech entró", v.verifyErr
}

func (v *verifyExec) Reverted(_ context.Context, dev string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.reverted++
	v.fakeExec.log("reverted " + dev)
	return v.revertErr
}

const newHash = "$9$NUEVO$hashquenuncadebeverse0123456789"

// rotationRun arma una ejecución de rotación: el equipo muestra el hash previo hasta que se aplica el secreto nuevo.
func rotationRun(t *testing.T, vErr error, mods ...func(*fakeExec)) (*Run, *verifyExec, *auditRec) {
	t.Helper()
	return rotationRunWith(t, vErr, nil, mods...)
}

func rotationRunWith(t *testing.T, vErr error, tune func(*verifyExec), mods ...func(*fakeExec)) (*Run, *verifyExec, *auditRec) {
	t.Helper()
	outs := rotOuts(usersOut("username admin privilege 15 secret 9 $9$otro$xyz", "username tech privilege 15 secret 9 "+oldHash9), xe17)
	dp, err := CredRotatePlan("SW1", CredRotateChange{User: "tech", NewSecret: newSec, ConnectedUser: "admin"}, outs)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	applied := false
	fx := &fakeExec{echo: true}
	fx.onConfigure = func(_ string, lines []string) {
		mu.Lock()
		applied = strings.Contains(lines[0], newSec)
		mu.Unlock()
	}
	fx.readFunc = func(_, cmd string) string {
		mu.Lock()
		defer mu.Unlock()
		switch cmd {
		case credUsersCmd:
			if applied {
				return usersOut("username admin privilege 15 secret 9 $9$otro$xyz", "username tech privilege 15 secret 9 "+newHash)
			}
			return outs[credUsersCmd]
		}
		return "Cisco IOS XE Software, Version 17.03.04a"
	}
	for _, m := range mods {
		m(fx)
	}
	vx := &verifyExec{fakeExec: fx, verifyErr: vErr}
	if tune != nil {
		tune(vx)
	}
	a := &auditRec{}
	r, err := NewRun(Options{ID: "rot1", Plan: Plan{Function: CredRotate.Name, WriteMemory: true, Devices: []DevicePlan{dp}}, Fn: CredRotate, Assisted: true, Exec: vx, Audit: a.add})
	if err != nil {
		t.Fatal(err)
	}
	return r, vx, a
}

// allText junta todo lo que el motor entrega: bitácora, eventos, pasos, motivo del fallo.
func allText(r *Run, a *auditRec) string {
	var b strings.Builder
	b.WriteString(a.text())
	evs, _ := r.Events(0)
	for _, e := range evs {
		fmt.Fprintf(&b, "\n%s %s %s %q", e.Kind, e.State, e.Device, e.Text)
		if e.Step != nil {
			fmt.Fprintf(&b, " %v", e.Step.Lines)
		}
	}
	sn := r.Snapshot()
	fmt.Fprintf(&b, "\n%s", sn.Reason)
	if sn.Pending != nil {
		fmt.Fprintf(&b, " %v", sn.Pending.Lines)
	}
	if p := r.Pending(); p != nil {
		fmt.Fprintf(&b, " %v", p.Lines)
	}
	return b.String()
}

func noSecrets(t *testing.T, what, text string) {
	t.Helper()
	for _, s := range []string{newSec, oldHash9, newHash} {
		if strings.Contains(text, s) {
			t.Errorf("%s filtra %q:\n%s", what, s, text)
		}
	}
}

func TestRotationSecretNeverReachesAuditEventsStepsOrReasons(t *testing.T) {
	r, vx, a := rotationRun(t, nil)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	noSecrets(t, "el paso pendiente", allText(r, a))
	step := r.Pending()
	if !strings.Contains(strings.Join(step.Lines, " "), hidden) {
		t.Errorf("el paso debe mostrar la línea con el secreto oculto: %v", step.Lines)
	}
	r.Confirm("apply-1")
	pending(t, r, "save-1")
	r.Confirm("save-1")
	wait(t, r, Done)
	<-r.Done()
	if vx.verified != 1 {
		t.Fatalf("verify = %d", vx.verified)
	}
	noSecrets(t, "una rotación completa", allText(r, a))
	// El equipo sí recibió el secreto real (si no, la rotación no rotaría nada).
	if !strings.Contains(strings.Join(vx.Calls(), "\n"), newSec) {
		t.Errorf("el equipo no recibió el secreto nuevo: %v", vx.Calls())
	}
}

func TestRotationFailureAndRollbackNeverLeakSecret(t *testing.T) {
	line := "username tech privilege 15 algorithm-type scrypt secret " + newSec
	r, vx, a := rotationRun(t, nil, func(f *fakeExec) { f.failCfg = map[string]string{"SW1": line} })
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	wait(t, r, Failed)
	noSecrets(t, "el motivo del fallo", allText(r, a))
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "rollback-1")
	if !strings.Contains(strings.Join(r.Pending().Lines, " "), hidden) {
		t.Errorf("la reversa muestra el hash oculto: %v", r.Pending().Lines)
	}
	noSecrets(t, "el paso de reversa", allText(r, a))
	r.Confirm("rollback-1")
	wait(t, r, RolledBack)
	<-r.Done()
	noSecrets(t, "la reversa completa", allText(r, a))
	// El hash previo se mandó tal cual al equipo, sin enmascarar.
	if !strings.Contains(strings.Join(vx.Calls(), "\n"), "secret 9 "+oldHash9) {
		t.Errorf("la reversa no usó el hash previo: %v", vx.Calls())
	}
}

func TestRotationVerifiesNewLoginAfterPostCheckBeforeFinishing(t *testing.T) {
	r, vx, _ := rotationRun(t, nil)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "save-1")
	r.Confirm("save-1")
	wait(t, r, Done)
	calls := strings.Join(vx.Calls(), "\n")
	iCfg, iVerify := strings.Index(calls, "cfg SW1"), strings.Index(calls, "verify SW1")
	iPost := strings.LastIndex(calls, "read SW1: "+credUsersCmd)
	if iCfg < 0 || iVerify < iPost || iPost < iCfg {
		t.Errorf("el orden debe ser configurar, post-check, verificar:\n%s", calls)
	}
	if vx.reverted != 0 {
		t.Errorf("no hubo reversa")
	}
}

func TestRotationLoginFailureStopsAndRollsBackThroughOriginalSession(t *testing.T) {
	r, vx, a := rotationRun(t, errors.New("autenticación rechazada"))
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	wait(t, r, Failed)
	if !strings.Contains(r.FailReason(), "autenticación rechazada") {
		t.Errorf("motivo: %s", r.FailReason())
	}
	if r.Snapshot().Changed[0] != "SW1" || !r.Snapshot().Waiting || !r.Snapshot().CanRollback {
		t.Errorf("debe ofrecer la reversa: %+v", r.Snapshot())
	}
	r.Rollback()
	pending(t, r, "rollback-1")
	r.Confirm("rollback-1")
	wait(t, r, RolledBack)
	<-r.Done()
	if vx.reverted != 1 {
		t.Errorf("la reversa debe avisar al ejecutor para que la bóveda vuelva a la credencial anterior: %d", vx.reverted)
	}
	if vx.verified != 1 {
		t.Errorf("verified = %d", vx.verified)
	}
	noSecrets(t, "el fallo de login", allText(r, a))
}

func TestRotationPlanNeedsAnExecutorThatCanVerify(t *testing.T) {
	outs := rotOuts(usersOut("username tech secret 9 "+oldHash9), xe17)
	dp, err := CredRotatePlan("SW1", CredRotateChange{User: "tech", NewSecret: newSec, ConnectedUser: "admin"}, outs)
	if err != nil {
		t.Fatal(err)
	}
	ex := &fakeExec{}
	_, err = NewRun(Options{ID: "r", Plan: Plan{Function: CredRotate.Name, Devices: []DevicePlan{dp}}, Fn: CredRotate, Assisted: true, Exec: ex, Audit: func(a, b, c string) {}})
	if err == nil {
		t.Fatal("un ejecutor que no sabe verificar no puede ejecutar una rotación")
	}
	if len(ex.Calls()) != 0 {
		t.Errorf("hubo llamadas: %v", ex.Calls())
	}
	dp.VerifyLogin = false
	if err := Validate(Plan{Function: CredRotate.Name, Devices: []DevicePlan{dp}}, CredRotate); !errors.Is(err, ErrInvalidPlan) {
		t.Errorf("una rotación sin verificación no es un plan válido: %v", err)
	}
}

// La rotación sin write memory dejaría al equipo con el hash viejo tras un reinicio y a la bóveda con el nuevo.
func TestRotationPlanNeedsWriteMemory(t *testing.T) {
	outs := rotOuts(usersOut("username tech secret 9 "+oldHash9), xe17)
	dp, err := CredRotatePlan("SW1", CredRotateChange{User: "tech", NewSecret: newSec, ConnectedUser: "admin"}, outs)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(Plan{Function: CredRotate.Name, Devices: []DevicePlan{dp}}, CredRotate); !errors.Is(err, ErrInvalidPlan) {
		t.Errorf("sin write memory el plan no es válido: %v", err)
	}
	if err := Validate(Plan{Function: CredRotate.Name, WriteMemory: true, Devices: []DevicePlan{dp}}, CredRotate); err != nil {
		t.Error(err)
	}
}

func TestRotationVaultIsUpdatedOnlyAfterASuccessfulSave(t *testing.T) {
	r, vx, a := rotationRun(t, nil)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "save-1")
	if vx.saved != 0 || vx.verified != 1 {
		t.Fatalf("antes de guardar la bóveda no cambia: saved=%d verified=%d", vx.saved, vx.verified)
	}
	r.Confirm("save-1")
	wait(t, r, Done)
	<-r.Done()
	calls := strings.Join(vx.Calls(), "\n")
	if vx.saved != 1 || strings.Index(calls, "save SW1") > strings.Index(calls, "saved SW1") || !strings.Contains(calls, "save SW1") {
		t.Errorf("la bóveda se actualiza después de write memory:\n%s", calls)
	}
	noSecrets(t, "la rotación completa", allText(r, a))
}

func TestRotationRejectedSaveProposesRollbackAndLeavesVaultAlone(t *testing.T) {
	r, vx, _ := rotationRun(t, nil)
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "save-1")
	if err := r.Abort(); err != nil { // el ingeniero rechaza write memory
		t.Fatal(err)
	}
	wait(t, r, Failed)
	if sn := r.Snapshot(); !sn.Waiting || !sn.CanRollback || sn.Changed[0] != "SW1" {
		t.Fatalf("debe ofrecer la reversa, no terminar: %+v", sn)
	}
	if !strings.Contains(r.FailReason(), "write memory") {
		t.Errorf("motivo: %s", r.FailReason())
	}
	if vx.saved != 0 {
		t.Errorf("la bóveda no debe tocarse: saved=%d", vx.saved)
	}
	if err := r.Rollback(); err != nil {
		t.Fatal(err)
	}
	pending(t, r, "rollback-1")
	r.Confirm("rollback-1")
	wait(t, r, RolledBack)
	<-r.Done()
	if vx.saved != 0 || vx.reverted != 1 || strings.Contains(strings.Join(vx.Calls(), "|"), "save SW1") {
		t.Errorf("saved=%d reverted=%d calls=%v", vx.saved, vx.reverted, vx.Calls())
	}
}

func TestRotationSaveErrorProposesRollbackAndLeavesVaultAlone(t *testing.T) {
	r, vx, _ := rotationRunWith(t, nil, func(v *verifyExec) { v.saveText = "%Error opening nvram:/startup-config (No space left on device)" })
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "save-1")
	r.Confirm("save-1")
	wait(t, r, Failed)
	if sn := r.Snapshot(); !sn.Waiting || !sn.CanRollback {
		t.Fatalf("debe ofrecer la reversa: %+v", sn)
	}
	if vx.saved != 0 {
		t.Errorf("la bóveda no debe tocarse: saved=%d", vx.saved)
	}
	r.Abort()
	<-r.Done()
}

// Si la bóveda no se puede actualizar tras guardar, la ejecución no termina en done como si nada.
func TestRotationVaultFailureAfterSaveIsAFailure(t *testing.T) {
	r, vx, _ := rotationRunWith(t, nil, func(v *verifyExec) { v.savedErr = errors.New("la bóveda está bloqueada") })
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	pending(t, r, "save-1")
	r.Confirm("save-1")
	wait(t, r, Failed)
	if !strings.Contains(r.FailReason(), "la bóveda está bloqueada") || vx.saved != 1 {
		t.Errorf("motivo: %s saved=%d", r.FailReason(), vx.saved)
	}
	r.Abort()
	<-r.Done()
}

// Si la bóveda no vuelve a la credencial anterior, el error con código va a la auditoría en inglés
// (la pantalla lo recibe en español).
func TestRotationRevertedErrorGoesToAuditInEnglish(t *testing.T) {
	coded := i18n.New("ingest.invalid.addr.any", nil)
	r, _, a := rotationRunWith(t, errors.New("autenticación rechazada"), func(v *verifyExec) { v.revertErr = coded })
	r.Start(context.Background())
	pending(t, r, "apply-1")
	r.Confirm("apply-1")
	wait(t, r, Failed)
	r.Rollback()
	pending(t, r, "rollback-1")
	r.Confirm("rollback-1")
	wait(t, r, RolledBack)
	<-r.Done()
	if txt := a.text(); !strings.Contains(txt, coded.Localize(i18n.En)) || strings.Contains(txt, coded.Error()) {
		t.Fatalf("la auditoría debe traer el texto en inglés del error:\n%s", txt)
	}
}
