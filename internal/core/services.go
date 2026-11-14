package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/engine"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/pack"
	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

// ---- Bóveda ----

type vaultSvc struct {
	v1.UnimplementedVaultServiceServer
	c *Core
}

func (s *vaultSvc) v(ctx context.Context) (*vault.Vault, error) {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	if s.c.vault == nil {
		return nil, service.Err(ctx, codes.FailedPrecondition, "patrol.svc.no_vault_create", nil)
	}
	return s.c.vault, nil
}

func (s *vaultSvc) Status(context.Context, *v1.StatusRequest) (*v1.StatusResponse, error) {
	r := &v1.StatusResponse{State: s.c.vaultState()}
	s.c.mu.Lock()
	if s.c.vault != nil {
		for _, w := range s.c.vault.Windows() {
			r.ArmedJobIds = append(r.ArmedJobIds, w.JobID)
		}
	}
	s.c.mu.Unlock()
	return r, nil
}

func (s *vaultSvc) Create(ctx context.Context, r *v1.CreateRequest) (*v1.CreateResponse, error) {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	if s.c.vault != nil {
		return nil, service.Err(ctx, codes.AlreadyExists, "patrol.svc.vault_exists", nil)
	}
	p := vault.Calibrate(time.Second)
	if s.c.o.VaultParams != nil {
		p = *s.c.o.VaultParams
	}
	v, err := vault.Create(s.c.vaultPath(), r.MasterPassword, p)
	if err != nil {
		return nil, service.VaultErr(ctx, err)
	}
	v.SetClock(s.c.o.Now)
	v.OnLock(s.c.respaldos.wipeAll)
	s.c.vault = v
	s.c.activity = s.c.o.Now() // el reloj de inactividad cuenta desde que la bóveda queda abierta
	s.c.mu.Unlock()
	s.c.audit("vault.create", "", fmt.Sprintf("argon2id m=%dKiB t=%d p=%d", p.MemoryKiB, p.Iterations, p.Threads))
	s.c.mu.Lock()
	return &v1.CreateResponse{}, nil
}

func (s *vaultSvc) Unlock(ctx context.Context, r *v1.UnlockRequest) (*v1.UnlockResponse, error) {
	s.c.markActive()
	v, err := s.v(ctx)
	if err != nil {
		return nil, err
	}
	if err := v.Unlock(r.MasterPassword); err != nil {
		s.c.audit("vault.unlock_failed", "", "")
		return nil, service.VaultErr(ctx, err)
	}
	s.c.markActive()
	s.c.audit("vault.unlock", "", "")
	s.c.resumePaused()
	return &v1.UnlockResponse{}, nil
}

func (s *vaultSvc) Lock(ctx context.Context, _ *v1.LockRequest) (*v1.LockResponse, error) {
	v, err := s.v(ctx)
	if err != nil {
		return nil, err
	}
	v.Lock()
	s.c.audit("vault.lock", "", "reason=user")
	return &v1.LockResponse{}, nil
}

func (s *vaultSvc) ChangeMasterPassword(ctx context.Context, r *v1.ChangeMasterPasswordRequest) (*v1.ChangeMasterPasswordResponse, error) {
	s.c.markActive()
	v, err := s.v(ctx)
	if err != nil {
		return nil, err
	}
	if err := v.ChangeMasterPassword(r.CurrentMasterPassword, r.NewMasterPassword); err != nil {
		return nil, service.VaultErr(ctx, err)
	}
	s.c.audit("vault.change_master", "", "")
	return &v1.ChangeMasterPasswordResponse{}, nil
}

func (s *vaultSvc) ListCredentials(ctx context.Context, _ *v1.ListCredentialsRequest) (*v1.ListCredentialsResponse, error) {
	v, err := s.v(ctx)
	if err != nil {
		return nil, err
	}
	infos, err := v.List()
	if err != nil {
		return nil, service.VaultErr(ctx, err)
	}
	r := &v1.ListCredentialsResponse{}
	for _, i := range infos {
		r.Credentials = append(r.Credentials, &v1.CredentialInfo{Id: i.ID, Label: i.Label, Username: i.Username, HasEnableSecret: i.HasEnable, HasSshKey: i.HasSSHKey})
	}
	return r, nil
}

func (s *vaultSvc) PutCredential(ctx context.Context, r *v1.PutCredentialRequest) (*v1.PutCredentialResponse, error) {
	s.c.markActive()
	v, err := s.v(ctx)
	if err != nil {
		return nil, err
	}
	if vault.Reserved(r.Label) {
		return nil, service.Err(ctx, codes.InvalidArgument, "patrol.svc.reserved_label", i18n.A("label", r.Label))
	}
	// secret.New pone en ceros los bytes recibidos; el búfer de gRPC del cable no se puede borrar.
	c := vault.Credential{ID: r.Id, Label: r.Label, Username: r.Username,
		Password: secret.New(r.Password), Enable: secret.New(r.EnableSecret), SSHKey: secret.New(r.SshPrivateKey)}
	defer c.Password.Destroy()
	defer c.Enable.Destroy()
	defer c.SSHKey.Destroy()
	id, err := v.Put(c)
	if err != nil {
		return nil, service.VaultErr(ctx, err)
	}
	s.c.audit("credential.put", id, "")
	return &v1.PutCredentialResponse{Id: id}, nil
}

func (s *vaultSvc) DeleteCredential(ctx context.Context, r *v1.DeleteCredentialRequest) (*v1.DeleteCredentialResponse, error) {
	s.c.markActive()
	v, err := s.v(ctx)
	if err != nil {
		return nil, err
	}
	if err := v.Delete(r.Id); err != nil {
		return nil, service.VaultErr(ctx, err)
	}
	s.c.audit("credential.delete", r.Id, "")
	return &v1.DeleteCredentialResponse{}, nil
}

// ---- Patrol ----

type patrolSvc struct {
	v1.UnimplementedPatrolServiceServer
	c *Core
}

// jobKinds son los tipos de trabajo; vacío es patrol (specs viejas, mctl y la UI).
var jobKinds = []string{"", "patrol", "adhoc", "backup", "change"}

// validate traduce y revisa un JobSpec; también la usa la ventana de cambio.
func (s *patrolSvc) validate(ctx context.Context, p *v1.JobSpec) (patrol.Spec, error) {
	spec := specFromProto(p)
	s.c.mu.Lock()
	v := s.c.vault
	s.c.mu.Unlock()
	if v == nil {
		return spec, service.Err(ctx, codes.FailedPrecondition, "patrol.svc.no_vault", nil)
	}
	if !slices.Contains(jobKinds, spec.Kind) {
		return spec, service.Err(ctx, codes.InvalidArgument, "patrol.svc.bad_kind", i18n.A("kind", spec.Kind))
	}
	// Un output_dir explícito pasa por la validación de Ajustes → Almacenamiento; vacío = la carpeta vigente.
	if spec.OutputDir == "" {
		spec.OutputDir = s.c.settings.Outputs()
	} else if dir, err := service.CheckOutputs(spec.OutputDir, s.c.settings, true); err != nil {
		return spec, err
	} else {
		spec.OutputDir = dir
	}
	if err := patrol.ValidateWith(spec, s.c.catalog(), v, s.c.missingPack); err != nil {
		var fe *patrol.FieldError
		if errors.As(err, &fe) {
			return spec, service.ErrFrom(ctx, codes.InvalidArgument, err)
		}
		return spec, service.ErrFrom(ctx, codes.FailedPrecondition, err)
	}
	return spec, nil
}

func (s *patrolSvc) CreateJob(ctx context.Context, r *v1.CreateJobRequest) (*v1.CreateJobResponse, error) {
	s.c.markActive()
	spec, err := s.validate(ctx, r.GetSpec())
	if err != nil {
		return nil, err
	}
	j := &job{id: service.NewID(), spec: spec, state: "created", pbs: s.c.catalog(), results: map[int][]patrol.DeviceResult{}}
	s.c.mu.Lock()
	s.c.jobs[j.id] = j
	s.c.mu.Unlock()
	s.c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_CREATED, 0, "", nil)
	sum := sha256.Sum256([]byte(spec.CustomCommands))
	detail := fmt.Sprintf("name=%s devices=%d playbooks=%v pasted_commands_sha256=%s masked=%v",
		spec.Name, len(spec.Targets), spec.PlaybookIDs, hex.EncodeToString(sum[:]), !spec.DisableMasking)
	if len(spec.Params) > 0 {
		detail += fmt.Sprintf(" params=%v", spec.Params) // validados; no son secretos
	}
	s.c.audit("job.create", j.id, detail)
	return &v1.CreateJobResponse{JobId: j.id}, nil
}

func loginToProto(loc string, r patrol.LoginResult) *v1.LoginTestResponse {
	detail, reason, args := detailOf(loc, r.Detail, r.DetailErr)
	return &v1.LoginTestResponse{Target: &v1.Target{Address: r.Target}, Passed: r.Passed, FailedStep: loginSteps[r.FailedStep],
		Detail: detail, DetectedPlatform: r.Platform, HostKeyFingerprint: r.Fingerprint, Reason: reason, Args: args}
}

func (s *patrolSvc) LoginTest(r *v1.LoginTestRequest, st v1.PatrolService_LoginTestServer) error {
	j, err := s.c.getJob(r.JobId)
	if err != nil {
		return err
	}
	s.c.markActive()
	s.c.mu.Lock()
	spec, state := j.spec, j.state
	s.c.mu.Unlock()
	if state != "created" {
		return service.Err(st.Context(), codes.FailedPrecondition, "patrol.svc.login_after_arm", i18n.A("state", state))
	}
	res := patrol.LoginTest(st.Context(), s.c.deps(j), j.id, spec, true, nil)
	passed := 0
	for _, x := range res {
		if x.Passed {
			passed++
		}
		if err := st.Send(loginToProto(i18n.Locale(st.Context()), x)); err != nil {
			return err
		}
	}
	s.c.audit("job.logintest", j.id, fmt.Sprintf("passed=%d of %d", passed, len(res)))
	s.c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_LOGIN_TEST_DONE, 0, "phase.ok_failed", i18n.A("ok", passed, "failed", len(res)-passed))
	return nil
}

func (s *patrolSvc) ArmJob(ctx context.Context, r *v1.ArmJobRequest) (*v1.ArmJobResponse, error) {
	c := s.c
	c.markActive()
	j, err := c.getJob(r.JobId)
	if err != nil {
		return nil, err
	}
	// Un solo armado a la vez: el estado pasa a "arming" en la misma sección en que se revisa.
	c.mu.Lock()
	if j.state != "created" {
		st := j.state
		c.mu.Unlock()
		return nil, service.Err(ctx, codes.FailedPrecondition, "patrol.svc.job_state", i18n.A("state", st))
	}
	j.state = "arming"
	spec, v := j.spec, c.vault
	c.mu.Unlock()
	var undo []func()
	// reason es el motivo en inglés para la auditoría (no depende del idioma del cliente).
	fail := func(err error, reason string) (*v1.ArmJobResponse, error) {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
		c.mu.Lock()
		j.state = "created"
		if j.cancelReq { // cancelaron durante el armado fallido: no vuelve a "created"
			j.cancelReq, j.state = false, "cancelled"
		}
		c.mu.Unlock()
		c.persistJob(j) // la fase del Login Test ya guardó "arming"; al recargar no debe verse como caído
		c.audit("job.arm_failed", j.id, reason)
		return nil, err
	}

	excluded := map[string]bool{}
	for _, id := range r.ExcludedDeviceIds {
		excluded[id] = true
	}
	var keep []patrol.Target
	for _, t := range spec.Targets {
		// Se acepta el ID, la dirección o el host:puerto que muestra el Login Test.
		if !excluded[t.DeviceID] && !excluded[t.Address] && !excluded[patrolHostport(t)] {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		return fail(service.Err(ctx, codes.FailedPrecondition, "patrol.svc.no_devices_left", nil), "no devices left")
	}
	spec.Targets = keep // copia local: un armado fallido no altera el trabajo
	accepted := map[string]bool{}
	for _, fp := range r.AcceptedHostKeyFingerprints {
		accepted[fp] = true
	}
	// Login Test obligatorio al armar, con las huellas que confirmó el ingeniero (spec §12.2).
	res := patrol.LoginTest(ctx, c.deps(j), j.id, spec, true, accepted)
	verified := map[string]bool{}
	var changes []patrol.HostKeyChange
	var failed []string
	for _, x := range res {
		if !x.Passed {
			failed = append(failed, x.Target+": "+x.FailedStep)
			continue
		}
		verified[x.Target] = true
		if x.ChangedHostKey != nil {
			changes = append(changes, *x.ChangedHostKey)
		}
	}
	undo = append(undo, func() { c.guard.Revoke(j.id) })
	c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_ARM_CHECK_DONE, 0, "phase.ok_failed", i18n.A("ok", len(res)-len(failed), "failed", len(failed)))
	if len(failed) > 0 {
		return fail(service.Err(ctx, codes.FailedPrecondition, "patrol.svc.login_failed", i18n.A("failed", strings.Join(failed, "; "))), "login test failed: "+strings.Join(failed, "; "))
	}
	until := c.o.Now().Add(time.Duration(spec.WindowHours) * time.Hour)
	creds := []string{spec.DefaultCredentialID}
	for _, o := range spec.Overrides {
		for _, id := range []string{o.CredentialID, o.FallbackCredentialID} {
			if id != "" {
				creds = append(creds, id)
			}
		}
	}
	if err := v.Arm(j.id, until, creds); err != nil {
		return fail(service.VaultErr(ctx, err), i18n.English(err))
	}
	undo = append(undo, func() { v.Disarm(j.id) })
	w, err := patrol.NewWriter(spec.OutputDir, spec, c.o.Now())
	if err != nil {
		return fail(status.Error(codes.FailedPrecondition, err.Error()), i18n.English(err))
	}
	for _, ch := range changes {
		w.NoteHostKeyChange(ch)
	}
	release, missing := c.o.Inhibitor.Take("Trabajo armado: " + spec.Name)
	undo = append(undo, release)

	byHP := map[string]patrol.Target{}
	var targets []string
	for _, t := range spec.Targets {
		hp := patrolHostport(t)
		byHP[hp] = t
		targets = append(targets, hp)
	}
	c.mu.Lock()
	j.spec, j.verified, j.changes, j.Until, j.creds, j.writer, j.release = spec, verified, changes, until, creds, w, release
	j.OutputDir = w.Dir()
	c.mu.Unlock()
	run := func(ctx context.Context, round int, hp string) error {
		ctx, cancelWin := windowCtx(ctx, until, c.o.Now())
		defer cancelWin()
		res := patrol.RunDevice(ctx, c.deps(j), j.id, spec, w, round, byHP[hp], func(p patrol.Progress) {
			kind := engine.DeviceState
			if p.State == "running" {
				kind = engine.Progress
			}
			c.bus.Publish(engine.Event{JobID: j.id, Kind: kind, DeviceID: p.Target, State: p.State, Command: p.Command, Index: p.Index, Total: p.Total, Bytes: p.Bytes, Detail: p.Detail, Err: p.Err})
		})
		c.mu.Lock()
		j.results[round] = append(j.results[round], res)
		j.enterRound(round)
		if res.State == "completed" {
			j.OK++
		} else {
			j.Failed++
		}
		c.mu.Unlock()
		if res.State != "completed" {
			return errors.New(res.Detail)
		}
		return nil
	}
	c.mu.Lock()
	if j.cancelReq {
		j.cancelReq, j.state = false, "cancelled"
		c.mu.Unlock()
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
		c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_CANCELLED, 0, "phase.before_arming", nil)
		return nil, service.Err(ctx, codes.FailedPrecondition, "patrol.svc.job_state", i18n.A("state", "cancelled"))
	}
	c.mu.Unlock()
	events, cancelSub := c.bus.Subscribe([]string{j.id})
	if err := c.sched.Arm(j.id, engineSchedule(spec.Schedule), until, targets, run); err != nil {
		cancelSub()
		return fail(status.Error(codes.InvalidArgument, err.Error()), i18n.English(err))
	}
	c.mu.Lock()
	j.state, j.ArmedAt = "armed", c.o.Now()
	late := j.cancelReq // la cancelación llegó entre la revisión y el armado
	j.cancelReq = false
	c.mu.Unlock()
	if late {
		defer c.sched.Cancel(j.id)
	}
	armed, armedArgs := "phase.devices", i18n.A("n", len(spec.Targets))
	if n := len(r.ExcludedDeviceIds); n > 0 {
		armed, armedArgs = "phase.devices_excluded", i18n.A("n", len(spec.Targets), "excluded", n)
	}
	// Antes de lanzar watch: así ARMED queda antes de ROUND_STARTED de la primera ronda.
	c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_ARMED, 0, armed, armedArgs)
	c.watchers.Add(1)
	go c.watch(j, events, cancelSub)
	c.audit("job.arm", j.id, fmt.Sprintf("window_until=%s excluded=%v", until.UTC().Format(time.RFC3339), r.ExcludedDeviceIds))
	c.audit("power.inhibit", j.id, fmt.Sprintf("missing=%v", missing))
	return &v1.ArmJobResponse{WindowEndsAt: timestamppb.New(until), MissingInhibitors: missing}, nil
}

func patrolHostport(t patrol.Target) string {
	return fmt.Sprintf("%s:%d", t.Address, patrol.EffectivePort(t.Port))
}

// watch empaqueta cada ronda y cierra el trabajo al terminar.
func (c *Core) watch(j *job, events <-chan engine.Event, cancel func()) {
	defer c.watchers.Done()
	defer cancel()
	for e := range events {
		if e.Kind == engine.Warning && e.Detail == "round.skipped" {
			// Rondas perdidas por pausa o por una ronda anterior aún en curso (spec §10.4).
			j.writer.NoteSkippedRound(e.Index)
			c.audit("round.skipped", j.id, fmt.Sprintf("round=%d", e.Index))
			c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_ROUND_SKIPPED, e.Index, "", nil)
			continue
		}
		if e.Kind != engine.JobState {
			continue
		}
		switch e.State {
		case "round.start":
			c.mu.Lock()
			j.enterRound(e.Index)
			c.mu.Unlock()
			c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_ROUND_STARTED, e.Index, "", nil)
		case "round.end":
			c.mu.Lock()
			j.rounds = e.Index
			ok, failed := j.OK, j.Failed
			c.mu.Unlock()
			c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_ROUND_FINISHED, e.Index, "phase.ok_failed", i18n.A("ok", ok, "failed", failed))
			if zip, err := patrol.RoundDone(j.writer, j.spec, e.Index); err != nil {
				c.audit("job.zip_failed", j.id, i18n.English(err))
				c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_FAILED, e.Index, "phase.round_zip_failed", i18n.A("error", err.Error()))
			} else if zip != "" {
				c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_PACKAGED, e.Index, "phase.packaged", i18n.A("path", zip))
			}
		case "completed", "cancelled":
			c.finish(j, e.State)
			return
		}
	}
}

func (c *Core) finish(j *job, state string) {
	c.mu.Lock()
	if j.state == "completed" || j.state == "cancelled" {
		c.mu.Unlock()
		return
	}
	j.state = state
	w := j.writer
	var all []patrol.DeviceResult
	for r := 1; r <= j.rounds; r++ {
		all = append(all, j.results[r]...)
	}
	v, rounds, spec, release := c.vault, j.rounds, j.spec, j.release
	c.mu.Unlock()
	if w != nil {
		if _, err := patrol.Finish(context.Background(), c.deps(j), w, spec, rounds, all); err != nil {
			c.audit("job.finish_failed", j.id, i18n.English(err))
			c.mu.Lock()
			j.FinishErr = err.Error()
			c.mu.Unlock()
			c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_FAILED, 0, "phase.close_failed", i18n.A("error", err.Error()))
		} else if zip := patrol.FinalZip(w, spec); zip != "" {
			c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_PACKAGED, 0, "phase.packaged", i18n.A("path", zip))
		}
	}
	if v != nil {
		v.Disarm(j.id) // al terminar la última ronda la DEK se borra si nadie más la necesita (spec §10.4)
	}
	c.guard.Revoke(j.id)
	if release != nil {
		release()
		c.audit("power.release", j.id, "")
	}
	c.audit("job."+state, j.id, fmt.Sprintf("rounds=%d", rounds))
	c.addPhase(j, endPhase[state], 0, "phase.rounds", i18n.A("n", rounds))
	// "closed" sale cuando el manifest y el zip ya existen: es lo que la UI espera para ofrecer el paquete.
	detail := ""
	if w != nil {
		detail = w.Dir()
	}
	c.bus.Publish(engine.Event{JobID: j.id, Kind: engine.JobState, State: "closed", Detail: detail})
}

var endPhase = map[string]v1.JobPhaseKind{"completed": v1.JobPhaseKind_JOB_PHASE_KIND_COMPLETED, "cancelled": v1.JobPhaseKind_JOB_PHASE_KIND_CANCELLED}

func (s *patrolSvc) CancelJob(_ context.Context, r *v1.CancelJobRequest) (*v1.CancelJobResponse, error) {
	s.c.markActive()
	j, err := s.c.getJob(r.JobId)
	if err != nil {
		return nil, err
	}
	s.c.audit("job.cancel", j.id, "")
	s.c.mu.Lock()
	created := j.state == "created"
	if j.state == "arming" {
		j.cancelReq = true // ArmJob la atiende antes de armar en el planificador
	}
	if created {
		j.state = "cancelled" // nada que detener: solo deja de aparecer como vivo
	}
	s.c.mu.Unlock()
	if created {
		s.c.guard.Revoke(j.id)
		s.c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_CANCELLED, 0, "phase.before_arming", nil)
		return &v1.CancelJobResponse{}, nil
	}
	s.c.sched.Cancel(j.id)
	return &v1.CancelJobResponse{}, nil
}

func (s *patrolSvc) ListJobs(ctx context.Context, _ *v1.ListJobsRequest) (*v1.ListJobsResponse, error) {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	r := &v1.ListJobsResponse{}
	for _, j := range s.c.jobs {
		r.Jobs = append(r.Jobs, s.c.summary(i18n.Locale(ctx), j))
	}
	return r, nil
}

// ListPlaybooks devuelve los playbooks ya cargados (embebidos, de paquetes y de config/playbooks), ordenados por id;
// el id es el mismo que CreateJob acepta en playbook_ids.
func (s *patrolSvc) ListPlaybooks(ctx context.Context, r *v1.ListPlaybooksRequest) (*v1.ListPlaybooksResponse, error) {
	out := &v1.ListPlaybooksResponse{}
	pbs := s.c.catalog()
	if r.GetPlatform() != "" {
		pbs = playbook.Visible(r.GetPlatform(), pbs) // ios lista los de ios-xe que oom/ios no reemplaza
	}
	var hidden map[string]bool
	if s.c.packs != nil && s.c.db != nil { // sin almacén o sin base (núcleo mínimo de prueba) no hay nada oculto
		h, _, err := pack.HiddenSets(s.c.db, s.c.packs.Snapshot(), s.c.userIDs()) // ocultos: fuera de la lista; CreateJob los sigue resolviendo
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		hidden = h
	}
	for _, p := range pbs {
		if hidden[p.ID] {
			continue
		}
		info := &v1.PlaybookInfo{Id: p.ID, Platform: p.Platform, Name: p.NameFor(i18n.Locale(ctx)), Commands: slices.Clone(p.Pre)} // los pre corren primero
		for _, c := range p.Commands {
			if r.GetPlatform() == "" || c.Applies(r.GetPlatform()) { // sin plataforma, todos; con ella, los que corren ahí
				info.Commands = append(info.Commands, c.Text)
			}
		}
		for _, q := range p.Params {
			info.Params = append(info.Params, &v1.PlaybookParam{Name: q.Name, Kind: q.Kind})
		}
		out.Playbooks = append(out.Playbooks, info)
	}
	sort.Slice(out.Playbooks, func(i, j int) bool { return out.Playbooks[i].Id < out.Playbooks[j].Id })
	return out, nil
}

func (s *patrolSvc) GetRun(ctx context.Context, r *v1.GetRunRequest) (*v1.GetRunResponse, error) {
	j, err := s.c.getJob(r.JobId)
	if err != nil {
		return nil, err
	}
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	out := &v1.GetRunResponse{}
	if j.writer != nil {
		out.OutputPath = j.writer.Dir()
	}
	for _, d := range j.results[int(r.Round)] {
		detail, reason, args := detailOf(i18n.Locale(ctx), d.Detail, d.DetailErr)
		out.Devices = append(out.Devices, &v1.RunDevice{Target: &v1.Target{Address: d.Target.Address, Port: uint32(patrol.EffectivePort(d.Target.Port)), DeviceId: d.Target.DeviceID},
			State: deviceStates[d.State], Detail: detail, Reason: reason, Args: args})
	}
	return out, nil
}

// ---- Eventos ----

type eventSvc struct {
	v1.UnimplementedEventServiceServer
	c *Core
}

func (s *eventSvc) Subscribe(r *v1.SubscribeRequest, st v1.EventService_SubscribeServer) error {
	ch, cancel := s.c.bus.Subscribe(r.JobIds)
	defer cancel()
	st.SendHeader(nil)
	for {
		select {
		case <-st.Context().Done():
			return nil
		case e, ok := <-ch:
			if !ok {
				return nil
			}
			if err := st.Send(eventToProto(i18n.Locale(st.Context()), e)); err != nil {
				return err
			}
		}
	}
}

// ---- Auditoría ----

type auditSvc struct {
	v1.UnimplementedAuditServiceServer
	c *Core
}

func (s *auditSvc) Verify(ctx context.Context, _ *v1.VerifyRequest) (*v1.VerifyResponse, error) {
	v, err := s.c.log.Verify(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &v1.VerifyResponse{Intact: v.Intact, FirstBrokenSeq: v.FirstBroken, HeadHash: v.Head}, nil
}

func (s *auditSvc) Export(r *v1.ExportRequest, st v1.AuditService_ExportServer) error {
	from, to := time.Time{}, time.Now().Add(24*time.Hour)
	if r.From != nil {
		from = r.From.AsTime()
	}
	if r.To != nil {
		to = r.To.AsTime()
	}
	var buf bytes.Buffer
	if err := s.c.log.Export(st.Context(), &buf, from, to); err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	for _, ln := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if ln == "" {
			continue
		}
		if err := st.Send(&v1.ExportResponse{JsonLine: ln}); err != nil {
			return err
		}
	}
	return nil
}

// windowCtx limita a un equipo al fin de la ventana de la bóveda (until), no a Schedule.Until, que solo
// impide empezar rondas nuevas. El plazo es relativo al reloj del núcleo; si ya pasó, nace vencido.
func windowCtx(ctx context.Context, until, now time.Time) (context.Context, context.CancelFunc) {
	return context.WithTimeoutCause(ctx, until.Sub(now), patrol.ErrWindowEnded)
}
