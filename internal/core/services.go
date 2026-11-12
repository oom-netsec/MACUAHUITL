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
	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

// ---- Bóveda ----

type vaultSvc struct {
	v1.UnimplementedVaultServiceServer
	c *Core
}

func (s *vaultSvc) v() (*vault.Vault, error) {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	if s.c.vault == nil {
		return nil, status.Error(codes.FailedPrecondition, "no hay bóveda; créala primero")
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

func (s *vaultSvc) Create(_ context.Context, r *v1.CreateRequest) (*v1.CreateResponse, error) {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	if s.c.vault != nil {
		return nil, status.Error(codes.AlreadyExists, "la bóveda ya existe")
	}
	p := vault.Calibrate(time.Second)
	if s.c.o.VaultParams != nil {
		p = *s.c.o.VaultParams
	}
	v, err := vault.Create(s.c.vaultPath(), r.MasterPassword, p)
	if err != nil {
		return nil, service.VaultErr(err)
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

func (s *vaultSvc) Unlock(_ context.Context, r *v1.UnlockRequest) (*v1.UnlockResponse, error) {
	s.c.markActive()
	v, err := s.v()
	if err != nil {
		return nil, err
	}
	if err := v.Unlock(r.MasterPassword); err != nil {
		s.c.audit("vault.unlock_failed", "", "")
		return nil, service.VaultErr(err)
	}
	s.c.markActive()
	s.c.audit("vault.unlock", "", "")
	s.c.resumePaused()
	return &v1.UnlockResponse{}, nil
}

func (s *vaultSvc) Lock(context.Context, *v1.LockRequest) (*v1.LockResponse, error) {
	v, err := s.v()
	if err != nil {
		return nil, err
	}
	v.Lock()
	s.c.audit("vault.lock", "", "usuario")
	return &v1.LockResponse{}, nil
}

func (s *vaultSvc) ChangeMasterPassword(_ context.Context, r *v1.ChangeMasterPasswordRequest) (*v1.ChangeMasterPasswordResponse, error) {
	s.c.markActive()
	v, err := s.v()
	if err != nil {
		return nil, err
	}
	if err := v.ChangeMasterPassword(r.CurrentMasterPassword, r.NewMasterPassword); err != nil {
		return nil, service.VaultErr(err)
	}
	s.c.audit("vault.change_master", "", "")
	return &v1.ChangeMasterPasswordResponse{}, nil
}

func (s *vaultSvc) ListCredentials(context.Context, *v1.ListCredentialsRequest) (*v1.ListCredentialsResponse, error) {
	v, err := s.v()
	if err != nil {
		return nil, err
	}
	infos, err := v.List()
	if err != nil {
		return nil, service.VaultErr(err)
	}
	r := &v1.ListCredentialsResponse{}
	for _, i := range infos {
		r.Credentials = append(r.Credentials, &v1.CredentialInfo{Id: i.ID, Label: i.Label, Username: i.Username, HasEnableSecret: i.HasEnable, HasSshKey: i.HasSSHKey})
	}
	return r, nil
}

func (s *vaultSvc) PutCredential(_ context.Context, r *v1.PutCredentialRequest) (*v1.PutCredentialResponse, error) {
	s.c.markActive()
	v, err := s.v()
	if err != nil {
		return nil, err
	}
	if vault.Reserved(r.Label) {
		return nil, status.Errorf(codes.InvalidArgument, "la etiqueta %q está reservada para el sistema", r.Label)
	}
	// secret.New pone en ceros los bytes recibidos; el búfer de gRPC del cable no se puede borrar.
	c := vault.Credential{ID: r.Id, Label: r.Label, Username: r.Username,
		Password: secret.New(r.Password), Enable: secret.New(r.EnableSecret), SSHKey: secret.New(r.SshPrivateKey)}
	defer c.Password.Destroy()
	defer c.Enable.Destroy()
	defer c.SSHKey.Destroy()
	id, err := v.Put(c)
	if err != nil {
		return nil, service.VaultErr(err)
	}
	s.c.audit("credential.put", id, "")
	return &v1.PutCredentialResponse{Id: id}, nil
}

func (s *vaultSvc) DeleteCredential(_ context.Context, r *v1.DeleteCredentialRequest) (*v1.DeleteCredentialResponse, error) {
	s.c.markActive()
	v, err := s.v()
	if err != nil {
		return nil, err
	}
	if err := v.Delete(r.Id); err != nil {
		return nil, service.VaultErr(err)
	}
	s.c.audit("credential.delete", r.Id, "")
	return &v1.DeleteCredentialResponse{}, nil
}

// ---- Patrol ----

type patrolSvc struct {
	v1.UnimplementedPatrolServiceServer
	c *Core
}

// validate traduce y revisa un JobSpec; también la usa la ventana de cambio.
func (s *patrolSvc) validate(p *v1.JobSpec) (patrol.Spec, error) {
	spec := specFromProto(p)
	s.c.mu.Lock()
	v := s.c.vault
	s.c.mu.Unlock()
	if v == nil {
		return spec, status.Error(codes.FailedPrecondition, "no hay bóveda")
	}
	if err := patrol.Validate(spec, s.c.pbs, v); err != nil {
		var fe *patrol.FieldError
		if errors.As(err, &fe) {
			return spec, status.Error(codes.InvalidArgument, err.Error())
		}
		return spec, status.Error(codes.FailedPrecondition, err.Error())
	}
	return spec, nil
}

func (s *patrolSvc) CreateJob(_ context.Context, r *v1.CreateJobRequest) (*v1.CreateJobResponse, error) {
	s.c.markActive()
	spec, err := s.validate(r.GetSpec())
	if err != nil {
		return nil, err
	}
	j := &job{id: service.NewID(), spec: spec, state: "created", results: map[int][]patrol.DeviceResult{}}
	s.c.mu.Lock()
	s.c.jobs[j.id] = j
	s.c.mu.Unlock()
	s.c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_CREATED, 0, "")
	sum := sha256.Sum256([]byte(spec.CustomCommands))
	s.c.audit("job.create", j.id, fmt.Sprintf("nombre=%s equipos=%d playbooks=%v comandos_pegados_sha256=%s enmascarado=%v",
		spec.Name, len(spec.Targets), spec.PlaybookIDs, hex.EncodeToString(sum[:]), !spec.DisableMasking))
	return &v1.CreateJobResponse{JobId: j.id}, nil
}

func loginToProto(r patrol.LoginResult) *v1.LoginTestResponse {
	return &v1.LoginTestResponse{Target: &v1.Target{Address: r.Target}, Passed: r.Passed, FailedStep: loginSteps[r.FailedStep],
		Detail: r.Detail, DetectedPlatform: r.Platform, HostKeyFingerprint: r.Fingerprint}
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
		return status.Errorf(codes.FailedPrecondition, "el trabajo está %s; el Login Test solo aplica antes de armar", state)
	}
	res := patrol.LoginTest(st.Context(), s.c.deps(j), j.id, spec, true, nil)
	passed := 0
	for _, x := range res {
		if x.Passed {
			passed++
		}
		if err := st.Send(loginToProto(x)); err != nil {
			return err
		}
	}
	s.c.audit("job.logintest", j.id, fmt.Sprintf("pasaron=%d de %d", passed, len(res)))
	s.c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_LOGIN_TEST_DONE, 0, okFailed(passed, len(res)-passed))
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
		return nil, status.Errorf(codes.FailedPrecondition, "el trabajo está %s", st)
	}
	j.state = "arming"
	spec, v := j.spec, c.vault
	c.mu.Unlock()
	var undo []func()
	fail := func(err error) (*v1.ArmJobResponse, error) {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
		c.mu.Lock()
		j.state = "created"
		c.mu.Unlock()
		c.persistJob(j) // la fase del Login Test ya guardó "arming"; al recargar no debe verse como caído
		c.audit("job.arm_failed", j.id, status.Convert(err).Message())
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
		return fail(status.Error(codes.FailedPrecondition, "no quedan equipos"))
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
	c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_ARM_CHECK_DONE, 0, okFailed(len(res)-len(failed), len(failed)))
	if len(failed) > 0 {
		return fail(status.Errorf(codes.FailedPrecondition, "Login Test falló; excluye o corrige: %s", strings.Join(failed, "; ")))
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
		return fail(service.VaultErr(err))
	}
	undo = append(undo, func() { v.Disarm(j.id) })
	w, err := patrol.NewWriter(spec.OutputDir, spec, c.o.Now())
	if err != nil {
		return fail(status.Error(codes.FailedPrecondition, err.Error()))
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
		res := patrol.RunDevice(ctx, c.deps(j), j.id, spec, w, round, byHP[hp], func(p patrol.Progress) {
			kind := engine.DeviceState
			if p.State == "running" {
				kind = engine.Progress
			}
			c.bus.Publish(engine.Event{JobID: j.id, Kind: kind, DeviceID: p.Target, State: p.State, Command: p.Command, Index: p.Index, Total: p.Total, Bytes: p.Bytes, Detail: p.Detail})
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
	events, cancelSub := c.bus.Subscribe([]string{j.id})
	if err := c.sched.Arm(j.id, engineSchedule(spec.Schedule), until, targets, run); err != nil {
		cancelSub()
		return fail(status.Error(codes.InvalidArgument, err.Error()))
	}
	c.mu.Lock()
	j.state, j.ArmedAt = "armed", c.o.Now()
	c.mu.Unlock()
	armed := count(len(spec.Targets), "equipo", "equipos")
	if n := len(r.ExcludedDeviceIds); n > 0 {
		armed += ", " + count(n, "excluido", "excluidos")
	}
	// Antes de lanzar watch: así ARMED queda antes de ROUND_STARTED de la primera ronda.
	c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_ARMED, 0, armed)
	c.watchers.Add(1)
	go c.watch(j, events, cancelSub)
	c.audit("job.arm", j.id, fmt.Sprintf("ventana_hasta=%s excluidos=%v", until.UTC().Format(time.RFC3339), r.ExcludedDeviceIds))
	c.audit("power.inhibit", j.id, fmt.Sprintf("faltan=%v", missing))
	return &v1.ArmJobResponse{WindowEndsAt: timestamppb.New(until), MissingInhibitors: missing}, nil
}

// effectivePort es el puerto SSH que se usa de verdad: 0 en la spec significa el de omisión (22).
func effectivePort(p uint16) uint16 {
	if p == 0 {
		return 22
	}
	return p
}

func patrolHostport(t patrol.Target) string {
	return fmt.Sprintf("%s:%d", t.Address, effectivePort(t.Port))
}

// watch empaqueta cada ronda y cierra el trabajo al terminar.
func (c *Core) watch(j *job, events <-chan engine.Event, cancel func()) {
	defer c.watchers.Done()
	defer cancel()
	for e := range events {
		if e.Kind == engine.Warning && e.Detail == "round.skipped" {
			// Rondas perdidas por pausa o por una ronda anterior aún en curso (spec §10.4).
			j.writer.NoteSkippedRound(e.Index)
			c.audit("round.skipped", j.id, fmt.Sprintf("ronda=%d", e.Index))
			c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_ROUND_SKIPPED, e.Index, "")
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
			c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_ROUND_STARTED, e.Index, "")
		case "round.end":
			c.mu.Lock()
			j.rounds = e.Index
			ok, failed := j.OK, j.Failed
			c.mu.Unlock()
			c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_ROUND_FINISHED, e.Index, okFailed(ok, failed))
			if zip, err := patrol.RoundDone(j.writer, j.spec, e.Index); err != nil {
				c.audit("job.zip_failed", j.id, err.Error())
				c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_FAILED, e.Index, "zip de la ronda: "+err.Error())
			} else if zip != "" {
				c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_PACKAGED, e.Index, zip)
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
			c.audit("job.finish_failed", j.id, err.Error())
			c.mu.Lock()
			j.FinishErr = err.Error()
			c.mu.Unlock()
			c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_FAILED, 0, "cierre (manifest o zip): "+err.Error())
		} else if zip := patrol.FinalZip(w, spec); zip != "" {
			c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_PACKAGED, 0, zip)
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
	c.audit("job."+state, j.id, fmt.Sprintf("rondas=%d", rounds))
	c.addPhase(j, endPhase[state], 0, count(rounds, "ronda", "rondas"))
	// "closed" sale cuando el manifest y el zip ya existen: es lo que la UI espera para ofrecer el paquete.
	detail := ""
	if w != nil {
		detail = w.Dir()
	}
	c.bus.Publish(engine.Event{JobID: j.id, Kind: engine.JobState, State: "closed", Detail: detail})
}

var endPhase = map[string]v1.JobPhaseKind{"completed": v1.JobPhaseKind_JOB_PHASE_KIND_COMPLETED, "cancelled": v1.JobPhaseKind_JOB_PHASE_KIND_CANCELLED}

func okFailed(ok, failed int) string {
	return fmt.Sprintf("%s, %d con fallas", count(ok, "correcto", "correctos"), failed)
}

// count escribe "1 equipo" o "3 equipos": el detalle de las fases se muestra tal cual en la UI.
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func (s *patrolSvc) CancelJob(_ context.Context, r *v1.CancelJobRequest) (*v1.CancelJobResponse, error) {
	s.c.markActive()
	j, err := s.c.getJob(r.JobId)
	if err != nil {
		return nil, err
	}
	s.c.audit("job.cancel", j.id, "")
	s.c.mu.Lock()
	created := j.state == "created"
	if created {
		j.state = "cancelled" // nada que detener: solo deja de aparecer como vivo
	}
	s.c.mu.Unlock()
	if created {
		s.c.guard.Revoke(j.id)
		s.c.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_CANCELLED, 0, "antes de armar")
		return &v1.CancelJobResponse{}, nil
	}
	s.c.sched.Cancel(j.id)
	return &v1.CancelJobResponse{}, nil
}

func (s *patrolSvc) ListJobs(context.Context, *v1.ListJobsRequest) (*v1.ListJobsResponse, error) {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	r := &v1.ListJobsResponse{}
	for _, j := range s.c.jobs {
		r.Jobs = append(r.Jobs, s.c.summary(j))
	}
	return r, nil
}

// ListPlaybooks devuelve los playbooks ya cargados (embebidos y de config/playbooks), ordenados por id;
// el id es el mismo que CreateJob acepta en playbook_ids.
func (s *patrolSvc) ListPlaybooks(_ context.Context, r *v1.ListPlaybooksRequest) (*v1.ListPlaybooksResponse, error) {
	out := &v1.ListPlaybooksResponse{}
	for _, p := range s.c.pbs {
		if r.GetPlatform() != "" && p.Platform != r.GetPlatform() {
			continue
		}
		info := &v1.PlaybookInfo{Id: p.ID, Platform: p.Platform, Name: p.Name, Commands: slices.Clone(p.Pre)} // los pre corren primero
		for _, c := range p.Commands {
			info.Commands = append(info.Commands, c.Text)
		}
		out.Playbooks = append(out.Playbooks, info)
	}
	sort.Slice(out.Playbooks, func(i, j int) bool { return out.Playbooks[i].Id < out.Playbooks[j].Id })
	return out, nil
}

func (s *patrolSvc) GetRun(_ context.Context, r *v1.GetRunRequest) (*v1.GetRunResponse, error) {
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
		out.Devices = append(out.Devices, &v1.RunDevice{Target: &v1.Target{Address: d.Target.Address, Port: uint32(effectivePort(d.Target.Port)), DeviceId: d.Target.DeviceID},
			State: deviceStates[d.State], Detail: d.Detail})
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
			if err := st.Send(eventToProto(e)); err != nil {
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
