// Package assist es el servicio gRPC del modo de cambio asistido (ADR 0007). Planear solo lee;
// cambiar exige assisted=true en StartRun y la confirmación de cada paso. La ejecución usa la
// ventana de la bóveda y el guard, ambos cerrados al terminar.
package assist

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/assist"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
)

const (
	planTTL      = time.Hour
	runWindow    = 4 * time.Hour // ventana de la bóveda de una ejecución
	maxKeptPlans = 50
	runTTL       = time.Hour // una ejecución terminada sale del mapa pasado este tiempo
	maxKeptRuns  = 50        // o cuando hay más terminadas que esto
	closeWait    = 15 * time.Second
)

type planRec struct {
	plan    assist.Plan
	fn      assist.Function
	label   string
	t       target
	created time.Time
	rot     *rotation // solo la rotación de credenciales
}

type runRec struct {
	run      *assist.Run
	finished chan struct{} // se cierra cuando ya se soltaron guard y ventana
	started  time.Time
	ended    time.Time // cero mientras viva; protegido por assistSvc.mu
	keys     []string  // (equipo, interfaz) que la ejecución tiene tomados
}

type assistSvc struct {
	v1.UnimplementedAssistServiceServer
	d     service.Deps
	mu    sync.Mutex
	plans map[string]*planRec // shortcut: en memoria; un reinicio del núcleo descarta planes y ejecuciones
	runs  map[string]*runRec
	// ctx vive mientras el núcleo: cancelarlo (Close) hace que las ejecuciones se abandonen.
	ctx             context.Context
	cancel          context.CancelFunc
	decisionTimeout time.Duration // 0 = assist.DefaultDecisionTimeout
}

func newSvc(d service.Deps) *assistSvc {
	ctx, cancel := context.WithCancel(context.Background())
	return &assistSvc{d: d, plans: map[string]*planRec{}, runs: map[string]*runRec{}, ctx: ctx, cancel: cancel}
}

// Close cancela las ejecuciones vivas y espera a que cada una cierre su sesión, audite en qué quedó y
// suelte guard y ventana. El núcleo lo llama antes de cerrar la base de datos.
func (s *assistSvc) Close() {
	s.cancel()
	s.mu.Lock()
	recs := make([]*runRec, 0, len(s.runs))
	for _, rr := range s.runs {
		recs = append(recs, rr)
	}
	s.mu.Unlock()
	deadline := time.After(closeWait)
	for _, rr := range recs {
		select {
		case <-rr.finished:
		case <-deadline:
			return
		}
	}
}

// prunePlansLocked quita los planes caducados y, si aún hay demasiados, los más viejos. Requiere s.mu.
func (s *assistSvc) prunePlansLocked(now time.Time) {
	for id, p := range s.plans {
		if now.Sub(p.created) > planTTL {
			delete(s.plans, id)
		}
	}
	for len(s.plans) >= maxKeptPlans {
		oldest, at := "", time.Time{}
		for id, p := range s.plans {
			if oldest == "" || p.created.Before(at) {
				oldest, at = id, p.created
			}
		}
		delete(s.plans, oldest)
	}
}

// pruneRunsLocked quita las ejecuciones terminadas hace más de runTTL y, si quedan más de maxKeptRuns, las más viejas.
func (s *assistSvc) pruneRunsLocked(now time.Time) {
	var ended []string
	for id, rr := range s.runs {
		switch {
		case rr.ended.IsZero():
		case now.Sub(rr.ended) > runTTL:
			delete(s.runs, id)
		default:
			ended = append(ended, id)
		}
	}
	sort.Slice(ended, func(i, j int) bool { return s.runs[ended[i]].ended.Before(s.runs[ended[j]].ended) })
	for len(ended) > maxKeptRuns {
		delete(s.runs, ended[0])
		ended = ended[1:]
	}
}

// portKeys son los objetos (equipo, interfaz | VLAN | usuario) que un plan va a cambiar; sirven de candado entre ejecuciones.
func portKeys(rec *planRec) []string {
	var keys []string
	add := func(kind, obj string) {
		keys = append(keys, strings.ToLower(fmt.Sprintf("%s:%d|%s%s", rec.t.host, rec.t.port, kind, obj)))
	}
	if rec.plan.Function == assist.RestoreDiff { // restaurar toca el equipo entero: un solo candado que choca con cualquier otro del equipo
		return []string{strings.ToLower(fmt.Sprintf("%s:%d|*", rec.t.host, rec.t.port))}
	}
	for _, dp := range rec.plan.Devices {
		for _, l := range dp.Apply {
			f := strings.Fields(l)
			switch {
			case len(f) == 2 && f[0] == "interface":
				add("", iosxe.ShortIf(f[1]))
			case len(f) == 2 && f[0] == "vlan":
				add("vlan ", f[1])
			case len(f) > 2 && f[0] == "username":
				add("user ", f[1])
			case len(f) > 2 && f[0] == "errdisable": // configuración global: un solo candado por equipo
				add("global ", "errdisable recovery")
			case len(f) > 2 && f[0] == "ip" && f[1] == "route", len(f) > 1 && slices.Contains([]string{"ntp", "logging", "snmp-server", "banner"}, f[0]), len(f) > 2 && f[0] == "line" && f[1] == "vty":
				add("global ", ifElseStr(f[0] == "ip" || f[0] == "line", f[0]+" "+f[1], f[0])) // un candado por familia de configuración global del lote 28d
			}
		}
	}
	return keys
}

func ifElseStr(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}

// keysConflict: dos claves son la misma, o una es el candado del equipo entero (host:puerto|*) y la otra es del mismo equipo.
func keysConflict(a, b string) bool {
	if a == b {
		return true
	}
	host := func(k string) string { h, _, _ := strings.Cut(k, "|"); return h }
	return host(a) == host(b) && (strings.HasSuffix(a, "|*") || strings.HasSuffix(b, "|*"))
}

// busyLocked devuelve la ejecución viva que ya tiene tomado alguno de los puertos. Requiere s.mu.
func (s *assistSvc) busyLocked(keys []string) (string, bool) {
	for id, rr := range s.runs {
		if !rr.ended.IsZero() {
			continue
		}
		select {
		case <-rr.run.Done():
			continue
		default:
		}
		for _, k := range rr.keys {
			if slices.ContainsFunc(keys, func(x string) bool { return keysConflict(x, k) }) {
				return id, true
			}
		}
	}
	return "", false
}

// connErr traduce los errores de conexión a códigos gRPC. La huella de una llave nueva va en el mensaje.
func connErr(err error) error {
	var he *transport.HostKeyError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &he):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, transport.ErrAuth), errors.Is(err, transport.ErrEgressDenied):
		return status.Error(codes.PermissionDenied, err.Error())
	}
	if s := service.VaultErr(err); status.Code(s) != codes.Internal {
		return s
	}
	return status.Error(codes.Unavailable, err.Error())
}

func (s *assistSvc) vault(ctx context.Context) error {
	if v := s.d.Vault(); v == nil || !v.Unlocked() {
		return service.Err(ctx, codes.FailedPrecondition, "assist.svc.abre_la_boveda_el_modo", nil)
	}
	return nil
}

func checkTarget(ctx context.Context, t *v1.AssistTarget) error {
	if t == nil || t.Address == "" || t.CredentialId == "" {
		return service.Err(ctx, codes.InvalidArgument, "assist.svc.indica_el_equipo_direccion_y", nil)
	}
	if t.Port > 65535 {
		return service.Err(ctx, codes.InvalidArgument, "assist.svc.puerto_fuera_de_rango", nil)
	}
	return nil
}

// templateKey lleva en el contexto el id de la plantilla del catálogo (vlan, trunk, svi o el de la plantilla) para
// la metadata `template` de assist.refused, igual que en assist.invalid_value.
type templateKey struct{}

// planErr traduce el rechazo de una función a un código: las negativas por el estado del equipo son FailedPrecondition.
func planErr(ctx context.Context, err error, device string) error {
	template, _ := ctx.Value(templateKey{}).(string)
	var sr *assist.SnippetRefusal
	if errors.As(err, &sr) {
		sr.Template, sr.Device = template, device
		return service.ErrFrom(ctx, codes.FailedPrecondition, err)
	}
	var ve *assist.ValueErrors
	if errors.As(err, &ve) {
		return service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	if errors.Is(err, assist.ErrPortRefused) || errors.Is(err, assist.ErrRotateRefused) ||
		errors.Is(err, assist.ErrRestoreRefused) || errors.Is(err, assist.ErrNoDifference) {
		return service.ErrFrom(ctx, codes.FailedPrecondition, err)
	}
	return service.ErrFrom(ctx, codes.InvalidArgument, err)
}

// planOn es lo común de planear: abre una sesión de solo lectura (ventana de guard plan-ID con defer Revoke), corre pre, deja que build arme el
// plan del equipo y lo guarda con un id. Nada se manda al equipo salvo comandos de lectura.
func (s *assistSvc) planOn(ctx context.Context, t *v1.AssistTarget, accepted []string, pre []string, fn assist.Function, writeMem bool, detail string,
	rot *rotation, build func(label string, byCmd map[string]string) (assist.DevicePlan, error)) (string, assist.Plan, error) {
	return s.planWith(ctx, t, accepted, pre, nil, &fn, nil, writeMem, detail, rot, build)
}

// planWith es planOn con una función que build puede reemplazar (restaurar arma la suya con la interfaz de gestión y el tope del plan) y con
// lecturas extra que dependen de las primeras (more recibe lo leído en pre; restaurar pregunta por la salida hacia el origen de la sesión).
func (s *assistSvc) planWith(ctx context.Context, t *v1.AssistTarget, accepted []string, pre []string, more func(map[string]string) []string, fnp *assist.Function, platforms []string, writeMem bool, detail string,
	rot *rotation, build func(label string, byCmd map[string]string) (assist.DevicePlan, error)) (string, assist.Plan, error) {
	if err := s.vault(ctx); err != nil {
		return "", assist.Plan{}, err
	}
	port := uint16(t.Port)
	if port == 0 {
		port = 22
	}
	label := t.Name
	if label == "" {
		label = t.Address + ":" + strconv.Itoa(int(port))
	}
	tg := target{host: t.Address, port: port, cred: t.CredentialId}
	planID := service.NewID()
	gid := "plan-" + planID
	if err := s.d.Guard().Allow(ctx, gid, []string{t.Address}); err != nil {
		return "", assist.Plan{}, status.Error(codes.PermissionDenied, err.Error())
	}
	defer s.d.Guard().Revoke(gid)
	acc := map[string]bool{}
	for _, fp := range accepted {
		acc[fp] = true
	}
	ex := newExec(s.d, gid, map[string]target{label: tg}, transport.HostKeyPolicy{Accepted: acc})
	defer ex.Close()
	outs, err := ex.Read(ctx, label, pre)
	if err != nil {
		return "", assist.Plan{}, connErr(err)
	}
	byCmd := map[string]string{}
	for _, o := range outs {
		byCmd[o.Command] = o.Text
	}
	if a := ex.SourceAddr(label); a != "" { // lo usa vty-acl para no dejar fuera a esta sesión
		byCmd[assist.SessionSourceKey] = a
	}
	if more != nil {
		if extra := more(byCmd); len(extra) > 0 {
			outs, err = ex.Read(ctx, label, extra)
			if err != nil {
				return "", assist.Plan{}, connErr(err)
			}
			for _, o := range outs {
				byCmd[o.Command] = o.Text
			}
		}
	}
	if p := ex.Platform(label); len(platforms) > 0 && !slices.Contains(platforms, p) {
		return "", assist.Plan{}, service.Err(ctx, codes.FailedPrecondition, "assist.svc.la_plantilla_es_de_y", i18n.A("platforms", strings.Join(platforms, ", "), "platform", p))
	}
	dp, err := build(label, byCmd)
	if err != nil {
		return "", assist.Plan{}, planErr(ctx, err, label)
	}
	fn := *fnp // build puede haber puesto la función propia del plan
	plan := assist.Plan{Function: fn.Name, WriteMemory: writeMem, Devices: []assist.DevicePlan{dp}}
	if err := assist.Validate(plan, fn); err != nil {
		return "", assist.Plan{}, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	s.mu.Lock()
	now := s.d.Now()
	s.prunePlansLocked(now)
	s.plans[planID] = &planRec{plan: plan, fn: fn, label: label, t: tg, created: now, rot: rot}
	s.mu.Unlock()
	s.d.Audit("assist.plan", planID, fmt.Sprintf("function=%s device=%s %s lines=%d rollback=%d", fn.Name, label, detail, len(dp.Apply), len(dp.Rollback)))
	return planID, plan, nil
}

func (s *assistSvc) PlanPorts(ctx context.Context, r *v1.PlanPortsRequest) (*v1.PlanPortsResponse, error) {
	s.d.MarkActive()
	if err := checkTarget(ctx, r.Target); err != nil {
		return nil, err
	}
	ch := assist.PortChange{Vlan: int(r.Vlan), Voice: int(r.Voice), Description: r.Description, Shutdown: r.Shutdown}
	pre, err := assist.PortsPre(r.Interfaces, ch)
	if err != nil {
		return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	id, plan, err := s.planOn(ctx, r.Target, r.AcceptedHostKeyFingerprints, pre, assist.Ports, r.WriteMemory, fmt.Sprintf("interfaces=%v", r.Interfaces), nil,
		func(label string, outs map[string]string) (assist.DevicePlan, error) {
			return assist.PortsPlan(label, r.Interfaces, ch, outs)
		})
	if err != nil {
		return nil, err
	}
	return &v1.PlanPortsResponse{PlanId: id, Plan: planToProto(i18n.Locale(ctx), assist.Redact(plan, assist.Ports))}, nil
}

func (s *assistSvc) PlanSnippet(ctx context.Context, r *v1.PlanSnippetRequest) (*v1.PlanSnippetResponse, error) {
	s.d.MarkActive()
	if err := checkTarget(ctx, r.Target); err != nil {
		return nil, err
	}
	var (
		fn        assist.Function
		platforms []string // las que soporta la plantilla; vacío = no se compara
		pre       []string
		err       error
		build     func(label string, outs map[string]string) (assist.DevicePlan, error)
		detail    string
	)
	switch sn := r.Snippet.(type) {
	case *v1.PlanSnippetRequest_Vlan:
		ctx = context.WithValue(ctx, templateKey{}, "vlan")
		ch := assist.VlanChange{ID: int(sn.Vlan.Id), Name: sn.Vlan.Name, AcceptVTP: sn.Vlan.AcceptVtp, Remove: sn.Vlan.Remove, AcceptTrunk: sn.Vlan.AcceptTrunk}
		fn, detail = assist.SnippetVlan, fmt.Sprintf("vlan=%d", sn.Vlan.Id)
		pre, err = assist.VlanPre(ch)
		build = func(l string, o map[string]string) (assist.DevicePlan, error) { return assist.VlanPlan(l, ch, o) }
	case *v1.PlanSnippetRequest_Trunk:
		ctx = context.WithValue(ctx, templateKey{}, "trunk")
		ch := assist.TrunkChange{Interface: sn.Trunk.Interface, Op: sn.Trunk.Op, Vlan: int(sn.Trunk.Vlan)}
		fn, detail = assist.SnippetTrunk, fmt.Sprintf("interface=%s %s vlan=%d", ch.Interface, ch.Op, ch.Vlan)
		pre, err = assist.TrunkPre(ch)
		build = func(l string, o map[string]string) (assist.DevicePlan, error) { return assist.TrunkPlan(l, ch, o) }
	case *v1.PlanSnippetRequest_Svi:
		ctx = context.WithValue(ctx, templateKey{}, "svi")
		ch := assist.SVIChange{VlanID: int(sn.Svi.Vlan), Description: sn.Svi.Description, Address: sn.Svi.Address, Mask: sn.Svi.Mask}
		fn, detail = assist.SnippetSVI, fmt.Sprintf("svi=Vlan%d", sn.Svi.Vlan)
		pre, err = assist.SVIPre(ch)
		build = func(l string, o map[string]string) (assist.DevicePlan, error) { return assist.SVIPlan(l, ch, o) }
	case *v1.PlanSnippetRequest_Template:
		ctx = context.WithValue(ctx, templateKey{}, sn.Template.GetId())
		t, vals, e := templateOf(ctx, sn.Template)
		if e != nil {
			return nil, e
		}
		fn, detail, platforms = t.Fn, assist.DescribeValues(t, vals), t.Platforms
		pre, err = t.Pre(vals)
		build = func(l string, o map[string]string) (assist.DevicePlan, error) { return t.Plan(l, vals, o) }
	default:
		return nil, service.Err(ctx, codes.InvalidArgument, "assist.svc.indica_el_snippet_vlan_trunk", nil)
	}
	if err != nil {
		return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	id, plan, err := s.planWith(ctx, r.Target, r.AcceptedHostKeyFingerprints, pre, nil, &fn, platforms, r.WriteMemory, detail, nil, build)
	if err != nil {
		return nil, err
	}
	return &v1.PlanSnippetResponse{PlanId: id, Plan: planToProto(i18n.Locale(ctx), assist.Redact(plan, fn))}, nil
}

// templateOf busca la plantilla pedida y valida sus valores (la validación autoritativa: la de la UI es solo ayuda).
func templateOf(ctx context.Context, ts *v1.TemplateSnippet) (assist.Template, assist.Values, error) {
	t, ok := assist.TemplateByID(ts.GetId())
	if !ok {
		return assist.Template{}, nil, service.Err(ctx, codes.InvalidArgument, "assist.svc.no_hay_una_plantilla_en", i18n.A("id", ts.GetId()))
	}
	vals := assist.Values(ts.GetValues())
	if err := assist.ValidateValues(t, vals); err != nil {
		return assist.Template{}, nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	return t, vals, nil
}

// ListSnippetTemplates da el catálogo de plantillas con sus campos tipados, en orden de catálogo; platform vacío = todas.
func (s *assistSvc) ListSnippetTemplates(_ context.Context, r *v1.ListSnippetTemplatesRequest) (*v1.ListSnippetTemplatesResponse, error) {
	s.d.MarkActive()
	out := &v1.ListSnippetTemplatesResponse{}
	for _, t := range assist.Templates() {
		if r.Platform != "" && !slices.Contains(t.Platforms, r.Platform) {
			continue
		}
		st := &v1.SnippetTemplate{Id: t.ID, Tech: t.Tech, Name: t.Name, Platforms: t.Platforms}
		for _, f := range t.Fields {
			st.Fields = append(st.Fields, &v1.SnippetField{Name: f.Name, Label: f.Label, Type: string(f.Type), Required: f.Required, Min: f.Min, Max: f.Max,
				Pattern: f.Pattern, Choices: f.Choices, DefaultValue: f.Default, Help: f.Help})
		}
		out.Templates = append(out.Templates, st)
	}
	return out, nil
}

// PlanCredRotate arma la rotación de la contraseña de un usuario local. Se rechaza al usuario de la credencial con la que se conecta: si la
// nueva no entrara no habría otra sesión por dónde revertir. El secreto (dado o generado) vive solo en el plan y en el ejecutor.
func (s *assistSvc) PlanCredRotate(ctx context.Context, r *v1.PlanCredRotateRequest) (*v1.PlanCredRotateResponse, error) {
	s.d.MarkActive()
	if err := checkTarget(ctx, r.Target); err != nil {
		return nil, err
	}
	pre, err := assist.CredRotatePre(r.User)
	if err != nil {
		return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	secret := r.NewSecret
	switch {
	case secret == "" && r.UpdateCredentialId == "":
		return nil, service.Err(ctx, codes.InvalidArgument, "assist.svc.un_secreto_generado_por_el", nil)
	case secret == "":
		if secret, err = assist.GenerateSecret(); err != nil {
			return nil, service.Err(ctx, codes.Internal, "assist.svc.no_se_pudo_generar_el", nil)
		}
	default:
		if err := assist.ValidateSecret(secret); err != nil {
			return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
		}
	}
	if err := s.vault(ctx); err != nil {
		return nil, err
	}
	connected, err := s.credUser(r.Target.CredentialId)
	if err != nil {
		return nil, err
	}
	if r.UpdateCredentialId != "" {
		u, err := s.credUser(r.UpdateCredentialId)
		if err != nil {
			return nil, err
		}
		if u != r.User {
			return nil, service.Err(ctx, codes.InvalidArgument, "assist.svc.la_credencial_es_del_usuario", i18n.A("credential", r.UpdateCredentialId, "actual", u, "wanted", r.User))
		}
	}
	rot := &rotation{user: r.User, secret: secret, updateCred: r.UpdateCredentialId}
	id, plan, err := s.planOn(ctx, r.Target, r.AcceptedHostKeyFingerprints, pre, assist.CredRotate, true /* write memory es obligatorio */, "user="+r.User, rot,
		func(label string, outs map[string]string) (assist.DevicePlan, error) {
			return assist.CredRotatePlan(label, assist.CredRotateChange{User: r.User, NewSecret: secret, ConnectedUser: connected}, outs)
		})
	if err != nil {
		return nil, err
	}
	return &v1.PlanCredRotateResponse{PlanId: id, Plan: planToProto(i18n.Locale(ctx), assist.Redact(plan, assist.CredRotate))}, nil
}

// credUser devuelve el usuario de una credencial de la bóveda, sin conservar sus secretos.
func (s *assistSvc) credUser(id string) (string, error) {
	c, err := s.d.Vault().Get(id)
	if err != nil {
		return "", service.VaultErr(err)
	}
	defer c.Password.Destroy()
	defer c.Enable.Destroy()
	defer c.SSHKey.Destroy()
	return c.Username, nil
}

func (s *assistSvc) StartRun(ctx context.Context, r *v1.StartRunRequest) (*v1.StartRunResponse, error) {
	s.d.MarkActive()
	// Regla 1: apagado por defecto. Nada se conecta ni se prepara sin esta bandera en esta petición.
	if !r.Assisted {
		return nil, service.Err(ctx, codes.FailedPrecondition, "assist.svc.el_modo_asistido_esta_apagado", nil)
	}
	if s.ctx.Err() != nil {
		return nil, service.Err(ctx, codes.Unavailable, "assist.svc.el_nucleo_se_esta_cerrando", nil)
	}
	s.mu.Lock()
	rec, ok := s.plans[r.PlanId]
	if ok && s.d.Now().Sub(rec.created) > planTTL {
		delete(s.plans, r.PlanId)
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		return nil, service.Err(ctx, codes.NotFound, "assist.svc.el_plan_no_existe_caduco", nil)
	}
	if err := s.vault(ctx); err != nil {
		return nil, err
	}
	runID := service.NewID()
	if err := s.d.Guard().Allow(ctx, runID, []string{rec.t.host}); err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	v := s.d.Vault()
	creds := []string{rec.t.cred}
	if rec.rot != nil && rec.rot.updateCred != "" {
		creds = append(creds, rec.rot.updateCred)
	}
	if err := v.Arm(runID, s.d.Now().Add(runWindow), creds); err != nil {
		s.d.Guard().Revoke(runID)
		return nil, service.VaultErr(err)
	}
	release := func() { s.d.Guard().Revoke(runID); v.Disarm(runID) }
	var ex assist.Executor = newExec(s.d, runID, map[string]target{rec.label: rec.t}, transport.HostKeyPolicy{})
	if rec.rot != nil {
		ex = &rotExec{devExec: ex.(*devExec), rot: *rec.rot}
	}
	run, err := assist.NewRun(assist.Options{ID: runID, Plan: rec.plan, Fn: rec.fn, Assisted: r.Assisted, Exec: ex, Audit: s.d.Audit,
		DecisionTimeout: s.decisionTimeout})
	if err != nil {
		release()
		return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	s.mu.Lock()
	if _, ok := s.plans[r.PlanId]; !ok { // otro StartRun ganó la carrera
		s.mu.Unlock()
		release()
		return nil, service.Err(ctx, codes.NotFound, "assist.svc.el_plan_ya_se_uso", nil)
	}
	keys := portKeys(rec)
	if other, busy := s.busyLocked(keys); busy { // un puerto, una ejecución a la vez
		s.mu.Unlock()
		release()
		return nil, service.Err(ctx, codes.FailedPrecondition, "assist.svc.la_ejecucion_sigue_activa_sobre", i18n.A("other", other))
	}
	delete(s.plans, r.PlanId)
	now := s.d.Now()
	s.pruneRunsLocked(now)
	rr := &runRec{run: run, finished: make(chan struct{}), started: now, keys: keys}
	s.runs[runID] = rr
	s.mu.Unlock()
	run.Start(s.ctx)
	go func() {
		<-run.Done()
		release()
		s.mu.Lock()
		rr.ended = s.d.Now()
		s.mu.Unlock()
		close(rr.finished)
	}()
	return &v1.StartRunResponse{RunId: runID}, nil
}

func (s *assistSvc) get(ctx context.Context, id string) (*runRec, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rr, ok := s.runs[id]
	if !ok {
		return nil, service.Err(ctx, codes.NotFound, "assist.svc.la_ejecucion_no_existe", i18n.A("id", id))
	}
	return rr, nil
}

func stepErr(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	return service.ErrFrom(ctx, codes.FailedPrecondition, err)
}

func (s *assistSvc) Confirm(ctx context.Context, r *v1.ConfirmRequest) (*v1.ConfirmResponse, error) {
	s.d.MarkActive()
	rr, err := s.get(ctx, r.RunId)
	if err != nil {
		return nil, err
	}
	if err := rr.run.Confirm(r.StepId); err != nil {
		return nil, stepErr(ctx, err)
	}
	return &v1.ConfirmResponse{Run: snapshot(i18n.Locale(ctx), rr)}, nil
}

func (s *assistSvc) Abort(ctx context.Context, r *v1.AbortRequest) (*v1.AbortResponse, error) {
	s.d.MarkActive()
	rr, err := s.get(ctx, r.RunId)
	if err != nil {
		return nil, err
	}
	if err := rr.run.Abort(); err != nil {
		return nil, stepErr(ctx, err)
	}
	return &v1.AbortResponse{Run: snapshot(i18n.Locale(ctx), rr)}, nil
}

func (s *assistSvc) Rollback(ctx context.Context, r *v1.RollbackRequest) (*v1.RollbackResponse, error) {
	s.d.MarkActive()
	rr, err := s.get(ctx, r.RunId)
	if err != nil {
		return nil, err
	}
	if err := rr.run.Rollback(); err != nil {
		return nil, stepErr(ctx, err)
	}
	return &v1.RollbackResponse{Run: snapshot(i18n.Locale(ctx), rr)}, nil
}

func (s *assistSvc) WatchRun(r *v1.WatchRunRequest, st v1.AssistService_WatchRunServer) error {
	ctx := st.Context()
	rr, err := s.get(ctx, r.RunId)
	if err != nil {
		return err
	}
	from := int(r.FromSeq)
	loc := i18n.Locale(ctx)
	send := func(evs []assist.Event) error {
		for _, e := range evs {
			if err := st.Send(&v1.WatchRunResponse{Event: eventToProto(loc, e)}); err != nil {
				return err
			}
		}
		from += len(evs)
		return nil
	}
	for {
		evs, more := rr.run.Events(from)
		if err := send(evs); err != nil {
			return err
		}
		select {
		case <-rr.run.Done():
			evs, _ := rr.run.Events(from)
			return send(evs)
		case <-more:
		case <-st.Context().Done():
			return st.Context().Err()
		}
	}
}

// ListRuns da las ejecuciones que el núcleo recuerda, las más recientes primero.
func (s *assistSvc) ListRuns(ctx context.Context, r *v1.ListRunsRequest) (*v1.ListRunsResponse, error) {
	s.mu.Lock()
	recs := make([]*runRec, 0, len(s.runs))
	for _, rr := range s.runs {
		recs = append(recs, rr)
	}
	s.mu.Unlock()
	sort.Slice(recs, func(i, j int) bool { return recs[i].started.After(recs[j].started) })
	out := &v1.ListRunsResponse{}
	for _, rr := range recs {
		if st := snapshot(i18n.Locale(ctx), rr); !r.ActiveOnly || st.Active {
			out.Runs = append(out.Runs, st)
		}
	}
	return out, nil
}

func (s *assistSvc) GetAssistRun(ctx context.Context, r *v1.GetAssistRunRequest) (*v1.GetAssistRunResponse, error) {
	rr, err := s.get(ctx, r.RunId)
	if err != nil {
		return nil, err
	}
	return &v1.GetAssistRunResponse{Run: snapshot(i18n.Locale(ctx), rr)}, nil
}

// Module registra el servicio Assist.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	svc := newSvc(d)
	d.OnClose(svc.Close)
	v1.RegisterAssistServiceServer(s, svc)
}
