// Package backup es el servicio gRPC de respaldos de configuración. La recolección es un trabajo
// de Patrol (bóveda, Login Test, guard, planificador y auditoría); este servicio solo copia las
// salidas de show running-config y startup-config a outputs/respaldos/<equipo>/. Nunca cambia un equipo.
package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/analyze"
	"github.com/oom-netsec/MACUAHUITL/internal/backup"
	"github.com/oom-netsec/MACUAHUITL/internal/capture"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

const (
	// trabajos guarda las carpetas de Patrol mientras se recolectan; se borran al terminar.
	trabajos = ".trabajos"
	maxKeep  = 1000
)

// tracked es lo que el servicio sabe de un trabajo que él mismo creó.
type tracked struct {
	masked bool
	keep   int
	lote   string
	root   string // carpeta de salidas con que arrancó el trabajo: aunque cambie, todo se guarda y se borra ahí; vacía = la vigente
	// Ventana en que pueden haberse tomado las salidas del trabajo (cero = sin comprobar).
	from, until time.Time
	done        map[string]int64 // archivos de ronda ya importados completos (equipo/archivo → tamaño)
	warned      map[string]bool  // avisos ya auditados
	saved       []string         // respaldos que guardó el trabajo en todas las llamadas: el informe final los cuenta todos
	incomplete  bool             // alguna salida llegó incompleta: no se relee, pero la carpeta de Patrol se conserva
}

// fstat es lo que se vio de un .txt de Patrol en una vuelta: si no cambió en la siguiente, no lo están escribiendo.
type fstat struct {
	size int64
	mod  time.Time
}

type backupSvc struct {
	v1.UnimplementedBackupServiceServer
	d      service.Deps
	poll   time.Duration
	quiet  time.Duration // un .txt tocado hace menos que esto puede estar a mitad de una escritura de Patrol: no se lee hasta que pase
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex // serializa collect: el vigilante y Collect no importan a la vez
	jobs   map[string]*tracked
	final  map[string]collected // resultado final de los últimos trabajos propios: quien llega segundo lo recibe igual
	order  []string
	seen   map[string]map[string]fstat // trabajo -> archivo -> lo visto en la vuelta anterior
}

const maxFinal = 32

func newSvc(d service.Deps) *backupSvc {
	ctx, cancel := context.WithCancel(context.Background())
	return &backupSvc{d: d, poll: 2 * time.Second, quiet: time.Second, ctx: ctx, cancel: cancel, jobs: map[string]*tracked{}}
}

func (s *backupSvc) store() backup.Store { return s.storeOf(nil) }

// outputs es la carpeta de salidas de un trabajo propio (la que tenía al arrancar) o, sin él, la vigente.
func (s *backupSvc) outputs(tr *tracked) string {
	if tr != nil && tr.root != "" {
		return tr.root
	}
	return s.d.Outputs()
}

func (s *backupSvc) storeOf(tr *tracked) backup.Store {
	return backup.Store{Root: filepath.Join(s.outputs(tr), "respaldos")}
}

func (s *backupSvc) close() {
	s.cancel()
	s.wg.Wait()
}

func keepOf(ctx context.Context, k uint32) (int, error) {
	if k == 0 {
		return backup.DefaultKeep, nil
	}
	if k > maxKeep {
		return 0, service.Err(ctx, codes.InvalidArgument, "backup.err.keep", i18n.A("max", maxKeep))
	}
	return int(k), nil
}

func (s *backupSvc) StartBackup(ctx context.Context, r *v1.StartBackupRequest) (*v1.StartBackupResponse, error) {
	s.d.MarkActive()
	if len(r.Targets) == 0 {
		return nil, service.Err(ctx, codes.InvalidArgument, "backup.err.no_targets", nil)
	}
	keep, err := keepOf(ctx, r.Keep)
	if err != nil {
		return nil, err
	}
	// Los comandos son fijos: lo que se respalda es la configuración, nunca algo que el ingeniero escriba.
	cmds := "show version\nshow running-config" // show version da la serie: la ficha del respaldo la guarda para restaurar solo en el mismo equipo
	if r.Startup {
		cmds += "\nshow startup-config"
	}
	spec := &v1.JobSpec{Kind: "backup", Name: "respaldo", Targets: r.Targets, DefaultCredentialId: r.CredentialId, CustomCommands: cmds,
		WindowHours: 1, Split: v1.SplitStrategy_SPLIT_STRATEGY_PER_ROUND, Zip: v1.ZipPolicy_ZIP_POLICY_NONE, DisableMasking: r.IncludeSecrets}
	if r.IntervalSeconds > 0 {
		if r.Rounds < 2 {
			return nil, service.Err(ctx, codes.InvalidArgument, "backup.err.rounds", nil)
		}
		spec.Schedule = &v1.Schedule{IntervalSeconds: r.IntervalSeconds, Rounds: r.Rounds}
		spec.WindowHours = uint32(min(96, (uint64(r.IntervalSeconds)*uint64(r.Rounds))/3600+2))
	}
	out := s.d.Outputs() // se lee una sola vez: el trabajo entero queda en esta carpeta aunque luego cambie
	root := filepath.Join(out, "respaldos", trabajos)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, service.Err(ctx, codes.Internal, "backup.err.out_dir", i18n.A("error", err.Error()))
	}
	lote, err := os.MkdirTemp(root, "lote-")
	if err != nil {
		return nil, service.Err(ctx, codes.Internal, "backup.err.out_dir", i18n.A("error", err.Error()))
	}
	spec.OutputDir = lote
	p := s.d.Patrol()
	cj, err := p.CreateJob(ctx, &v1.CreateJobRequest{Spec: spec})
	if err != nil {
		os.Remove(lote)
		return nil, err
	}
	now := s.d.Now()
	win := time.Duration(spec.WindowHours)*time.Hour + 5*time.Minute // margen por si el reloj se mueve
	s.mu.Lock()
	s.jobs[cj.JobId] = &tracked{masked: !r.IncludeSecrets, keep: keep, lote: lote, root: out, from: now.Add(-time.Minute), until: now.Add(win)}
	s.mu.Unlock()
	s.d.Audit("backup.start", cj.JobId, fmt.Sprintf("devices=%d startup=%v keep=%d interval=%ds rounds=%d masked=%v", len(r.Targets), r.Startup, keep, r.IntervalSeconds, r.Rounds, !r.IncludeSecrets))
	ar, err := p.ArmJob(ctx, &v1.ArmJobRequest{JobId: cj.JobId, AcceptedHostKeyFingerprints: r.AcceptedHostKeyFingerprints, ExcludedDeviceIds: r.ExcludedDeviceIds})
	if err != nil {
		os.Remove(lote) // vacía; Patrol la recrea si luego se arma
		// Queda creado: se revisa con LoginTest y se arma con ArmJob; CollectBackups lo guarda al terminar.
		return &v1.StartBackupResponse{JobId: cj.JobId, Detail: status.Convert(err).Message()}, nil
	}
	s.watch(cj.JobId)
	return &v1.StartBackupResponse{JobId: cj.JobId, Armed: true, WindowEndsAt: ar.WindowEndsAt}, nil
}

// watch guarda cada ronda según termina, hasta que el trabajo acaba o el núcleo se cierra.
func (s *backupSvc) watch(job string) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(s.poll)
		defer t.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-t.C:
			}
			r, err := s.collect(i18n.WithLocale(s.ctx, i18n.En), job, 0) // la auditoría va en inglés (Deps.Job ya devuelve el error localizado)
			if err != nil {
				s.d.Audit("backup.failed", job, i18n.English(err))
				return
			}
			if r.done {
				return
			}
		}
	}()
}

type collected struct {
	state    string
	done     bool
	errMsg   string
	Saved    []string `json:"saved"`
	Skipped  int      `json:"skipped"`
	Pruned   int      `json:"pruned"`
	Warnings []string `json:"warnings"`
	// WarningTexts son Warnings como texto de catálogo (mismo orden); no viajan en el JSON.
	WarningTexts []i18n.Text `json:"-"`
}

// warn agrega un aviso: en español para el JSON de siempre y como texto para darlo en otro idioma.
func (c *collected) warn(t i18n.Text) {
	c.Warnings, c.WarningTexts = append(c.Warnings, t.In(i18n.Es)), append(c.WarningTexts, t)
}

// text es el informe en el idioma dado (es es el de siempre).
func (c collected) text(loc string) string {
	var b strings.Builder
	b.WriteString(i18n.Msg(loc, "backup.rep.saved", i18n.A("saved", len(c.Saved), "skipped", c.Skipped)))
	if c.Pruned > 0 {
		b.WriteString(i18n.Msg(loc, "backup.rep.pruned", i18n.A("n", c.Pruned)))
	}
	b.WriteString("\n")
	for _, id := range c.Saved {
		fmt.Fprintf(&b, "  %s\n", id)
	}
	for _, w := range i18n.Notes(loc, c.Warnings, c.WarningTexts) { // listas paralelas: si se desparejan, sale es, nunca mezclado
		b.WriteString(i18n.Msg(loc, "backup.rep.warning", i18n.A("w", w)) + "\n")
	}
	return b.String()
}

// skip: la ronda ya se importó completa y no ha crecido.
func (t *tracked) skip(rel string, size int64) bool {
	n, ok := t.done[rel]
	return ok && n == size
}

// inWindow: la hora de una sección cae en la ventana del trabajo. Sin ventana conocida, todo vale.
func (t *tracked) inWindow(at time.Time) bool {
	return t == nil || t.from.IsZero() || !at.Before(t.from) && !at.After(t.until)
}

// masked: lo que se anotó al crear el trabajo; si no es nuestro, el manifest de Patrol; si falta, enmascarado (aviso conservador).
func masked(t *tracked, dir string) bool {
	if t != nil {
		return t.masked
	}
	f, err := sys.OpenRegular(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return true
	}
	defer f.Close()
	var m struct {
		Masked bool `json:"masked"`
	}
	if json.NewDecoder(io.LimitReader(f, 8<<20)).Decode(&m) != nil {
		return true
	}
	return m.Masked
}

// collect serializa collectLocked; el primero en ver el estado terminal de un trabajo propio deja su
// resultado en final, para que el otro (vigilante o CollectBackups) no responda con la carpeta ya borrada.
func (s *backupSvc) collect(ctx context.Context, job string, keep int) (collected, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.final[job]; ok {
		return f, nil
	}
	own := s.jobs[job] != nil
	res, err := s.collectLocked(ctx, job, keep)
	if err == nil && res.done && own {
		if s.final == nil {
			s.final = map[string]collected{}
		}
		s.final[job] = res
		if s.order = append(s.order, job); len(s.order) > maxFinal {
			delete(s.final, s.order[0])
			s.order = s.order[1:]
		}
	}
	return res, err
}

func (s *backupSvc) collectLocked(ctx context.Context, job string, keep int) (collected, error) {
	j, err := s.d.Job(ctx, job)
	if err != nil {
		return collected{}, err
	}
	res := collected{state: j.State, Saved: []string{}, Warnings: []string{}}
	terminal := j.State == "completed" || j.State == "cancelled"
	tr := s.jobs[job]
	if keep == 0 {
		keep = backup.DefaultKeep
		if tr != nil {
			keep = tr.keep
		}
	}
	res.done = terminal
	if j.Dir == "" {
		return res, nil
	}
	observed := map[string]fstat{}
	skip := func(rel string, size int64) bool {
		if tr != nil && tr.skip(rel, size) {
			return true
		}
		// Con el trabajo en marcha, Patrol puede estar escribiendo ese archivo: leerlo ahora guardaría un respaldo cortado.
		// Se lee solo si lleva quieto más de s.quiet y tamaño y fecha son los mismos que en la vuelta anterior (el mtime
		// solo no basta: FAT/exFAT lo redondea a 2 s). Límite: un archivo en el que Patrol escribe cada vuelta no se
		// importa hasta que el trabajo termina.
		if !terminal && s.quiet > 0 {
			fi, err := os.Stat(filepath.Join(j.Dir, filepath.FromSlash(rel)))
			if err != nil {
				return false
			}
			cur := fstat{fi.Size(), fi.ModTime()}
			observed[rel] = cur
			return time.Since(fi.ModTime()) < s.quiet || s.seen[job][rel] != cur
		}
		return false
	}
	b, err := analyze.LoadSkipping(j.Dir, skip)
	if s.seen == nil {
		s.seen = map[string]map[string]fstat{}
	}
	s.seen[job] = observed
	if err != nil {
		// Sin salidas aún no es un error mientras el trabajo corre.
		if terminal {
			res.errMsg = firstNonEmpty(j.FinishErr, err.Error())
			s.forget(job, tr, false)
		}
		return res, nil
	}
	// Un aviso del lector (tope de tamaño, recorte, archivo ilegible) significa que algo no se leyó entero.
	failed := len(b.Warnings) > 0
	for _, w := range b.Warnings {
		msg := w.MsgTx
		if msg.Empty() {
			msg = i18n.Lit(w.Msg, w.Msg)
		}
		res.warn(i18n.Join(": ", i18n.Lit(w.Device, w.Device), i18n.Lit(w.Command, w.Command), msg))
	}
	type slot struct {
		dev   string
		round int
		kind  backup.Kind
	}
	count, valid := map[slot]int{}, []analyze.Section{}
	for _, sec := range b.Sections {
		kind, ok := kindOf(sec.Command)
		switch {
		case !ok:
		case sec.Invalid:
			if kind == backup.Startup {
				res.warn(i18n.Tx("backup.warn.no_startup", "device", sec.Device))
			}
		case sec.Incomplete:
			res.warn(i18n.Tx("backup.warn.incomplete", "device", sec.Device, "cmd", sec.Command))
			if tr != nil {
				tr.incomplete = true
			}
		case !tr.inWindow(sec.At):
			// Solo puede venir de texto del equipo que imita una cabecera: no es un respaldo.
			res.warn(i18n.Tx("backup.warn.outside", "device", sec.Device, "cmd", sec.Command, "at", sec.At.Format(time.RFC3339)))
			failed = true
		default:
			count[slot{sec.Device, sec.Round, kind}]++
			valid = append(valid, sec)
		}
	}
	st, mk := s.storeOf(tr), masked(tr, j.Dir)
	// La ficha se firma con la llave de la bóveda (se crea la primera vez); con la bóveda cerrada el respaldo se guarda, pero sin firma no se podrá restaurar.
	if key, err := service.BackupKey(s.d.Vault(), true); err == nil {
		st.Key = key
	} else if len(valid) > 0 {
		res.warn(i18n.Tx("backup.warn.unsigned"))
	}
	serials := map[[2]string]string{} // (equipo, ronda) -> número de serie de show version
	for _, sec := range b.Sections {
		if !sec.Invalid && !sec.Incomplete && capture.Key(sec.Command) == "show version" {
			if v, _ := iosxe.ParseVersion(sec.Text); v.Serial != "" {
				serials[[2]string{sec.Device, strconv.Itoa(sec.Round)}] = v.Serial
			}
		}
	}
	touched, dup := map[string]bool{}, map[slot]bool{}
	for _, sec := range valid {
		kind, _ := kindOf(sec.Command)
		k := slot{sec.Device, sec.Round, kind}
		if count[k] > 1 {
			if !dup[k] {
				dup[k], failed = true, true
				res.warn(i18n.Tx("backup.warn.dup_section", "device", sec.Device, "cmd", sec.Command, "round", sec.Round))
			}
			continue
		}
		at := sec.At
		if at.IsZero() {
			at = s.d.Now()
		}
		e, created, err := st.Save(backup.Entry{Device: sec.Device, Kind: kind, At: at, Masked: mk, Job: job, Round: sec.Round,
			Serial: serials[[2]string{sec.Device, strconv.Itoa(sec.Round)}], Truncated: sec.Truncated}, sec.Text)
		if err != nil {
			res.warn(i18n.Tx("backup.warn.device_cause", "device", sec.Device).With("cause", i18n.FromErr(err)))
			failed = true
			continue
		}
		touched[e.Device] = true
		if !created {
			res.Skipped++
			continue
		}
		res.Saved = append(res.Saved, e.ID)
		s.d.Audit("backup.save", e.ID, fmt.Sprintf("job=%s round=%d bytes=%d sha256=%s masked=%v", job, sec.Round, e.Bytes, e.SHA256, mk))
	}
	if tr != nil && !failed {
		// Todo lo leído se guardó: la próxima vuelta no vuelve a abrir esos archivos.
		if tr.done == nil {
			tr.done = map[string]int64{}
		}
		for rel, n := range b.Files {
			tr.done[rel] = n
		}
	}
	for dev := range touched {
		n, err := st.Prune(dev, keep)
		if err != nil {
			res.warn(i18n.Tx("backup.warn.prune", "device", dev).With("cause", i18n.FromErr(err)))
		}
		if n > 0 {
			res.Pruned += n
			s.d.Audit("backup.prune", dev, fmt.Sprintf("deleted=%d keep=%d", n, keep))
		}
	}
	s.auditWarnings(job, tr, res.Warnings, res.WarningTexts)
	if tr != nil {
		tr.saved = append(tr.saved, res.Saved...)
		if terminal {
			res.Saved = slices.Clone(tr.saved)
		}
	}
	if terminal {
		res.errMsg = j.FinishErr
		// Si algo no se pudo guardar o leer entero, la carpeta de Patrol queda como única copia.
		clean := !failed && (tr == nil || !tr.incomplete) && j.FinishErr == ""
		if !clean && tr != nil {
			s.d.Audit("backup.kept", job, "Patrol folder kept: "+tr.lote)
		}
		s.forget(job, tr, clean)
	}
	return res, nil
}

func kindOf(cmd string) (backup.Kind, bool) {
	switch capture.Key(cmd) {
	case "show running-config":
		return backup.Running, true
	case "show startup-config":
		return backup.Startup, true
	}
	return "", false
}

// auditWarnings anota los avisos del vigilante; los de un trabajo propio, una sola vez cada uno.
func (s *backupSvc) auditWarnings(job string, tr *tracked, ws []string, ts []i18n.Text) {
	en := i18n.Notes(i18n.En, ws, ts) // la auditoría va en inglés
	for i, w := range ws {
		if tr != nil {
			if tr.warned[w] {
				continue
			}
			if tr.warned == nil {
				tr.warned = map[string]bool{}
			}
			tr.warned[w] = true
		}
		s.d.Audit("backup.warning", job, en[i])
	}
}

// forget suelta el trabajo; con clean borra su carpeta de Patrol (ya copiada), solo si la creó este servicio.
func (s *backupSvc) forget(job string, tr *tracked, clean bool) {
	delete(s.jobs, job)
	delete(s.seen, job)
	if clean && tr != nil && filepath.Dir(tr.lote) == filepath.Join(s.outputs(tr), "respaldos", trabajos) {
		os.RemoveAll(tr.lote)
	}
}

func (s *backupSvc) CollectBackups(ctx context.Context, r *v1.CollectBackupsRequest) (*v1.CollectBackupsResponse, error) {
	s.d.MarkActive()
	keep := 0 // 0 = la retención del trabajo propio, o la de por defecto
	if r.Keep > 0 {
		var err error
		if keep, err = keepOf(ctx, r.Keep); err != nil {
			return nil, err
		}
	}
	c, err := s.collect(ctx, r.JobId, keep)
	if err != nil {
		return nil, err
	}
	return &v1.CollectBackupsResponse{State: c.state, Done: c.done, Error: c.errMsg, Report: service.Report(c, c.text(i18n.Locale(ctx)))}, nil
}

func (s *backupSvc) ListBackups(ctx context.Context, r *v1.ListBackupsRequest) (*v1.ListBackupsResponse, error) {
	s.d.MarkActive()
	loc := i18n.Locale(ctx)
	es, err := s.store().List(r.Device)
	if err != nil {
		return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	if es == nil {
		es = []backup.Entry{}
	}
	anyMasked := false
	var b strings.Builder
	for _, e := range es {
		m := ""
		if e.Masked {
			m, anyMasked = i18n.Msg(loc, "backup.list.masked", nil), true
		}
		fmt.Fprintf(&b, "%s  %s  %s  %d bytes%s\n", e.ID, e.At.Format("2006-01-02 15:04:05Z"), e.Kind, e.Bytes, m)
	}
	if len(es) == 0 {
		b.WriteString(i18n.Msg(loc, "backup.list.none", nil) + "\n")
	}
	if anyMasked {
		b.WriteString("\n" + i18n.Msg(loc, "backup.rep.notice", i18n.A("w", i18n.Msg(loc, "backup.list.masked_notice", nil))) + "\n")
	}
	return &v1.ListBackupsResponse{Report: service.Report(map[string]any{"backups": es, "masked": anyMasked}, b.String())}, nil
}

func (s *backupSvc) GetBackup(ctx context.Context, r *v1.GetBackupRequest) (*v1.GetBackupResponse, error) {
	s.d.MarkActive()
	e, text, err := s.store().Get(r.Id)
	if err != nil {
		return nil, service.ErrFrom(ctx, codes.NotFound, err)
	}
	s.d.Audit("backup.export", e.ID, fmt.Sprintf("bytes=%d masked=%v", e.Bytes, e.Masked))
	meta, _ := json.Marshal(e)
	return &v1.GetBackupResponse{MetaJson: string(meta), Text: text}, nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// Module registra el servicio Backup y, al cerrarse el núcleo, detiene a sus vigilantes.
type Module struct{}

func (Module) Register(r ipc.Registrar, d service.Deps) {
	s := newSvc(d)
	d.OnClose(s.close)
	v1.RegisterBackupServiceServer(r, s)
}
