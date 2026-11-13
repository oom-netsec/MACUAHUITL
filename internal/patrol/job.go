// Package patrol define los trabajos de recolección: validación, Login Test,
// ejecución por equipo, outputs, manifest con hashes y zip (spec §12).
//
// No hace: programar rondas; eso es de engine.
package patrol

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/platform/iosxe"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

type SplitStrategy int

const (
	SplitPerRound SplitStrategy = iota // valor cero = por ronda
	SplitConsolidated
)

type ZipPolicy int

const (
	ZipAtEnd ZipPolicy = iota // valor cero = al final
	ZipNone
	ZipPerRound
)

type Target struct {
	Address  string
	Port     uint16 // 0 = 22
	DeviceID string
}

type Override struct {
	DeviceID, CredentialID, FallbackCredentialID string
}

type Schedule struct {
	IntervalSeconds, Rounds uint32
	Until                   time.Time
	Cron                    string
}

// Spec es el espejo Go de JobSpec (api/proto/macuahuitl/v1/patrol.proto).
type Spec struct {
	Name                string
	Targets             []Target
	DefaultCredentialID string
	Overrides           []Override
	PlaybookIDs         []string
	CustomCommands      string
	OutputDir           string
	// Kind: patrol (vacío), adhoc, backup o change; lo pone el servicio que crea el trabajo.
	Kind                  string
	Split                 SplitStrategy
	Schedule              Schedule
	Zip                   ZipPolicy
	DeleteLooseFiles      bool
	DisableMasking        bool // valor cero = enmascarado (spec §12.5)
	AcceptChangedHostKeys bool // valor cero = omitir el equipo (spec §12.2)
	WindowHours           uint32
}

// Deps son los servicios que Patrol usa; el núcleo los arma.
type Deps struct {
	Guard     *transport.Guard
	Hosts     *transport.KnownHosts
	Vault     *vault.Vault
	Audit     *audit.Log
	Now       func() time.Time
	Playbooks []playbook.Playbook
	// MissingPack dice qué paquete trae un playbook que ya no está (movido o de un paquete quitado); nil o "" = ninguno.
	MissingPack func(id string) string
	NewDriver   func() platform.Driver // nil = iosxe.New
	// PrimaryVerified: host:puerto cuya credencial principal pasó el Login Test al armar.
	// Solo para esos equipos se intenta la credencial de respaldo tras un rechazo (spec §10.2).
	PrimaryVerified map[string]bool
	// RetryBackoff son las esperas entre reintentos por falla de conexión; nil = 1 s, 2 s, 4 s (spec §6).
	RetryBackoff []time.Duration
}

func (d Deps) backoff() []time.Duration {
	if d.RetryBackoff != nil {
		return d.RetryBackoff
	}
	return []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
}

func (d Deps) driver() platform.Driver {
	if d.NewDriver != nil {
		return d.NewDriver()
	}
	return iosxe.New()
}

// FieldError es un campo inválido del trabajo. Msg es el texto en español de siempre; T es el mismo mensaje como
// texto de catálogo, con lo que el error es un i18n.Coded (reason = la clave de T, metadata = sus argumentos y el campo).
type FieldError struct {
	Field, Msg string
	T          i18n.Text
}

func (e *FieldError) Error() string { return "patrol: " + e.Field + ": " + e.Msg }

func (e *FieldError) Reason() string { return i18n.Reason(e.T.Key) }

func (e *FieldError) Metadata() map[string]string {
	m := i18n.Metadata(e.T.Key, e.T.Args)
	m["field"] = e.Field
	return m
}

func (e *FieldError) Localize(loc string) string { return "patrol: " + e.Field + ": " + e.T.In(loc) }

// fieldErr arma el error del campo f con el mensaje del código key (patrol.field.*) y sus argumentos.
func fieldErr(f, key string, kv ...any) error {
	t := i18n.Tx(key, kv...)
	return &FieldError{Field: f, Msg: t.In(i18n.Es), T: t}
}

// fieldErrOf es fieldErr para un error ya armado: con código del catálogo lo conserva; sin él, va como texto de sistema.
func fieldErrOf(f string, err error) error {
	var ie *i18n.Error
	if errors.As(err, &ie) && ie.Error() == err.Error() { // solo si el error es el del catálogo, sin envoltorio propio
		return fieldErr(f, ie.Code, kvOf(ie.Args)...)
	}
	return fieldErr(f, "patrol.field.error", "error", err.Error())
}

func kvOf(a i18n.Args) (kv []any) {
	for k, v := range a {
		kv = append(kv, k, v)
	}
	return kv
}

// ValidateWith revisa el trabajo antes de crearlo, para no fallar a mitad de la primera ronda.
// v debe estar abierta; con v nil no se revisan las credenciales.
// noPlaybook es el error de un playbook que no existe; si lo trae un paquete que no está instalado, pack.missing.
func noPlaybook(id string, missing func(string) string) error {
	if missing != nil {
		if pk := missing(id); pk != "" {
			return fieldErr("playbook_ids", "pack.missing", "playbook", id, "pack", pk)
		}
	}
	return fieldErr("playbook_ids", "patrol.field.no_playbook", "id", id)
}

// missing dice qué paquete trae un playbook que ya no está (pack.missing, ADR 0010); nil = ninguno.
func ValidateWith(s Spec, pbs []playbook.Playbook, v *vault.Vault, missing func(string) string) error {
	if len(s.Targets) == 0 {
		return fieldErr("targets", "patrol.field.no_targets")
	}
	if s.DefaultCredentialID == "" {
		return fieldErr("credential", "patrol.field.no_credential")
	}
	if s.WindowHours == 0 || s.WindowHours > 96 {
		return fieldErr("window_hours", "patrol.field.window", "n", s.WindowHours)
	}
	if err := writable(s.OutputDir); err != nil {
		return fieldErrOf("output_dir", err)
	}
	if s.CustomCommands == "" && len(s.PlaybookIDs) == 0 {
		return fieldErr("commands", "patrol.field.no_commands")
	}
	if s.CustomCommands != "" {
		if _, err := playbook.Ephemeral("ios-xe", s.CustomCommands); err != nil {
			return fieldErrOf("custom_commands", err)
		}
	}
	for _, id := range s.PlaybookIDs {
		if find(pbs, id) == nil && playbook.Twin(pbs, id, "ios") == nil && playbook.Twin(pbs, id, "ios-xe") == nil {
			return noPlaybook(id, missing)
		}
	}
	if v != nil {
		infos, err := v.List()
		if err != nil {
			return fieldErrOf("credential", err)
		}
		have := map[string]bool{}
		for _, i := range infos {
			have[i.ID] = true
		}
		if !have[s.DefaultCredentialID] {
			return fieldErr("credential", "patrol.field.cred_missing", "id", s.DefaultCredentialID)
		}
		for _, o := range s.Overrides {
			for _, id := range []string{o.CredentialID, o.FallbackCredentialID} {
				if id != "" && !have[id] {
					return fieldErr("overrides", "patrol.field.override_missing", "id", id, "device", o.DeviceID)
				}
			}
		}
	}
	sc := s.Schedule
	if sc.IntervalSeconds > 0 && sc.Cron != "" {
		return fieldErr("schedule", "patrol.field.schedule_exclusive")
	}
	if sc.Cron != "" {
		if _, err := cron.ParseStandard(sc.Cron); err != nil {
			return fieldErr("schedule", "patrol.field.cron", "error", err.Error())
		}
	}
	if !sc.Until.IsZero() && !sc.Until.After(time.Now()) {
		return fieldErr("schedule", "patrol.field.until_past")
	}
	return nil
}

func writable(dir string) error {
	if dir == "" {
		return i18n.New("patrol.writable.empty", nil)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return i18n.New("patrol.writable.not_dir", nil)
	}
	f, err := os.CreateTemp(dir, ".macuahuitl-prueba-*")
	if err != nil {
		return i18n.Wrap("patrol.writable.no_write", err, nil)
	}
	f.Close()
	return os.Remove(f.Name())
}

func find(pbs []playbook.Playbook, id string) *playbook.Playbook {
	for i := range pbs {
		if pbs[i].ID == id {
			return &pbs[i]
		}
	}
	return nil
}

func iosFamily(p string) bool { return p == "ios" || p == "ios-xe" }

// resolve da los playbooks que corren en la plataforma detectada, en orden y sin repetir: cada ID elegido pasa a su
// gemelo (ios/x en IOS clásico, ios-xe/x en IOS-XE), también si el elegido ya no existe.
func resolve(s Spec, detected string, pbs []playbook.Playbook, missing func(string) string) ([]*playbook.Playbook, error) {
	var out []*playbook.Playbook
	seen := map[string]bool{}
	for _, id := range s.PlaybookIDs {
		p := find(pbs, id)
		if iosFamily(detected) && (p == nil || iosFamily(p.Platform)) { // flota mixta
			if twin := playbook.Twin(pbs, id, detected); twin != nil {
				p = twin
			}
		}
		if p == nil {
			return nil, noPlaybook(id, missing)
		}
		if !playbook.Compatible(detected, p.Platform) {
			return nil, i18n.New("patrol.err.playbook_platform", i18n.A("id", id, "platform", p.Platform, "detected", detected))
		}
		if !seen[p.ID] { // elegir los dos del par no corre el playbook dos veces
			seen[p.ID] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// commands arma la lista para la plataforma detectada: playbooks elegidos y luego los pegados. Los comandos
// marcados para otras plataformas (platforms:) no entran; skipped trae su texto, para anotarlo en el manifest.
func commands(s Spec, detected string, pbs []playbook.Playbook, missing func(string) string) (out []playbook.Command, skipped []string, err error) {
	ran, err := resolve(s, detected, pbs, missing)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range ran {
		for _, pre := range p.Pre {
			out = append(out, playbook.Command{Text: pre, Timeout: 60 * time.Second})
		}
		for _, c := range p.Commands {
			if c.Applies(detected) {
				out = append(out, c)
			} else {
				skipped = append(skipped, c.Text)
			}
		}
	}
	if s.CustomCommands != "" {
		p, err := playbook.Ephemeral(detected, s.CustomCommands)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, p.Commands...)
	}
	return out, skipped, nil
}

func credentialsFor(s Spec, t Target) (primary, fallback string) {
	primary = s.DefaultCredentialID
	for _, o := range s.Overrides {
		if o.DeviceID != "" && o.DeviceID == t.DeviceID {
			if o.CredentialID != "" {
				primary = o.CredentialID
			}
			fallback = o.FallbackCredentialID
		}
	}
	return primary, fallback
}

// EffectivePort es el puerto SSH que se usa de verdad: 0 en la spec significa el de omisión (22).
func EffectivePort(p uint16) uint16 {
	if p == 0 {
		return 22
	}
	return p
}

func port(t Target) uint16 { return EffectivePort(t.Port) }

func dirName(s string) string {
	b := []byte(s)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			b[i] = '_'
		}
	}
	if len(b) == 0 || string(b) == "." || string(b) == ".." {
		return "trabajo"
	}
	return filepath.Base(string(b))
}
