// Package patrol define los trabajos de recolección: validación, Login Test,
// ejecución por equipo, outputs, manifest con hashes y zip (spec §12).
//
// No hace: programar rondas; eso es de engine.
package patrol

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
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
	Name                  string
	Targets               []Target
	DefaultCredentialID   string
	Overrides             []Override
	PlaybookIDs           []string
	CustomCommands        string
	OutputDir             string
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
	NewDriver func() platform.Driver // nil = iosxe.New
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

type FieldError struct{ Field, Msg string }

func (e *FieldError) Error() string { return "patrol: " + e.Field + ": " + e.Msg }

func fieldErr(f, format string, a ...any) error {
	return &FieldError{Field: f, Msg: fmt.Sprintf(format, a...)}
}

// Validate revisa el trabajo antes de crearlo, para no fallar a mitad de la primera ronda.
// v debe estar abierta; con v nil no se revisan las credenciales.
func Validate(s Spec, pbs []playbook.Playbook, v *vault.Vault) error {
	if len(s.Targets) == 0 {
		return fieldErr("targets", "sin equipos")
	}
	if s.DefaultCredentialID == "" {
		return fieldErr("credential", "sin credencial por defecto")
	}
	if s.WindowHours == 0 || s.WindowHours > 96 {
		return fieldErr("window_hours", "debe estar entre 1 y 96, es %d", s.WindowHours)
	}
	if err := writable(s.OutputDir); err != nil {
		return fieldErr("output_dir", "%v", err)
	}
	if s.CustomCommands == "" && len(s.PlaybookIDs) == 0 {
		return fieldErr("commands", "sin playbooks ni comandos")
	}
	if s.CustomCommands != "" {
		if _, err := playbook.Ephemeral("ios-xe", s.CustomCommands); err != nil {
			return fieldErr("custom_commands", "%v", err)
		}
	}
	for _, id := range s.PlaybookIDs {
		if find(pbs, id) == nil {
			return fieldErr("playbook_ids", "%s no existe", id)
		}
	}
	if v != nil {
		infos, err := v.List()
		if err != nil {
			return fieldErr("credential", "%v", err)
		}
		have := map[string]bool{}
		for _, i := range infos {
			have[i.ID] = true
		}
		if !have[s.DefaultCredentialID] {
			return fieldErr("credential", "%s no está en la bóveda", s.DefaultCredentialID)
		}
		for _, o := range s.Overrides {
			for _, id := range []string{o.CredentialID, o.FallbackCredentialID} {
				if id != "" && !have[id] {
					return fieldErr("overrides", "%s (equipo %s) no está en la bóveda", id, o.DeviceID)
				}
			}
		}
	}
	sc := s.Schedule
	if sc.IntervalSeconds > 0 && sc.Cron != "" {
		return fieldErr("schedule", "intervalo y cron son excluyentes")
	}
	if sc.Cron != "" {
		if _, err := cron.ParseStandard(sc.Cron); err != nil {
			return fieldErr("schedule", "cron: %v", err)
		}
	}
	if !sc.Until.IsZero() && !sc.Until.After(time.Now()) {
		return fieldErr("schedule", "la fecha de fin ya pasó")
	}
	return nil
}

func writable(dir string) error {
	if dir == "" {
		return errors.New("vacía")
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return errors.New("no es una carpeta")
	}
	f, err := os.CreateTemp(dir, ".macuahuitl-prueba-*")
	if err != nil {
		return fmt.Errorf("sin permiso de escritura: %w", err)
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

// compatible: un IOS clásico usa los playbooks de IOS-XE; lo que no exista queda marcado inválido.
func compatible(detected, pbPlatform string) bool {
	return detected == pbPlatform || (detected == "ios" && pbPlatform == "ios-xe")
}

// commands arma la lista para la plataforma detectada: playbooks elegidos y luego los pegados.
func commands(s Spec, detected string, pbs []playbook.Playbook) ([]playbook.Command, error) {
	var out []playbook.Command
	for _, id := range s.PlaybookIDs {
		p := find(pbs, id)
		if p == nil {
			return nil, fieldErr("playbook_ids", "%s no existe", id)
		}
		if !compatible(detected, p.Platform) {
			return nil, fmt.Errorf("patrol: el playbook %s es para %s y el equipo es %s", id, p.Platform, detected)
		}
		for _, pre := range p.Pre {
			out = append(out, playbook.Command{Text: pre, Timeout: 60 * time.Second})
		}
		out = append(out, p.Commands...)
	}
	if s.CustomCommands != "" {
		p, err := playbook.Ephemeral(detected, s.CustomCommands)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Commands...)
	}
	return out, nil
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

func port(t Target) uint16 {
	if t.Port == 0 {
		return 22
	}
	return t.Port
}

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
