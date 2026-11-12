package prefs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// prefKeys es la lista cerrada de preferencias aceptadas; agregar una aquí al crear su pantalla.
var prefKeys = map[string]bool{"terminal": true, "ui.language": true}

const maxPrefValue = 4096

// prefsSvc guarda preferencias de la interfaz (clave/valor pequeño) en el store.
type prefsSvc struct {
	v1.UnimplementedPrefsServiceServer
	d  service.Deps
	mu sync.Mutex // serializa SetCorePrefs: validar, guardar y aplicar son un solo paso
}

// okKey acepta solo las claves de la lista cerrada; el prefijo core.* es de las preferencias del núcleo
// (GetCorePrefs/SetCorePrefs) y este camino genérico nunca lo toca, aunque alguien lo agregue a prefKeys.
func okKey(k string) bool { return prefKeys[k] && !strings.HasPrefix(k, service.CorePrefix) }

func (s *prefsSvc) GetPreference(_ context.Context, r *v1.GetPreferenceRequest) (*v1.GetPreferenceResponse, error) {
	if !okKey(r.Key) {
		return nil, status.Error(codes.InvalidArgument, "clave de preferencia inválida")
	}
	var v string
	err := s.d.DB().QueryRow(`SELECT value FROM preferences WHERE key = ?`, r.Key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return &v1.GetPreferenceResponse{}, nil
	}
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &v1.GetPreferenceResponse{Value: v, Found: true}, nil
}

func (s *prefsSvc) SetPreference(_ context.Context, r *v1.SetPreferenceRequest) (*v1.SetPreferenceResponse, error) {
	if !okKey(r.Key) {
		return nil, status.Error(codes.InvalidArgument, "clave de preferencia inválida")
	}
	if r.Key == "ui.language" && r.Value != "es" && r.Value != "en" {
		return nil, status.Error(codes.InvalidArgument, "ui.language debe ser es o en")
	}
	if len(r.Value) > maxPrefValue {
		return nil, status.Error(codes.InvalidArgument, "valor de preferencia mayor de 4 KiB")
	}
	_, err := s.d.DB().Exec(`INSERT INTO preferences(key,value,updated_at) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		r.Key, r.Value, s.d.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &v1.SetPreferenceResponse{}, nil
}

const outputsNote = "El cambio aplica a lo que empiece después: los trabajos y escuchas en curso conservan la carpeta con que arrancaron. Los datos de la carpeta anterior no se mueven."

func (s *prefsSvc) state(note string) *v1.CorePrefsState {
	st := s.d.Settings()
	note = strings.TrimSpace(note + " " + st.Issue())
	out, ing := st.Configured()
	return &v1.CorePrefsState{
		Prefs:               &v1.CorePrefs{OutputsDir: out, IngestDefaults: &v1.IngestDefaults{RotateMb: ing.RotateMB, RotateMinutes: ing.RotateMinutes, MaxFiles: ing.MaxFiles, Format: ing.Format}},
		OutputsDirEffective: st.Outputs(), OutputsDirDefault: st.Factory(), Note: note,
	}
}

func (s *prefsSvc) GetCorePrefs(context.Context, *v1.GetCorePrefsRequest) (*v1.GetCorePrefsResponse, error) {
	return &v1.GetCorePrefsResponse{State: s.state("")}, nil
}

// SetCorePrefs reemplaza las preferencias del núcleo: lo que va en 0 o vacío vuelve al de fábrica.
func (s *prefsSvc) SetCorePrefs(ctx context.Context, r *v1.SetCorePrefsRequest) (*v1.SetCorePrefsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in := r.GetPrefs().GetIngestDefaults()
	ing := service.IngestDefaults{RotateMB: in.GetRotateMb(), RotateMinutes: in.GetRotateMinutes(), MaxFiles: in.GetMaxFiles(), Format: in.GetFormat()}
	if err := service.ValidateIngestDefaults(ctx, ing); err != nil {
		return nil, err
	}
	st := s.d.Settings()
	oldOut, oldIng := st.Configured()
	req, issue := r.GetPrefs().GetOutputsDir(), ""
	out, err := service.CheckOutputs(req, st, true)
	if err != nil {
		if req == "" || req != oldOut {
			return nil, err
		}
		// La carpeta no cambia pero ya no vale: el resto sí se guarda y el estado avisa (rige la de fábrica).
		out, issue = oldOut, service.OutputsIssue(oldOut, status.Convert(err).Message())
	}
	var ch []string
	diff := func(name, a, b string) {
		if a != b {
			ch = append(ch, fmt.Sprintf("%s: %s -> %s", name, a, b))
		}
	}
	diff("outputs_dir", cmpOutputs(oldOut, st.Factory()), cmpOutputs(out, st.Factory()))
	diff("rotate_mb", fmt.Sprint(oldIng.RotateMB), fmt.Sprint(ing.RotateMB))
	diff("rotate_min", fmt.Sprint(oldIng.RotateMinutes), fmt.Sprint(ing.RotateMinutes))
	diff("max_files", fmt.Sprint(oldIng.MaxFiles), fmt.Sprint(ing.MaxFiles))
	diff("format", oldIng.Format, ing.Format)
	diff("carpeta_invalida", st.Issue(), issue)
	if len(ch) == 0 {
		return &v1.SetCorePrefsResponse{State: s.state("")}, nil
	}
	if err := service.SaveCoreSettings(s.d.DB(), s.d.Now(), out, ing); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	st.Apply(out, ing)
	st.Mark(issue)
	s.d.Audit("prefs.core", "core", strings.Join(ch, " "))
	note := ""
	if oldOut != out {
		note = outputsNote
	}
	return &v1.SetCorePrefsResponse{State: s.state(note)}, nil
}

// cmpOutputs muestra la carpeta de fábrica cuando no hay una configurada, para que la auditoría diga rutas reales.
func cmpOutputs(configured, factory string) string {
	if configured == "" {
		return factory
	}
	return configured
}

// Module registra el servicio Prefs.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterPrefsServiceServer(s, &prefsSvc{d: d})
}
