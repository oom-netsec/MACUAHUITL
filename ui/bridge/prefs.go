package bridge

import (
	"context"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Preferencias de la interfaz ----

// GetPreference devuelve el valor guardado en el núcleo, o "" si no hay.
func (b *Bridge) GetPreference(key string) (string, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewPrefsServiceClient(c).GetPreference(ctx, &v1.GetPreferenceRequest{Key: key})
		return r.GetValue(), err
	})
}

func (b *Bridge) SetPreference(key, value string) error {
	_, err := call(b, func(ctx context.Context, c *ipc.ClientConn) (struct{}, error) {
		_, err := v1.NewPrefsServiceClient(c).SetPreference(ctx, &v1.SetPreferenceRequest{Key: key, Value: value})
		return struct{}{}, err
	})
	if err == nil && key == langPref {
		b.setLanguage(value)
	}
	return err
}

// ---- Preferencias del núcleo (fase 29e) ----

// CorePrefsDTO son las preferencias tipadas del núcleo. En Set viajan los cuatro primeros campos (0 o vacío = de
// fábrica); el resto lo llena el núcleo. Los errores de la carpeta empiezan con prefs.outputs.<motivo>.
type CorePrefsDTO struct {
	OutputsDir          string `json:"outputsDir"`
	RotateMB            int32  `json:"rotateMb"`
	RotateMin           int32  `json:"rotateMin"`
	MaxFiles            int32  `json:"maxFiles"`
	Format              string `json:"format"`
	OutputsDirEffective string `json:"outputsDirEffective"`
	OutputsDirDefault   string `json:"outputsDirDefault"`
	Note                string `json:"note"`
}

func corePrefsDTO(s *v1.CorePrefsState) CorePrefsDTO {
	in := s.GetPrefs().GetIngestDefaults()
	return CorePrefsDTO{OutputsDir: s.GetPrefs().GetOutputsDir(), RotateMB: in.GetRotateMb(), RotateMin: in.GetRotateMinutes(), MaxFiles: in.GetMaxFiles(), Format: in.GetFormat(),
		OutputsDirEffective: s.GetOutputsDirEffective(), OutputsDirDefault: s.GetOutputsDirDefault(), Note: s.GetNote()}
}

func (b *Bridge) GetCorePrefs() (CorePrefsDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (CorePrefsDTO, error) {
		r, err := v1.NewPrefsServiceClient(c).GetCorePrefs(ctx, &v1.GetCorePrefsRequest{})
		return corePrefsDTO(r.GetState()), err
	})
}

// SetCorePrefs reemplaza las preferencias del núcleo: lo que va en 0 o vacío vuelve al de fábrica.
func (b *Bridge) SetCorePrefs(p CorePrefsDTO) (CorePrefsDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (CorePrefsDTO, error) {
		r, err := v1.NewPrefsServiceClient(c).SetCorePrefs(ctx, &v1.SetCorePrefsRequest{Prefs: &v1.CorePrefs{OutputsDir: p.OutputsDir,
			IngestDefaults: &v1.IngestDefaults{RotateMb: p.RotateMB, RotateMinutes: p.RotateMin, MaxFiles: p.MaxFiles, Format: p.Format}}})
		return corePrefsDTO(r.GetState()), err
	})
}
