package bridge

import (
	"context"
	"fmt"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Forense de logs y fallas (Fase 17): solo lectura ----

// ForensicMsg devuelve el JSON de las fichas de la base de mensajes (mnemónico exacto o con comodín).
func (b *Bridge) ForensicMsg(query string) (string, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewForensicServiceClient(c).MsgLookup(ctx, &v1.MsgLookupRequest{Query: query})
		return r.GetReport().GetJson(), err
	})
}

// ForensicCrashinfo analiza el texto pegado o, si text va vacío, el archivo de path (ruta absoluta).
func (b *Bridge) ForensicCrashinfo(text, path string) (string, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewForensicServiceClient(c).Crashinfo(ctx, &v1.CrashinfoRequest{Text: text, Path: path})
		return r.GetReport().GetJson(), err
	})
}

// LogSourceDTO es de dónde salen los mensajes: exactamente una de texto, path, capture o job.
type LogSourceDTO struct {
	Text    string `json:"text"`
	Path    string `json:"path"`
	Capture bool   `json:"capture"`
	Job     string `json:"job"`
	Device  string `json:"device"`
	MaxKiB  uint32 `json:"max_kib"` // con capture: solo el final, a lo más tantos KiB (0 = tope normal)
}

func (s LogSourceDTO) proto() *v1.LogSource {
	return &v1.LogSource{Text: s.Text, Path: s.Path, Capture: s.Capture, Job: s.Job, Device: s.Device, MaxKib: s.MaxKiB}
}

// ForensicPatterns agrupa por patrón y marca ráfagas (burst mensajes en window segundos; 0 = 5 en 60).
func (b *Bridge) ForensicPatterns(src LogSourceDTO, burst, window int) (string, error) {
	if burst < 0 || window < 0 {
		return "", wrapErr(fmt.Errorf("ráfaga inválida: %d en %d s", burst, window))
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewForensicServiceClient(c).LogPatterns(ctx, &v1.LogPatternsRequest{Source: src.proto(), BurstCount: uint32(burst), BurstWindowSeconds: uint32(window)})
		return r.GetReport().GetJson(), err
	})
}

// ForensicFlapping detecta interfaces con count transiciones en window segundos (0 = 3 en 60) y, con un
// trabajo, saltos de contadores de al menos minDelta entre rondas (0 = 3).
func (b *Bridge) ForensicFlapping(src LogSourceDTO, count, window, minDelta int) (string, error) {
	if count < 0 || window < 0 || minDelta < 0 {
		return "", wrapErr(fmt.Errorf("umbral inválido: %d en %d s, delta %d", count, window, minDelta))
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewForensicServiceClient(c).Flapping(ctx, &v1.FlappingRequest{Source: src.proto(), Count: uint32(count), WindowSeconds: uint32(window), MinDelta: uint32(minDelta)})
		return r.GetReport().GetJson(), err
	})
}

// ForensicDebugs filtra un debug pegado (text) o de un archivo (path): agrupa, oculta el ruido y marca anomalías.
func (b *Bridge) ForensicDebugs(text, path string, noise []string, familyMin, rareMax, top int) (string, error) {
	if familyMin < 0 || rareMax < 0 || top < 0 {
		return "", wrapErr(fmt.Errorf("umbral inválido"))
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewForensicServiceClient(c).DebugFilter(ctx, &v1.DebugFilterRequest{Text: text, Path: path, Noise: noise, FamilyMin: uint32(familyMin), RareMax: uint32(rareMax), Top: uint32(top)})
		return r.GetReport().GetJson(), err
	})
}

// ForensicLeaks busca procesos con memoria creciente entre las rondas de un trabajo de Patrol.
func (b *Bridge) ForensicLeaks(job, device string, minRounds, minGrowthKiB int) (string, error) {
	if minRounds < 0 || minGrowthKiB < 0 {
		return "", wrapErr(fmt.Errorf("umbral inválido"))
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewForensicServiceClient(c).MemLeaks(ctx, &v1.MemLeaksRequest{Job: job, Device: device, MinRounds: uint32(minRounds), MinGrowthKib: uint32(minGrowthKiB)})
		return r.GetReport().GetJson(), err
	})
}
