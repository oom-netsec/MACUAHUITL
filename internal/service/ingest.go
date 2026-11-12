package service

import (
	"cmp"
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/ingest"
)

// Defaults del archivo: con 20 de 50 MB el tope en disco es ~1 GB.
const (
	defRotateMB = 50
	defMaxFiles = 20
)

// IngestOpts son los campos de topes y de archivo que comparten Syslog, SnmpTraps y
// Flows (los mismos de SyslogRequest). 0 = default; fuera de rango = InvalidArgument.
type IngestOpts struct {
	RatePerSource, BurstPerSource, RateGlobal, BurstGlobal, QueueSize int32
	RotateMB, RotateMinutes, MaxFiles                                 int32
	NameTemplate, Format                                              string
	DefPerSource, DefGlobal                                           int            // default de la tasa de este receptor; 0 = el de ingest
	Prefs                                                             IngestDefaults // preferencias del núcleo: rigen donde el campo viene en 0 o vacío
}

// minutes pasa minutos a Duration sin desbordar: n*Minute en int64 da la vuelta con ~3e8 y un valor absurdo parecería
// válido. Se acota antes de multiplicar; lo que queda fuera de 1-10080 sigue fuera y Sink.Validate lo rechaza.
func minutes(n int32) time.Duration { return time.Duration(max(-1, min(n, 1<<20))) * time.Minute }

// ValidateIngestDefaults comprueba los rangos de las preferencias con las mismas reglas del archivo.
func ValidateIngestDefaults(ctx context.Context, d IngestDefaults) error {
	s := ingest.Sink{Dir: "x", Template: "t_{fecha}", RotateBytes: int64(d.RotateMB) << 20,
		RotateEvery: minutes(d.RotateMinutes), MaxFiles: int(d.MaxFiles), Format: d.Format}
	if s.MaxFiles == 0 {
		s.MaxFiles = 1
	}
	if err := s.Validate(); err != nil {
		return ErrFrom(ctx, codes.InvalidArgument, err)
	}
	return nil
}

// Build valida los rangos y arma los topes y el archivo (en dir) con los defaults;
// defTemplate es el nombre por omisión de cada receptor.
func (o IngestOpts) Build(ctx context.Context, dir, defTemplate string) (ingest.Limits, ingest.Sink, error) {
	lim := ingest.Limits{PerSource: int(o.RatePerSource), PerSourceBurst: int(o.BurstPerSource), Global: int(o.RateGlobal), GlobalBurst: int(o.BurstGlobal), Queue: int(o.QueueSize)}
	if err := lim.Validate(); err != nil {
		return lim, ingest.Sink{}, ErrFrom(ctx, codes.InvalidArgument, err)
	}
	if lim.PerSource == 0 {
		lim.PerSource = o.DefPerSource
	}
	if lim.Global == 0 {
		lim.Global = o.DefGlobal
	}
	sink := ingest.Sink{
		Dir: dir, Template: o.NameTemplate, RotateBytes: int64(o.RotateMB) << 20,
		RotateEvery: minutes(o.RotateMinutes), MaxFiles: int(o.MaxFiles), Format: o.Format,
	}
	if o.RotateMB == 0 {
		sink.RotateBytes = int64(cmp.Or(o.Prefs.RotateMB, defRotateMB)) << 20
	}
	if o.RotateMinutes == 0 {
		sink.RotateEvery = minutes(o.Prefs.RotateMinutes)
	}
	if sink.Template == "" {
		sink.Template = defTemplate
	}
	if o.MaxFiles == 0 {
		sink.MaxFiles = int(cmp.Or(o.Prefs.MaxFiles, defMaxFiles))
	}
	if sink.Format == "" {
		sink.Format = cmp.Or(o.Prefs.Format, "texto")
	}
	if err := sink.Validate(); err != nil {
		return lim, sink, ErrFrom(ctx, codes.InvalidArgument, err)
	}
	return lim, sink, nil
}

// IngestDetail es la configuración efectiva para la auditoría; con save agrega la del archivo.
func IngestDetail(l ingest.Limits, s ingest.Sink, save bool) string {
	e := l.Effective()
	d := fmt.Sprintf("tasa_origen=%d rafaga_origen=%d tasa_global=%d rafaga_global=%d cola=%d", e.PerSource, e.PerSourceBurst, e.Global, e.GlobalBurst, e.Queue)
	if save {
		d += fmt.Sprintf(" rotar_mb=%d rotar_min=%d plantilla=%s max_archivos=%d formato=%s", s.RotateBytes>>20, int(s.RotateEvery/time.Minute), s.Template, s.MaxFiles, s.Format)
	}
	return d
}

// DropsProto pasa el acumulado de descartes al mensaje del contrato.
func DropsProto(d ingest.Drops) *v1.SyslogDrops {
	out := &v1.SyslogDrops{Total: d.Total, PorOrigen: d.PorOrigen, Global: d.Global, ColaLlena: d.ColaLlena, SinceMs: d.Desde.UnixMilli()}
	for _, t := range d.Top {
		out.Top = append(out.Top, &v1.SyslogSourceDrops{Source: t.Source, Count: t.Count})
	}
	return out
}

// Pump lleva los eventos al stream de un cliente sin frenar nunca al receptor: un solo Send a la vez (el
// stream no admite concurrentes) y, si la cola hacia el cliente se llena, el evento se pierde para la
// interfaz (se cuenta); el archivo no lo pierde.
type Pump[M any] struct {
	out    chan M
	pumped chan struct{}
	lost   atomic.Uint64
}

// NewPump arranca el envío con una cola de queue eventos.
func NewPump[M any](send func(M) error, queue int) *Pump[M] {
	p := &Pump[M]{out: make(chan M, queue), pumped: make(chan struct{})}
	go func() {
		defer close(p.pumped)
		for m := range p.out {
			send(m)
		}
	}()
	return p
}

// Send encola sin esperar; con la cola llena el evento se pierde y se cuenta.
func (p *Pump[M]) Send(m M) {
	select {
	case p.out <- m:
	default:
		p.lost.Add(1)
	}
}

// Close entrega lo que ya está en cola, con espera acotada por grace (el contexto del stream no es el que
// vence, y al volver del RPC se cancela y libera el Send atascado), y devuelve los eventos perdidos.
func (p *Pump[M]) Close(grace time.Duration) uint64 {
	close(p.out)
	select {
	case <-p.pumped:
	case <-time.After(grace):
		p.lost.Add(uint64(len(p.out))) // lo que quedó en cola no se entregó
	}
	return p.lost.Load()
}
