package flows

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/ingest"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/listen"
)

// DefaultAddr: 2055 es el puerto habitual de NetFlow; IPFIX (4739) y sFlow (6343)
// se reciben en el mismo socket porque el formato se reconoce por la versión.
const DefaultAddr = "127.0.0.1:2055"

// MaxKeys acota cada tabla del agregador; MaxFile acota el archivo de flujos.
const (
	MaxKeys = 100_000
	MaxFile = 512 << 20
)

type Config struct {
	Addr        string
	AllowAny    bool
	Top         int           // elementos por tabla en cada resumen; 20 por defecto
	Every       time.Duration // cada cuánto se emite un resumen; 2 s por defecto
	Out         io.Writer     // un JSON por flujo; se deja de escribir al llegar a MaxFile
	OnListening func(addr string)
	OnSnapshot  func(Snapshot)
	Limits      ingest.Limits      // topes de tasa (por datagrama) y cola; 0 = default
	Sink        *ingest.Sink       // archivo con rotación y retención; nil = sin archivo
	Now         func() time.Time   // reloj de cubos, hora de los flujos y rotación; nil = time.Now
	OnDrops     func(ingest.Drops) // acumulado; a lo más una vez por segundo y solo si cambió, más una al cerrar
}

// Record es un flujo con la hora en que llegó; hace de él un ingest.Record: el origen
// es el exportador y la línea sale en texto, crudo o jsonl.
type Record struct {
	Time time.Time
	Flow
}

func (r Record) Origin() string { return r.Exporter }

// Text es el flujo en una línea (el «crudo» del archivo): protocolo, origen -> destino, bytes y paquetes.
func (f Flow) Text() string {
	return fmt.Sprintf("%s %s -> %s bytes=%d packets=%d exp=%s", protoName(f.Proto), endpoint(f.Src, f.SrcPort), endpoint(f.Dst, f.DstPort), f.Bytes, f.Packets, f.Exporter)
}

func endpoint(ip string, port uint16) string {
	if port == 0 {
		return ip
	}
	return net.JoinHostPort(ip, strconv.Itoa(int(port)))
}

// Line es la línea del archivo (con salto final): texto (hora, exportador y Text), crudo (solo Text) o jsonl.
func (r Record) Line(format string) []byte {
	switch format {
	case "crudo":
		return []byte(r.Text() + "\n")
	case "jsonl":
		b, _ := json.Marshal(r)
		return append(b, '\n')
	}
	return []byte(r.Time.Format(time.RFC3339) + " " + r.Exporter + " " + r.Text() + "\n")
}

// batch son los flujos de un datagrama: la unidad que se encola, así un descarte es un datagrama entero.
type batch struct {
	at    time.Time
	flows []Flow
}

// Listen recibe hasta que ctx termine y devuelve el resumen final.
func Listen(ctx context.Context, c Config) (Snapshot, error) {
	if c.Addr == "" {
		c.Addr = DefaultAddr
	}
	if c.Top <= 0 {
		c.Top = 20
	}
	if c.Every <= 0 {
		c.Every = 2 * time.Second
	}
	if err := listen.ValidateAddr(c.Addr, c.AllowAny); err != nil {
		return Snapshot{}, fmt.Errorf("flows: %w", err)
	}
	if err := c.Limits.Validate(); err != nil {
		return Snapshot{}, fmt.Errorf("flows: %w", err)
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	var w *ingest.Writer
	if c.Sink != nil {
		if err := c.Sink.Validate(); err != nil {
			return Snapshot{}, fmt.Errorf("flows: %w", err)
		}
		var err error
		if w, err = ingest.NewWriter(*c.Sink, c.Now); err != nil {
			return Snapshot{}, fmt.Errorf("flows: %w", err)
		}
		defer w.Close()
	}
	ctx, cancel := context.WithCancel(ctx) // un fallo del archivo cancela la escucha
	defer cancel()
	pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", c.Addr)
	if err != nil {
		return Snapshot{}, fmt.Errorf("flows: %w", err)
	}
	defer pc.Close()
	stop := context.AfterFunc(ctx, func() { pc.Close() })
	defer stop()
	if c.OnListening != nil {
		c.OnListening(pc.LocalAddr().String())
	}
	dec, agg := NewDecoder(), NewAggregator(MaxKeys)
	tick := time.NewTicker(c.Every)
	defer tick.Stop()
	done := make(chan struct{})
	var wg sync.WaitGroup
	// Al retornar no queda ningún OnSnapshot en curso: quien llama puede enviar el resumen final.
	defer wg.Wait()
	defer close(done)
	if c.OnSnapshot != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				case <-tick.C:
					c.OnSnapshot(agg.Snapshot(c.Top))
				}
			}
		}()
	}
	// Los lectores solo revisan los topes (por datagrama), deciden y encolan sin esperar; una gorutina aparte escribe.
	var written int64
	var p *ingest.Pipeline[batch]
	p = ingest.NewPipeline(ingest.PipelineConfig[batch]{Limits: c.Limits, Now: c.Now, Writer: w, Cancel: cancel, OnDrops: c.OnDrops,
		Handle: func(b batch) {
			for _, f := range b.flows {
				if c.Out != nil && written < MaxFile {
					j, _ := json.Marshal(f)
					m, _ := c.Out.Write(append(j, '\n'))
					written += int64(m)
				}
				p.Write(Record{b.at, f})
			}
		}})
	p.Start()
	err = readFlows(ctx, pc, dec, agg, c, p, w != nil || c.Out != nil)
	if sinkErr := p.Stop(); err == nil {
		err = sinkErr
	}
	return agg.Snapshot(c.Top), err
}

func readFlows(ctx context.Context, pc net.PacketConn, dec *Decoder, agg *Aggregator, c Config, p *ingest.Pipeline[batch], keep bool) error {
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("flows: %w", err)
		}
		// Sin dónde guardar no hay nada que proteger: el resumen en memoria ya está acotado, así que no se limita.
		key := ""
		if keep {
			var ok bool
			if key, ok = p.Admit(from.String()); !ok {
				continue
			}
		}
		fs, err := dec.Decode(from.String(), buf[:n])
		if err != nil {
			agg.Error(host(from.String()), err)
		}
		for _, f := range fs {
			agg.Add(f)
		}
		if keep && len(fs) > 0 {
			p.Enqueue(key, batch{p.Now(), fs})
		}
	}
}
