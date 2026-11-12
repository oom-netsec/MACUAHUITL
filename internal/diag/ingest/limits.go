// Package ingest es lo que comparten los receptores de eventos (syslog, traps SNMP
// y flujos): topes de tasa por origen y global, cola acotada que descarta y cuenta,
// y el archivo de salida con rotación, retención y formato.
package ingest

import (
	"net"
	"sort"
	"sync"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Defaults y rangos de los topes; 0 en Limits significa «el default».
const (
	defPerSource = 100
	defGlobal    = 1000
	defQueue     = 4096
	maxBurst     = 1_000_000
	maxSources   = 1024 // orígenes con cubo propio; los demás comparten «otros»
	maxDropKeys  = 4096 // orígenes distintos en la cuenta de descartes; el resto cuenta como «otros»
	idleSource   = 10 * time.Minute
	purgeEvery   = time.Minute // cada cuánto se busca qué cubos expiraron
	otros        = "otros"
)

// Motivos de descarte.
const (
	dropOrigen = "por_origen"
	dropGlobal = "global"
	dropCola   = "cola_llena"
)

// Limits acota lo que el receptor acepta: msg/s por origen y global (con su
// ráfaga) y el tamaño de la cola hacia el escritor.
type Limits struct {
	PerSource, PerSourceBurst int
	Global, GlobalBurst       int
	Queue                     int
}

// Effective rellena con los defaults los campos en 0 (ráfaga = 2x la tasa).
func (l Limits) Effective() Limits {
	if l.PerSource == 0 {
		l.PerSource = defPerSource
	}
	if l.Global == 0 {
		l.Global = defGlobal
	}
	if l.PerSourceBurst == 0 {
		l.PerSourceBurst = 2 * l.PerSource
	}
	if l.GlobalBurst == 0 {
		l.GlobalBurst = 2 * l.Global
	}
	if l.Queue == 0 {
		l.Queue = defQueue
	}
	return l
}

// Validate rechaza lo fuera de rango; 0 se acepta (default).
func (l Limits) Validate() error {
	for _, c := range []struct {
		field  string
		v      int
		lo, hi int
	}{
		{"rate_per_source", l.PerSource, 1, 10000},
		{"burst_per_source", l.PerSourceBurst, 1, maxBurst},
		{"rate_global", l.Global, 1, 100000},
		{"burst_global", l.GlobalBurst, 1, maxBurst},
		{"queue_size", l.Queue, 64, 65536},
	} {
		if c.v != 0 && (c.v < c.lo || c.v > c.hi) {
			return i18n.New("ingest.invalid."+c.field, i18n.A("min", c.lo, "max", c.hi, "value", c.v))
		}
	}
	return nil
}

// bucket es un token bucket: rate fichas por segundo hasta burst. El reloj
// llega por parámetro para que las pruebas lo controlen.
type bucket struct {
	rate, burst, tokens float64
	last                time.Time
}

func newBucket(rate, burst int, now time.Time) *bucket {
	return &bucket{rate: float64(rate), burst: float64(burst), tokens: float64(burst), last: now}
}

// give devuelve una ficha que no se llegó a usar.
func (b *bucket) give() { b.tokens++ }

func (b *bucket) take(now time.Time) bool {
	if d := now.Sub(b.last); d > 0 {
		b.tokens = min(b.burst, b.tokens+d.Seconds()*b.rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// limiter aplica primero el cubo del origen y luego el global, así un origen
// que inunda gasta solo su parte de la tasa global.
type limiter struct {
	mu     sync.Mutex
	l      Limits
	per    map[string]*bucket
	other  *bucket
	global *bucket
	purged time.Time
}

func newLimiter(l Limits, now time.Time) *limiter {
	return &limiter{l: l, purged: now, per: map[string]*bucket{}, other: newBucket(l.PerSource, l.PerSourceBurst, now), global: newBucket(l.Global, l.GlobalBurst, now)}
}

// allow devuelve la clave del origen contado y el motivo del descarte ("" si pasa).
func (lm *limiter) allow(ip string, now time.Time) (key, motivo string) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	key = ip
	b := lm.per[ip]
	if b == nil {
		if len(lm.per) >= maxSources {
			lm.expire(now)
		}
		if len(lm.per) >= maxSources {
			key, b = otros, lm.other
		} else {
			b = newBucket(lm.l.PerSource, lm.l.PerSourceBurst, now)
			lm.per[ip] = b
		}
	}
	if !b.take(now) {
		return key, dropOrigen
	}
	if !lm.global.take(now) {
		b.give() // el descarte global no debe gastar también la ficha del origen
		return key, dropGlobal
	}
	return key, ""
}

// expire suelta los cubos sin mensajes desde hace idleSource; con la tabla llena
// y UDP falsificado, la búsqueda se limita a una por purgeEvery.
func (lm *limiter) expire(now time.Time) {
	if now.Sub(lm.purged) < purgeEvery {
		return
	}
	lm.purged = now
	for ip, b := range lm.per {
		if now.Sub(b.last) >= idleSource {
			delete(lm.per, ip)
		}
	}
}

// SourceIP deja la IP sin puerto del "ip:puerto" que da la red.
func SourceIP(from string) string {
	if h, _, err := net.SplitHostPort(from); err == nil {
		return h
	}
	return from
}

// SourceDrops son los descartes de un origen.
type SourceDrops struct {
	Source string
	Count  uint64
}

// Drops es el acumulado de mensajes descartados desde que empezó la escucha.
type Drops struct {
	Total, PorOrigen, Global, ColaLlena uint64
	Desde                               time.Time     // primer descarte
	Top                                 []SourceDrops // hasta 10, el mayor primero
}

const topDrops = 10

type dropLog struct {
	mu  sync.Mutex
	d   Drops
	per map[string]uint64 // acotado por maxDropKeys+1
}

func newDropLog() *dropLog { return &dropLog{per: map[string]uint64{}} }

func (g *dropLog) add(motivo, key string, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.d.Total == 0 {
		g.d.Desde = now
	}
	g.d.Total++
	switch motivo {
	case dropOrigen:
		g.d.PorOrigen++
	case dropGlobal:
		g.d.Global++
	default:
		g.d.ColaLlena++
	}
	if _, ok := g.per[key]; !ok && len(g.per) >= maxDropKeys {
		key = otros
	}
	g.per[key]++
}

func (g *dropLog) snapshot() Drops {
	g.mu.Lock()
	defer g.mu.Unlock()
	d := g.d
	for k, n := range g.per {
		d.Top = append(d.Top, SourceDrops{k, n})
	}
	sort.Slice(d.Top, func(i, j int) bool {
		if d.Top[i].Count != d.Top[j].Count {
			return d.Top[i].Count > d.Top[j].Count
		}
		return d.Top[i].Source < d.Top[j].Source
	})
	if len(d.Top) > topDrops {
		d.Top = d.Top[:topDrops]
	}
	return d
}
