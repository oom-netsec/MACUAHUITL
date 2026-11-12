package serialcon

import (
	"bytes"
	"io"
	"sync"
	"time"
)

const stamp = "2006-01-02T15:04:05.000Z07:00"

// Recorder graba la sesión con la hora al inicio de cada línea. Solo se graba lo
// que devuelve el equipo (lo que se ve en pantalla), no lo tecleado: así una
// contraseña escrita en un prompt sin eco no queda en disco.
type Recorder struct {
	mu   sync.Mutex
	w    io.Writer
	now  func() time.Time
	midl bool // hay una línea abierta
}

func NewRecorder(w io.Writer, now func() time.Time) *Recorder {
	return &Recorder{w: w, now: now}
}

func (r *Recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b bytes.Buffer
	for _, c := range p {
		if c == '\r' { // el log se lee mejor sin retornos de carro
			continue
		}
		if !r.midl {
			b.WriteString(r.now().Format(stamp) + " ")
			r.midl = true
		}
		b.WriteByte(c)
		if c == '\n' {
			r.midl = false
		}
	}
	_, err := r.w.Write(b.Bytes())
	return len(p), err
}

// Mark anota un evento propio (apertura, BREAK, cierre) en una línea aparte.
func (r *Recorder) Mark(text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pre := ""
	if r.midl {
		pre = "\n"
	}
	io.WriteString(r.w, pre+r.now().Format(stamp)+" ### "+text+"\n")
	r.midl = false
}
