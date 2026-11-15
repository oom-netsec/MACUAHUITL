package syslogd

import (
	"bytes"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/ingest"
	"github.com/oom-netsec/MACUAHUITL/internal/mask"
)

// maskRaw enmascara un mensaje antes de parsearlo: lo parseado (texto, mnemónico) sale ya limpio. Un receptor no
// sabe de qué equipo viene el mensaje: la plataforma es la genérica (reglas de IOS) y «asa» solo si el mensaje trae
// un mnemónico %ASA/%FTD (ahí «snmp-server host IFNAME IP» tiene otra forma). No hay modo «sin enmascarar».
func maskRaw(raw []byte) []byte {
	platform := ""
	if bytes.Contains(raw, []byte("%ASA-")) || bytes.Contains(raw, []byte("%FTD-")) {
		platform = "asa"
	}
	out, _ := mask.Apply(platform, string(raw))
	// Línea por línea no basta: sanitize junta las líneas y la continuación de un comando citado («…command:key\nX»)
	// solo se reconoce unida; se vuelve a enmascarar con los saltos como espacios (lo ya tapado no cambia).
	if strings.ContainsAny(out, "\r\n") {
		out = strings.Join(strings.Fields(strings.NewReplacer("\r", " ", "\n", " ").Replace(out)), " ")
		out, _ = mask.Apply(platform, out)
	}
	return []byte(out)
}

// API que syslogd ha tenido siempre; el código vive en ingest y lo comparten
// los receptores de traps y flujos.
type (
	Limits      = ingest.Limits
	Sink        = ingest.Sink
	Drops       = ingest.Drops
	SourceDrops = ingest.SourceDrops
)

// ValidateTemplate valida la plantilla del nombre de archivo (ver ingest).
func ValidateTemplate(t string) error { return ingest.ValidateTemplate(t) }

type item struct {
	at        time.Time
	from      string
	raw       []byte
	truncated bool
}

// pipeline pone a syslog sobre ingest: los lectores encolan bytes crudos y el
// consumidor los parsea, los muestra, los guarda y los entrega.
type pipeline struct {
	*ingest.Pipeline[item]
}

func newPipeline(c Config, w *ingest.Writer, cancel func()) *pipeline {
	p := &pipeline{}
	p.Pipeline = ingest.NewPipeline(ingest.PipelineConfig[item]{
		Limits: c.Limits, Now: c.Now, Writer: w, Cancel: cancel, OnDrops: c.OnDrops, DropEvery: dropInterval,
		Handle: func(it item) {
			m := Parse(maskRaw(it.raw))
			m.Time, m.From, m.Truncated = it.at, it.from, it.truncated
			if c.Out != nil {
				c.Out.Write(m.Line("texto"))
			}
			p.Write(m)
			if c.OnMessage != nil {
				c.OnMessage(m)
			}
		},
	})
	return p
}

// submit lo llaman los lectores: nunca espera al escritor. raw se copia porque
// el lector UDP reutiliza su búfer.
func (p *pipeline) submit(from string, raw []byte, truncated bool) {
	if key, ok := p.Admit(from); ok {
		p.Enqueue(key, item{p.Now(), from, append([]byte(nil), raw...), truncated})
	}
}

// MaskRaw es el enmascarado que recibe cada mensaje antes de parsearlo; se expone para las pruebas de canales de mask.
func MaskRaw(raw []byte) []byte { return maskRaw(raw) }
