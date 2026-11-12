// Package crashinfo lee archivos crashinfo de texto de IOS e IOS-XE y saca de ellos el
// motivo de la falla, el proceso culpable, el traceback, la versión, el tiempo en línea
// previo y la CPU y la memoria si el archivo las trae. La entrada no es confiable: el
// texto se acota, las líneas se recortan y las expresiones son de Go (tiempo lineal).
// Los volcados binarios (core) solo se identifican. Formatos de la documentación pública
// de Cisco, sin validar en laboratorio. No toca la red ni el disco.
package crashinfo

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

const (
	// MaxBytes es lo más que se examina de un archivo; el resto se descarta y se avisa.
	MaxBytes = 4 << 20
	// MaxLine recorta cada línea antes de aplicarle expresiones.
	MaxLine       = 4096
	MaxTraceback  = 64
	MaxMnemonics  = 20
	maxLines      = 200000
	binarySniff   = 4096
	KindCrashinfo = "crashinfo"
	KindCore      = "core"
	KindUnknown   = "desconocido"
)

// ErrEmpty: no hay nada que leer.
var ErrEmpty error = i18n.New("crash.err.empty", nil)

type CPU struct {
	FiveSec float64 `json:"five_sec"`
	OneMin  float64 `json:"one_min"`
	FiveMin float64 `json:"five_min"`
}

type Mem struct {
	Total   int64   `json:"total"`
	Free    int64   `json:"free"`
	FreePct float64 `json:"free_pct"`
}

// Report es lo que se pudo leer; los campos vacíos son "el archivo no lo dice".
type Report struct {
	Kind      string   `json:"kind"`
	Binary    bool     `json:"binary"`
	Bytes     int      `json:"bytes"`
	Truncated bool     `json:"truncated,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	PC        string   `json:"pc,omitempty"`
	Process   string   `json:"process,omitempty"`
	PID       int      `json:"pid,omitempty"`
	Traceback []string `json:"traceback,omitempty"`
	Host      string   `json:"host,omitempty"`
	Model     string   `json:"model,omitempty"`
	Version   string   `json:"version,omitempty"`
	Uptime    string   `json:"uptime,omitempty"`
	CPU       *CPU     `json:"cpu,omitempty"`
	Memory    *Mem     `json:"memory,omitempty"`
	Mnemonics []string `json:"mnemonics,omitempty"`
	Hint      string   `json:"hint,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`

	// Los textos de catálogo de Hint y Warnings (en paralelo) para entregarlos en otro idioma; no viajan en el JSON.
	HintT i18n.Text   `json:"-"`
	WarnT []i18n.Text `json:"-"`
}

// Localize da el informe con Hint y Warnings en el idioma dado; con es devuelve el informe tal cual.
func (r Report) Localize(loc string) Report {
	if loc != i18n.En {
		return r
	}
	if !r.HintT.Empty() {
		r.Hint = r.HintT.In(loc)
	}
	r.Warnings = i18n.Notes(loc, r.Warnings, r.WarnT)
	return r
}

var (
	reasonROMRe  = regexp.MustCompile(`System returned to ROM by (.+)$`)
	reasonSigRe  = regexp.MustCompile(`\*\*\* System received an? (.+?) \*\*\*`)
	reasonVecRe  = regexp.MustCompile(`Unexpected exception to CPUvector (\d+)`)
	reasonXERe   = regexp.MustCompile(`^Last reload reason:\s*(.+)$`)
	reasonSoftRe = regexp.MustCompile(`Software-forced reload`)
	pcRe         = regexp.MustCompile(`\bPC (?:= )?(0x[0-9A-Fa-f]{1,16})`)
	procRe       = regexp.MustCompile(`-Process= "([^"]{1,64})", ipl= (\d+), pid= (\d+)`)
	procEqRe     = regexp.MustCompile(`^\s*Process = "([^"]{1,64})"`)
	procXERe     = regexp.MustCompile(`The process (\S{1,64}) has (?:failed|terminated)`)
	tracebackRe  = regexp.MustCompile(`-?Traceback=\s*(.*)$`)
	addrRe       = regexp.MustCompile(`^(?:0[xX])?([0-9A-Fa-f]{1,16})z?$`)
	mnemonicRe   = regexp.MustCompile(`%[A-Z0-9_]+-[0-7]-[A-Z0-9_]+`)
	uptimeRe     = regexp.MustCompile(`\buptime is (.+?)\s*$`)
	bannerRe     = regexp.MustCompile(`Software \(([A-Za-z0-9_]+)(?:-[^)]*)?\), Version`)
)

// Parse lee el texto de un crashinfo. Un volcado binario devuelve Kind "core" sin analizarlo;
// un texto que no parece crashinfo devuelve Kind "desconocido" con un aviso.
func Parse(text string) (Report, error) {
	r := Report{Kind: KindUnknown, Bytes: len(text)}
	if len(text) > MaxBytes {
		text, r.Truncated = text[:MaxBytes], true
		i18n.Note(&r.Warnings, &r.WarnT, "crash.warn.too_big")
	}
	if strings.TrimSpace(text) == "" {
		return r, ErrEmpty
	}
	if isBinary(text) {
		r.Kind, r.Binary = KindCore, true
		r.HintT = i18n.Tx("crash.hint.core")
		r.Hint = r.HintT.In(i18n.Es)
		return r, nil
	}
	if !utf8.ValidString(text) {
		text = strings.ToValidUTF8(text, "?")
	}
	ls := strings.Split(text, "\n")
	if len(ls) > maxLines {
		ls, r.Truncated = ls[:maxLines], true
		i18n.Note(&r.Warnings, &r.WarnT, "crash.warn.too_many")
	}
	seen := map[string]bool{}
	var cut []string
	for _, ln := range ls {
		ln = strings.TrimRight(ln, "\r")
		if len(ln) > MaxLine {
			ln = ln[:MaxLine]
		}
		cut = append(cut, ln)
		r.scan(ln, seen)
	}
	joined := strings.Join(cut, "\n")
	if v, _ := iosxe.ParseVersion(joined); v.Version != "" || v.Model != "" || v.Host != "" {
		r.Version, r.Model, r.Host = v.Version, v.Model, v.Host
		if m := bannerRe.FindStringSubmatch(joined); m != nil && r.Model == "" {
			r.Model = m[1]
		}
		if m := uptimeRe.FindStringSubmatch(v.UptimeLine); m != nil {
			r.Uptime = m[1]
		}
	}
	if c, ok := iosxe.ParseCPU(joined); ok {
		r.CPU = &CPU{c.FiveSec, c.OneMin, c.FiveMin}
	}
	if m, ok := iosxe.ParseMem(joined); ok {
		r.Memory = &Mem{Total: m.Total, Free: m.Free, FreePct: float64(m.Free) * 100 / float64(m.Total)}
	}
	if r.Reason != "" || r.Process != "" || len(r.Traceback) > 0 || r.Version != "" {
		r.Kind = KindCrashinfo
	} else {
		i18n.Note(&r.Warnings, &r.WarnT, "crash.warn.not_crash")
	}
	return r, nil
}

// scan toma de una línea lo que reconoce; el primer motivo y el primer proceso ganan.
func (r *Report) scan(ln string, seen map[string]bool) {
	if r.Reason == "" {
		switch {
		case reasonROMRe.MatchString(ln):
			r.Reason = strings.TrimSpace(reasonROMRe.FindStringSubmatch(ln)[1])
		case reasonXERe.MatchString(ln):
			r.Reason = strings.TrimSpace(reasonXERe.FindStringSubmatch(ln)[1])
		case reasonSigRe.MatchString(ln):
			r.Reason = reasonSigRe.FindStringSubmatch(ln)[1]
		case reasonSoftRe.MatchString(ln):
			r.Reason = "Software-forced reload"
		case reasonVecRe.MatchString(ln):
			r.Reason = "Unexpected exception to CPUvector " + reasonVecRe.FindStringSubmatch(ln)[1]
		}
	}
	if r.PC == "" {
		if m := pcRe.FindStringSubmatch(ln); m != nil {
			r.PC = "0x" + strings.ToUpper(m[1][2:])
		}
	}
	if r.Process == "" {
		if m := procRe.FindStringSubmatch(ln); m != nil {
			r.Process = m[1]
			r.PID, _ = strconv.Atoi(m[3])
		} else if m := procEqRe.FindStringSubmatch(ln); m != nil {
			r.Process = m[1]
		} else if m := procXERe.FindStringSubmatch(ln); m != nil {
			r.Process = m[1]
		}
	}
	if len(r.Traceback) == 0 {
		if m := tracebackRe.FindStringSubmatch(ln); m != nil {
			for _, tok := range strings.Fields(m[1]) {
				a := addrRe.FindStringSubmatch(tok)
				if a == nil {
					break
				}
				if len(r.Traceback) == MaxTraceback {
					break
				}
				r.Traceback = append(r.Traceback, "0x"+strings.ToUpper(a[1]))
			}
		}
	}
	if len(r.Mnemonics) < MaxMnemonics {
		if m := mnemonicRe.FindString(ln); m != "" && !seen[m] {
			seen[m] = true
			r.Mnemonics = append(r.Mnemonics, m)
		}
	}
}

// isBinary reconoce un volcado binario: firma ELF, bytes NUL o mucho carácter no imprimible
// en los primeros KiB.
func isBinary(s string) bool {
	head := s
	if len(head) > binarySniff {
		head = head[:binarySniff]
	}
	if strings.HasPrefix(head, "\x7fELF") || strings.IndexByte(head, 0) >= 0 {
		return true
	}
	bad := 0
	for i := 0; i < len(head); i++ {
		if c := head[i]; c < 0x09 || c > 0x0d && c < 0x20 || c >= 0x7f {
			bad++
		}
	}
	return bad*10 > len(head)*3
}

// Text arma el resumen legible del reporte en español.
func (r Report) Text() string { return r.TextIn(i18n.Es) }

// TextIn arma el resumen legible en el idioma dado (r ya viene en ese idioma: ver Localize).
func (r Report) TextIn(loc string) string {
	var b strings.Builder
	line := func(k, v string) {
		if v != "" {
			b.WriteString(i18n.Msg(loc, k, nil) + ": " + v + "\n")
		}
	}
	kind := r.Kind
	if kind == KindUnknown {
		kind = i18n.Msg(loc, "crash.kind.unknown", nil)
	}
	line("crash.label.type", kind)
	line("crash.label.notice", r.Hint)
	line("crash.label.reason", r.Reason)
	if r.PC != "" {
		b.WriteString("PC: " + r.PC + "\n")
	}
	if r.Process != "" {
		p := r.Process
		if r.PID > 0 {
			p += " (pid " + strconv.Itoa(r.PID) + ")"
		}
		line("crash.label.process", p)
	}
	line("crash.label.device", strings.TrimSpace(r.Host+" "+r.Model))
	line("crash.label.version", r.Version)
	line("crash.label.uptime", r.Uptime)
	if len(r.Traceback) > 0 {
		b.WriteString("Traceback: " + strings.Join(r.Traceback, " ") + "\n")
	}
	if r.CPU != nil {
		line("crash.label.cpu", strconv.FormatFloat(r.CPU.FiveSec, 'f', -1, 64)+"% (5 s), "+strconv.FormatFloat(r.CPU.OneMin, 'f', -1, 64)+"% (1 min), "+strconv.FormatFloat(r.CPU.FiveMin, 'f', -1, 64)+"% (5 min)")
	}
	if r.Memory != nil {
		line("crash.label.memory", i18n.Msg(loc, "crash.text.memory", i18n.A("pct", strconv.FormatFloat(r.Memory.FreePct, 'f', 1, 64), "free", r.Memory.Free, "total", r.Memory.Total)))
	}
	line("crash.label.messages", strings.Join(r.Mnemonics, ", "))
	for _, w := range r.Warnings {
		b.WriteString(i18n.Msg(loc, "crash.label.warning", nil) + ": " + w + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
