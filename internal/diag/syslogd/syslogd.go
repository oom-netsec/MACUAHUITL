// Package syslogd es un receptor syslog para laboratorio y diagnóstico: escucha
// UDP o TCP (RFC 6587, por salto de línea o por conteo de octetos), entiende
// RFC 3164, RFC 5424 y el mnemónico de Cisco (%FAC-SEV-MNEM) y nunca se cae por
// un mensaje enorme o binario.
package syslogd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/ingest"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// MaxMessage es el tamaño máximo que se conserva de cada mensaje; el resto se descarta.
const MaxMessage = 8192

const maxConns = 64

// maxPerSource es el tope de conexiones TCP simultáneas por IP de origen: un equipo usa una; un host no acapara las 64.
// Sin cierre por inactividad: un IOS callado perdería el primer mensaje al reconectar; las muertas las corta el keepalive TCP.
const maxPerSource = 4

type Message struct {
	Time      time.Time
	From      string
	Format    string // cisco, rfc5424, rfc3164 o desconocido
	Facility  int    // -1 si no trae PRI
	Severity  int    // -1 si no trae PRI
	Host      string `json:",omitempty"`
	App       string `json:",omitempty"`
	Mnemonic  string `json:",omitempty"`
	Text      string
	Raw       string
	Truncated bool `json:",omitempty"`
}

// Origin y Line hacen de Message un ingest.Record: el origen es «ip:puerto» y la
// línea (con salto final) sale en texto, crudo o jsonl.
func (m Message) Origin() string { return m.From }

func (m Message) Line(format string) []byte {
	switch format {
	case "crudo":
		return []byte(m.Raw + "\n")
	case "jsonl":
		b, _ := json.Marshal(m)
		return append(b, '\n')
	}
	return []byte(m.Time.Format(time.RFC3339) + " " + m.From + " " + m.Raw + "\n")
}

type Config struct {
	Addr        string // host:puerto; el host es obligatorio
	Proto       string // udp o tcp
	AllowAny    bool   // permite 0.0.0.0 / :: (escuchar en todas las interfaces)
	Out         io.Writer
	Sink        *Sink            // archivo con rotación y retención; nil = sin archivo
	Limits      Limits           // topes de tasa y cola; 0 = default
	Now         func() time.Time // reloj de cubos, hora de los mensajes y rotación; nil = time.Now
	OnMessage   func(Message)    // siempre desde la misma gorutina
	OnDrops     func(Drops)      // acumulado; a lo más una vez por dropInterval y solo si cambió, más una al cerrar
	OnListening func(addr string)
}

// dropInterval es cada cuánto se reportan los descartes.
var dropInterval = time.Second

// ValidateAddr exige un host explícito, puerto no privilegiado y, salvo que se
// pida, nada de escuchar en todas las interfaces.
func ValidateAddr(addr string, allowAny bool) error {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return i18n.New("ingest.invalid.addr.parse", i18n.A("addr", addr, "detail", err))
	}
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return i18n.New("ingest.invalid.addr.port", i18n.A("port", p))
	}
	if port != 0 && port < 1024 {
		return i18n.New("ingest.invalid.addr.privileged", i18n.A("port", port))
	}
	ip, err := netip.ParseAddr(h)
	if err != nil {
		return i18n.New("ingest.invalid.addr.host", i18n.A("host", h))
	}
	if ip.IsUnspecified() && !allowAny {
		return i18n.New("ingest.invalid.addr.any", nil)
	}
	return nil
}

// Listen recibe hasta que ctx se cancela. Los lectores (UDP o cada conexión TCP)
// solo revisan los topes y encolan sin esperar; una gorutina aparte parsea,
// escribe y llama a OnMessage.
func Listen(ctx context.Context, c Config) error {
	if c.Addr == "" {
		c.Addr = "127.0.0.1:5514"
	}
	if err := ValidateAddr(c.Addr, c.AllowAny); err != nil {
		return err
	}
	if c.Proto != "" && c.Proto != "udp" && c.Proto != "tcp" {
		return i18n.New("ingest.invalid.protocol", i18n.A("value", c.Proto))
	}
	if err := c.Limits.Validate(); err != nil {
		return err
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	var w *ingest.Writer
	if c.Sink != nil {
		if err := c.Sink.Validate(); err != nil {
			return err
		}
		var err error
		if w, err = ingest.NewWriter(*c.Sink, c.Now); err != nil {
			return err
		}
		defer w.Close()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	p := newPipeline(c, w, cancel)
	p.Start()
	var err error
	if c.Proto == "tcp" {
		err = listenTCP(ctx, c, p.submit)
	} else {
		err = listenUDP(ctx, c, p.submit)
	}
	if sinkErr := p.Stop(); err == nil {
		err = sinkErr
	}
	return err
}

type emitFunc func(from string, raw []byte, truncated bool)

func listenUDP(ctx context.Context, c Config, emit emitFunc) error {
	pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", c.Addr)
	if err != nil {
		return fmt.Errorf("syslogd: %w", err)
	}
	defer pc.Close()
	stop := context.AfterFunc(ctx, func() { pc.Close() })
	defer stop()
	if c.OnListening != nil {
		c.OnListening(pc.LocalAddr().String())
	}
	buf := make([]byte, 65536)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("syslogd: %w", err)
		}
		emit(from.String(), buf[:min(n, MaxMessage)], n > MaxMessage)
	}
}

func listenTCP(ctx context.Context, c Config, emit emitFunc) error {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", c.Addr)
	if err != nil {
		return fmt.Errorf("syslogd: %w", err)
	}
	defer ln.Close()
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	if c.OnListening != nil {
		c.OnListening(ln.Addr().String())
	}
	sem := make(chan struct{}, maxConns)
	var mu sync.Mutex
	perSource := map[string]int{}
	release := func(src string) {
		mu.Lock()
		if perSource[src]--; perSource[src] <= 0 {
			delete(perSource, src)
		}
		mu.Unlock()
		<-sem
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("syslogd: %w", err)
		}
		select {
		case sem <- struct{}{}:
		default:
			conn.Close() // demasiadas conexiones; se rechaza en vez de agotar recursos
			continue
		}
		src, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		mu.Lock()
		perSource[src]++
		full := perSource[src] > maxPerSource
		mu.Unlock()
		if full {
			release(src)
			conn.Close() // un solo origen no acapara el receptor
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer release(src)
			defer conn.Close()
			stopConn := context.AfterFunc(ctx, func() { conn.Close() })
			defer stopConn()
			readStream(bufio.NewReaderSize(conn, MaxMessage+16), conn.RemoteAddr().String(), emit)
		}()
	}
}

// readStream separa mensajes por conteo de octetos ("<len> <msg>") o por salto de línea.
func readStream(r *bufio.Reader, from string, emit emitFunc) {
	for {
		b, err := r.Peek(1)
		if err != nil {
			return
		}
		if b[0] >= '1' && b[0] <= '9' {
			if n, ok := octetCount(r); ok {
				keep := min(n, MaxMessage)
				msg := make([]byte, keep)
				if _, err := io.ReadFull(r, msg); err != nil {
					return
				}
				if _, err := r.Discard(n - keep); err != nil {
					return
				}
				emit(from, msg, n > keep)
				continue
			}
		}
		line, err := r.ReadSlice('\n')
		truncated := false
		if errors.Is(err, bufio.ErrBufferFull) {
			line, truncated = append([]byte(nil), line[:MaxMessage]...), true
			for errors.Is(err, bufio.ErrBufferFull) { // descarta hasta el fin de línea
				_, err = r.ReadSlice('\n')
			}
		}
		if msg := strings.TrimRight(string(line), "\r\n"); msg != "" {
			emit(from, []byte(msg), truncated)
		}
		if err != nil {
			return
		}
	}
}

// octetCount lee "<dígitos><espacio>" si el flujo empieza así; si no, no consume nada.
func octetCount(r *bufio.Reader) (int, bool) {
	head, _ := r.Peek(8)
	i := 0
	for i < len(head) && head[i] >= '0' && head[i] <= '9' {
		i++
	}
	if i == 0 || i >= len(head) || head[i] != ' ' {
		return 0, false
	}
	n, err := strconv.Atoi(string(head[:i]))
	if err != nil || n > 1<<20 {
		return 0, false
	}
	r.Discard(i + 1)
	return n, true
}

var (
	ciscoMnem = regexp.MustCompile(`%([A-Z0-9_]+(?:-[A-Z0-9_]+)*-[0-7]-[A-Z0-9_]+)`)
	months    = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec"
)

// sanitize deja solo UTF-8 válido y sin caracteres de control (evita inyectar
// secuencias de terminal en la salida).
func sanitize(b []byte) string {
	s := strings.ToValidUTF8(string(b), "?")
	return strings.Map(func(r rune) rune {
		if r == utf8.RuneError || r < 0x20 && r != '\t' || r == 0x7f {
			return '.'
		}
		return r
	}, s)
}

// Parse interpreta un mensaje syslog crudo.
func Parse(raw []byte) Message {
	s := sanitize(raw)
	m := Message{Raw: s, Format: "desconocido", Facility: -1, Severity: -1, Text: s}
	rest := s
	if strings.HasPrefix(s, "<") {
		if end := strings.IndexByte(s, '>'); end > 1 && end <= 4 {
			if pri, err := strconv.Atoi(s[1:end]); err == nil && pri <= 191 {
				m.Facility, m.Severity = pri/8, pri%8
				rest = s[end+1:]
				m.Text = rest
			}
		}
	}
	if m.Facility < 0 {
		return m
	}
	switch {
	case strings.HasPrefix(rest, "1 "):
		parse5424(&m, rest[2:])
	case len(rest) >= 16 && strings.Contains(months, rest[:3]) && rest[3] == ' ' && rest[15] == ' ':
		m.Format = "rfc3164"
		f := strings.SplitN(rest[16:], " ", 2)
		m.Host = f[0]
		if len(f) == 2 {
			m.Text = f[1]
			if i := strings.IndexAny(f[1], ":["); i > 0 && !strings.Contains(f[1][:i], " ") {
				m.App = f[1][:i]
			}
		}
	}
	if mm := ciscoMnem.FindStringSubmatchIndex(rest); mm != nil {
		m.Mnemonic = rest[mm[2]:mm[3]]
		if m.Format == "desconocido" {
			m.Format = "cisco"
		}
		m.Text = strings.TrimLeft(rest[mm[1]:], ": ")
	}
	return m
}

// parse5424: TIMESTAMP HOST APP PROCID MSGID SD MSG
func parse5424(m *Message, s string) {
	f := strings.SplitN(s, " ", 6)
	if len(f) < 6 {
		return
	}
	m.Format = "rfc5424"
	nil0 := func(v string) string {
		if v == "-" {
			return ""
		}
		return v
	}
	m.Host, m.App = nil0(f[1]), nil0(f[2])
	msg := f[5]
	if strings.HasPrefix(msg, "[") {
		msg = skipSD(msg)
	} else if strings.HasPrefix(msg, "-") {
		msg = msg[1:]
	}
	m.Text = strings.TrimPrefix(strings.TrimLeft(msg, " "), "\uFEFF")
}

// skipSD salta los elementos de datos estructurados "[id k=\"v\"]..." respetando escapes.
func skipSD(s string) string {
	depth, esc := 0, false
	for i, r := range s {
		switch {
		case esc:
			esc = false
		case r == '\\':
			esc = true
		case r == '[':
			depth++
		case r == ']':
			depth--
			if depth == 0 && (i+1 == len(s) || s[i+1] != '[') {
				return s[i+1:]
			}
		}
	}
	return ""
}
