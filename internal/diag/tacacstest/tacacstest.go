// Package tacacstest prueba un servidor TACACS+ (RFC 8907) como lo haría un
// equipo Cisco: autenticación ASCII o PAP, autorización de un comando y
// accounting Start/Stop, con el cuerpo ofuscado por el secreto compartido.
// Implementación propia con la biblioteca estándar.
//
// No hace: CHAP/MS-CHAP, single-connect ni TLS (draft TACACS+ sobre TLS);
// nunca muestra el secreto ni la contraseña.
package tacacstest

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

type Dialer func(ctx context.Context, network, host string, port uint16) (net.Conn, error)

// Config describe la prueba. Secret y Password son del llamador, que los borra.
type Config struct {
	Host       string
	Port       uint16 // 49 por defecto
	Secret     []byte
	Username   string
	Password   []byte
	AuthenType string // ascii (por defecto) o pap
	PrivLvl    int    // 1 por defecto
	Command    string // vacío = sin autorización de comando
	Accounting bool
	NASPort    string // "tty1" por defecto
	RemAddr    string
	Timeout    time.Duration
}

type Step struct {
	Kind      string   // authentication, authorization, accounting-start, accounting-stop
	Status    string   `json:",omitempty"`
	ServerMsg string   `json:",omitempty"`
	Data      string   `json:",omitempty"`
	Prompts   []string `json:",omitempty"` // lo que pidió el servidor en ASCII
	Sent      []string `json:",omitempty"` // AV pairs enviados
	AVPairs   []string `json:",omitempty"` // AV pairs devueltos
	RTTMillis float64
	Error     string `json:",omitempty"`
	// ErrText es Error como texto de catálogo (para darlo en otro idioma); no viaja en el JSON.
	ErrText i18n.Text `json:"-"`
}

// problem es un error de un paso con su texto de catálogo; Error() es el texto en español.
type problem struct{ t i18n.Text }

func (p problem) Error() string { return p.t.In(i18n.Es) }

func prob(key string, kv ...any) error { return problem{i18n.Tx(key, kv...)} }

// fail registra el error del paso: uno propio (problem) conserva su código; cualquier otro es un texto del sistema.
func (s *Step) fail(err error) {
	var p problem
	if !errors.As(err, &p) {
		p = problem{i18n.Tx("security.tacacs.err.system", "error", err.Error())}
	}
	s.ErrText, s.Error = p.t, p.Error()
}

// Finding es un hallazgo. Severity es aviso, error o info en el JSON y el texto en español de siempre.
type Finding struct {
	Severity, Code, Detail string
	Text                   i18n.Text `json:"-"` // Detail como texto de catálogo
	Err                    i18n.Text `json:"-"` // el error del paso que Detail cita, si lo cita
}

// ArgsIn son los argumentos del hallazgo; el error citado va en el idioma pedido.
func (f Finding) ArgsIn(loc string) i18n.Args {
	a := i18n.Args{}
	for k, v := range f.Text.Args {
		a[k] = v
	}
	if !f.Err.Empty() {
		a["error"] = f.Err.In(loc)
	}
	return a
}

// DetailIn es el detalle en el idioma pedido.
func (f Finding) DetailIn(loc string) string { return i18n.Msg(loc, f.Text.Key, f.ArgsIn(loc)) }

type Report struct {
	Server   string
	Steps    []Step
	Findings []Finding
}

var (
	authenStatus = map[byte]string{1: "PASS", 2: "FAIL", 3: "GETDATA", 4: "GETUSER", 5: "GETPASS", 6: "RESTART", 7: "ERROR", 0x21: "FOLLOW"}
	authorStatus = map[byte]string{1: "PASS_ADD", 2: "PASS_REPL", 0x10: "FAIL", 0x11: "ERROR", 0x21: "FOLLOW"}
	acctStatus   = map[byte]string{1: "SUCCESS", 2: "ERROR", 0x21: "FOLLOW"}
)

const (
	authenASCII   = 1
	authenPAP     = 2
	serviceLogin  = 1
	methodTACACS  = 6
	acctFlagStart = 0x02
	acctFlagStop  = 0x04
)

// commandArgs arma los AV pairs que manda IOS al autorizar un comando (RFC 8907 §8.2).
func commandArgs(cmd string) []string {
	f := strings.Fields(cmd)
	out := []string{"service=shell"}
	if len(f) == 0 {
		return out
	}
	out = append(out, "cmd="+f[0])
	for _, a := range f[1:] {
		out = append(out, "cmd-arg="+a)
	}
	return append(out, "cmd-arg=<cr>")
}

// acctCmd es el AV pair cmd= que IOS manda en el accounting de comandos.
func acctCmd(cmd string) string { return "cmd=" + cmd + " <cr>" }

func status(m map[byte]string, s byte) string {
	if v, ok := m[s]; ok {
		return v
	}
	return fmt.Sprintf("0x%02x", s)
}

func Run(ctx context.Context, d Dialer, c Config) (Report, error) {
	if strings.TrimSpace(c.Host) == "" || strings.HasPrefix(c.Host, "-") {
		return Report{}, errors.New("tacacs: servidor inválido")
	}
	if len(c.Secret) == 0 {
		return Report{}, errors.New("tacacs: falta el secreto compartido (sin él el tráfico viaja en claro)")
	}
	if c.Username == "" || len(c.Username) > 255 || len(c.Password) > 255 || len(c.NASPort) > 255 || len(c.RemAddr) > 255 {
		return Report{}, errors.New("tacacs: usuario vacío o campos de más de 255 bytes")
	}
	if c.AuthenType == "" {
		c.AuthenType = "ascii"
	}
	if c.AuthenType != "ascii" && c.AuthenType != "pap" {
		return Report{}, fmt.Errorf("tacacs: tipo de autenticación %q no soportado (ascii, pap)", c.AuthenType)
	}
	for _, a := range append(commandArgs(c.Command), acctCmd(c.Command)) {
		if len(a) > 255 { // RFC 8907: cada AV pair lleva su longitud en un byte
			return Report{}, fmt.Errorf("tacacs: el AV pair %.20q… mide %d bytes; el máximo es 255 (acorta el comando)", a, len(a))
		}
	}
	if c.Port == 0 {
		c.Port = 49
	}
	if c.PrivLvl <= 0 || c.PrivLvl > 15 {
		c.PrivLvl = 1
	}
	if c.NASPort == "" {
		c.NASPort = "tty1"
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	r := Report{Server: net.JoinHostPort(c.Host, strconv.Itoa(int(c.Port)))}
	r.Steps = append(r.Steps, authenticate(ctx, d, c))
	if c.Command != "" {
		r.Steps = append(r.Steps, authorize(ctx, d, c))
	}
	if c.Accounting {
		r.Steps = append(r.Steps, account(ctx, d, c, acctFlagStart), account(ctx, d, c, acctFlagStop))
	}
	r.findings()
	return r, nil
}

// session abre una conexión por paso (sin single-connect) y lleva la secuencia.
type session struct {
	c     Config
	conn  net.Conn
	h     header
	start time.Time
}

func open(ctx context.Context, d Dialer, c Config, typ, minor byte) (*session, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	conn, err := d(ctx, "tcp", c.Host, c.Port)
	if err != nil {
		return nil, err
	}
	var id [4]byte
	rand.Read(id[:])
	conn.SetDeadline(time.Now().Add(c.Timeout))
	return &session{c: c, conn: conn, h: header{Version: 0xc0 | minor, Type: typ, Session: binary.BigEndian.Uint32(id[:])}}, nil
}

// roundTrip manda body y valida que la respuesta sea de esta sesión y la secuencia siguiente.
func (s *session) roundTrip(body []byte) ([]byte, error) {
	s.h.Seq++
	s.start = time.Now()
	if err := writePacket(s.conn, s.h, s.c.Secret, body); err != nil {
		return nil, err
	}
	h, resp, err := readPacket(s.conn, s.c.Secret)
	if err != nil {
		if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "reset") {
			return nil, prob("security.tacacs.err.closed")
		}
		return nil, err
	}
	if h.Session != s.h.Session || h.Type != s.h.Type || h.Seq != s.h.Seq+1 {
		return nil, prob("security.tacacs.err.out_of_sequence", "session", fmt.Sprintf("%08x", h.Session), "type", h.Type, "seq", h.Seq)
	}
	if h.Flags&flagUnencrypted != 0 {
		return nil, prob("security.tacacs.err.unencrypted")
	}
	s.h.Seq++
	return resp, nil
}

func (s *session) rtt() float64 { return float64(time.Since(s.start).Microseconds()) / 1000 }

const badSecretKey = "security.tacacs.err.bad_secret"

func authenticate(ctx context.Context, d Dialer, c Config) Step {
	st := Step{Kind: "authentication"}
	typ, minor, data := byte(authenASCII), byte(0), []byte(nil)
	if c.AuthenType == "pap" {
		typ, minor, data = authenPAP, 1, c.Password // RFC 8907 §5.4.2: PAP usa la versión menor 1
	}
	s, err := open(ctx, d, c, typeAuthen, minor)
	if err != nil {
		st.fail(err)
		return st
	}
	defer s.conn.Close()
	body := []byte{1, byte(c.PrivLvl), typ, serviceLogin, byte(len(c.Username)), byte(len(c.NASPort)), byte(len(c.RemAddr)), byte(len(data))}
	body = append(append(append(append(body, c.Username...), c.NASPort...), c.RemAddr...), data...)
	defer clear(body)
	for range 5 { // GETUSER/GETPASS/GETDATA acotados
		raw, err := s.roundTrip(body)
		if err != nil {
			st.fail(err)
			return st
		}
		rep, err := parseAuthenReply(raw)
		if err != nil {
			st.fail(prob(badSecretKey))
			return st
		}
		st.RTTMillis += s.rtt()
		st.Status, st.ServerMsg, st.Data = status(authenStatus, rep.Status), rep.ServerMsg, printable(rep.Data)
		var answer []byte
		switch rep.Status {
		case 4: // GETUSER
			answer = []byte(c.Username)
		case 5, 3: // GETPASS, GETDATA
			answer = c.Password
		default:
			return st
		}
		st.Prompts = append(st.Prompts, strings.TrimSpace(rep.ServerMsg))
		clear(body)
		body = binary.BigEndian.AppendUint16(nil, uint16(len(answer)))
		body = append(append(binary.BigEndian.AppendUint16(body, 0), 0), answer...) // CONTINUE: user_msg, data vacío, flags
	}
	st.fail(prob("security.tacacs.err.too_many_prompts"))
	return st
}

func authorize(ctx context.Context, d Dialer, c Config) Step {
	st := Step{Kind: "authorization", Sent: commandArgs(c.Command)}
	s, err := open(ctx, d, c, typeAuthor, 0)
	if err != nil {
		st.fail(err)
		return st
	}
	defer s.conn.Close()
	typ := byte(authenASCII)
	if c.AuthenType == "pap" {
		typ = authenPAP
	}
	raw, err := s.roundTrip(requestBody([]byte{methodTACACS, byte(c.PrivLvl), typ, serviceLogin}, c.Username, c.NASPort, c.RemAddr, st.Sent))
	if err != nil {
		st.fail(err)
		return st
	}
	rep, err := parseAuthorResponse(raw)
	if err != nil {
		st.fail(prob(badSecretKey))
		return st
	}
	st.RTTMillis = s.rtt()
	st.Status, st.ServerMsg, st.Data, st.AVPairs = status(authorStatus, rep.Status), rep.ServerMsg, printable(rep.Data), rep.Args
	return st
}

var taskSeq atomic.Int64

func account(ctx context.Context, d Dialer, c Config, flag byte) Step {
	st := Step{Kind: map[byte]string{acctFlagStart: "accounting-start", acctFlagStop: "accounting-stop"}[flag]}
	now := time.Now().Unix()
	st.Sent = []string{"task_id=" + strconv.FormatInt(taskSeq.Add(1), 10), "timezone=UTC", "service=shell"}
	if flag == acctFlagStart {
		st.Sent = append(st.Sent, "start_time="+strconv.FormatInt(now, 10))
	} else {
		st.Sent = append(st.Sent, "stop_time="+strconv.FormatInt(now, 10), "elapsed_time=1")
	}
	if c.Command != "" {
		st.Sent = append(st.Sent, "priv-lvl="+strconv.Itoa(c.PrivLvl), acctCmd(c.Command))
	}
	s, err := open(ctx, d, c, typeAcct, 0)
	if err != nil {
		st.fail(err)
		return st
	}
	defer s.conn.Close()
	raw, err := s.roundTrip(requestBody([]byte{flag, methodTACACS, byte(c.PrivLvl), authenASCII, serviceLogin}, c.Username, c.NASPort, c.RemAddr, st.Sent))
	if err != nil {
		st.fail(err)
		return st
	}
	rep, err := parseAcctReply(raw)
	if err != nil {
		st.fail(prob(badSecretKey))
		return st
	}
	st.RTTMillis = s.rtt()
	st.Status, st.ServerMsg, st.Data = status(acctStatus, rep.Status), rep.ServerMsg, printable(rep.Data)
	return st
}

func printable(s string) string {
	for _, r := range s {
		if r < 0x20 && r != '\n' && r != '\t' {
			return fmt.Sprintf("0x%x", s)
		}
	}
	return s
}

func (r *Report) findings() {
	add := func(sev, code string, t, errT i18n.Text) {
		f := Finding{Severity: sev, Code: code, Text: t, Err: errT}
		f.Detail = f.DetailIn(i18n.Es)
		r.Findings = append(r.Findings, f)
	}
	for _, s := range r.Steps {
		switch {
		case s.ErrText.Key == badSecretKey:
			add("error", "secret", i18n.Tx("security.tacacs.finding.secret", "kind", s.Kind), i18n.Text{})
		case s.Error != "":
			add("error", "no_response", i18n.Tx("security.tacacs.finding.no_response", "kind", s.Kind, "port", strings.TrimPrefix(r.Server[strings.LastIndex(r.Server, ":"):], ":")), s.ErrText)
		case s.Status == "FAIL" && s.Kind == "authentication":
			add("info", "authen_fail", i18n.Tx("security.tacacs.finding.authen_fail"), i18n.Text{})
		case s.Status == "FAIL" && s.Kind == "authorization":
			add("info", "author_fail", i18n.Tx("security.tacacs.finding.author_fail"), i18n.Text{})
		case s.Status == "ERROR" || s.Status == "FOLLOW":
			add("aviso", "status", i18n.Tx("security.tacacs.finding.state", "kind", s.Kind, "status", s.Status, "message", s.ServerMsg), i18n.Text{})
		}
	}
}

// SeverityCode es la severidad como código cerrado en inglés: warning, error o info.
func SeverityCode(sev string) string {
	if sev == "aviso" {
		return "warning"
	}
	return sev
}

// Text es el resumen legible en español.
func (r Report) Text() string { return r.TextIn(i18n.Es) }

// TextIn es el resumen legible en el idioma pedido. Los valores (servidor, estados, mensajes del servidor, AV
// pairs) salen tal cual; con es es el texto de siempre.
func (r Report) TextIn(loc string) string {
	var b strings.Builder
	b.WriteString(i18n.Msg(loc, "security.tacacs.text.server", i18n.A("server", r.Server)) + "\n")
	for _, s := range r.Steps {
		fmt.Fprintf(&b, "\n%s: ", s.Kind)
		if s.Status != "" {
			b.WriteString(i18n.Msg(loc, "security.tacacs.text.status", i18n.A("status", s.Status, "rtt", fmt.Sprintf("%.1f", s.RTTMillis))) + "\n")
		} else {
			b.WriteString(i18n.Msg(loc, "security.tacacs.text.no_response", nil) + "\n")
		}
		if s.Error != "" {
			msg := s.Error
			if !s.ErrText.Empty() {
				msg = s.ErrText.In(loc)
			}
			fmt.Fprintf(&b, "  ! %s\n", msg)
		}
		for _, p := range s.Prompts {
			b.WriteString("  " + i18n.Msg(loc, "security.tacacs.text.prompt", i18n.A("prompt", p)) + "\n")
		}
		if s.ServerMsg != "" {
			b.WriteString("  " + i18n.Msg(loc, "security.tacacs.text.message", i18n.A("message", s.ServerMsg)) + "\n")
		}
		if s.Data != "" {
			b.WriteString("  " + i18n.Msg(loc, "security.tacacs.text.data", i18n.A("data", s.Data)) + "\n")
		}
		for _, a := range s.Sent {
			b.WriteString("  " + i18n.Msg(loc, "security.tacacs.text.sent", i18n.A("pair", a)) + "\n")
		}
		for _, a := range s.AVPairs {
			b.WriteString("  " + i18n.Msg(loc, "security.tacacs.text.received", i18n.A("pair", a)) + "\n")
		}
	}
	if len(r.Findings) > 0 {
		b.WriteString("\n" + i18n.Msg(loc, "security.findings_head", nil) + "\n")
		for _, f := range r.Findings {
			detail := f.Detail
			if !f.Text.Empty() {
				detail = f.DetailIn(loc)
			}
			fmt.Fprintf(&b, "  [%s] %s\n", i18n.Msg(loc, "security.severity."+SeverityCode(f.Severity), nil), detail)
		}
	}
	return b.String()
}
