package transfer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

type ftpConn struct {
	tp   *textproto.Conn
	r    *Request
	host string
	stop func() bool
}

// lineCapConn corta la lectura si una línea pasa de maxCtlLine o el control de FTP de maxCtlTotal
// bytes (textproto no tiene tope: un servidor malicioso lo llenaría de memoria).
type lineCapConn struct {
	net.Conn
	run, total int
}

const maxCtlTotal = 1 << 20

func (c *lineCapConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	for _, b := range p[:n] {
		if b == '\n' {
			c.run = 0
		} else if c.run++; c.run > maxCtlLine {
			return 0, errLineTooLong // sin datos: bufio se tragaría el error si viniera con bytes
		}
	}
	if c.total += n; c.total > maxCtlTotal {
		return 0, errLineTooLong
	}
	return n, err
}

func cleanFTP(s string) error {
	if strings.ContainsAny(s, "\r\n\x00") {
		return i18n.New("xfer.err.ftp_text", nil)
	}
	return nil
}

// ftpLogin abre el control, entra (anónimo si no hay usuario) y pone TYPE I.
func (r *Request) ftpLogin(ctx context.Context) (*ftpConn, error) {
	for _, s := range []string{r.User, r.Pass} {
		if err := cleanFTP(s); err != nil {
			return nil, err
		}
	}
	port, _ := Port(r.URL)
	nc, err := r.Net.Dial(ctx, "tcp", r.URL.Hostname(), port)
	if err != nil {
		return nil, err
	}
	deadline(ctx, nc)
	c := &ftpConn{tp: textproto.NewConn(&lineCapConn{Conn: nc}), r: r, host: r.URL.Hostname(), stop: closeOnDone(ctx, nc)}
	fail := func(err error) (*ftpConn, error) { c.close(); return nil, err }
	if _, _, err := c.tp.ReadResponse(220); err != nil {
		return fail(err)
	}
	user, pass := r.User, r.Pass
	if user == "" {
		user, pass = "anonymous", "mctl@localhost"
	}
	code, _, err := c.cmd(331, 230, "USER %s", user)
	if err != nil {
		return fail(err)
	}
	if code == 331 {
		if _, _, err := c.cmd(230, 0, "PASS %s", pass); err != nil {
			return fail(i18n.New("xfer.err.ftp_creds", nil))
		}
	}
	if _, _, err := c.cmd(200, 0, "TYPE I"); err != nil {
		return fail(err)
	}
	return c, nil
}

func (c *ftpConn) close() {
	c.stop()
	c.tp.Close()
}

// cmd envía una orden y acepta el código a (o b si no es 0).
func (c *ftpConn) cmd(a, b int, format string, args ...any) (int, string, error) {
	if err := c.tp.PrintfLine(format, args...); err != nil {
		return 0, "", err
	}
	return c.resp(a, b)
}

// ftpReplyError es una respuesta del servidor que no era la esperada; Code deja decidir (p. ej. MLSD no soportado → LIST).
type ftpReplyError struct {
	Code  int
	msg   string
	cause error // el error con código del catálogo, si la respuesta no era la esperada
}

func (e *ftpReplyError) Error() string { return e.msg }

// Unwrap deja ver el error con código del catálogo (si lo hay) para darlo en otro idioma.
func (e *ftpReplyError) Unwrap() error { return e.cause }

func newUnexpected(code int, msg string, want int) *ftpReplyError {
	c := i18n.New("xfer.err.ftp_reply", i18n.A("code", code, "message", msg, "want", want))
	return &ftpReplyError{code, c.Error(), c}
}

func (c *ftpConn) resp(a, b int) (int, string, error) {
	code, msg, err := c.tp.ReadResponse(0)
	if err != nil {
		var pe *textproto.Error
		if errors.As(err, &pe) {
			return pe.Code, pe.Msg, &ftpReplyError{pe.Code, fmt.Sprintf("FTP %d %s", pe.Code, pe.Msg), nil}
		}
		return 0, "", err
	}
	if code != a && (b == 0 || code != b) {
		return code, msg, newUnexpected(code, msg, a)
	}
	return code, msg, nil
}

var epsvRe = regexp.MustCompile(`\|\|\|(\d+)\|`)
var pasvRe = regexp.MustCompile(`,(\d+),(\d+)\)`)

// data abre la conexión de datos pasiva. Se conecta siempre al host del control, no a la IP
// que anuncie el servidor (evita que un servidor nos mande a conectar a un tercero).
func (c *ftpConn) data(ctx context.Context) (net.Conn, error) {
	var port int
	if _, msg, err := c.cmd(229, 0, "EPSV"); err == nil {
		if m := epsvRe.FindStringSubmatch(msg); m != nil {
			port, _ = strconv.Atoi(m[1])
		}
	} else if _, msg, err := c.cmd(227, 0, "PASV"); err == nil {
		if m := pasvRe.FindStringSubmatch(msg); m != nil {
			a, _ := strconv.Atoi(m[1])
			b, _ := strconv.Atoi(m[2])
			port = a*256 + b
		}
	}
	if port <= 0 || port > 65535 {
		return nil, i18n.New("xfer.err.ftp_passive", nil)
	}
	dc, err := c.r.Net.Dial(ctx, "tcp", c.host, uint16(port))
	if err != nil {
		return nil, err
	}
	deadline(ctx, dc)
	return dc, nil
}

func (r *Request) ftpGet(ctx context.Context, w io.Writer) error {
	file, err := remotePath(r.URL)
	if err != nil {
		return err
	}
	c, err := r.ftpLogin(ctx)
	if err != nil {
		return err
	}
	defer c.close()
	if _, msg, err := c.cmd(213, 0, "SIZE %s", file); err == nil { // el tamaño es solo para el avance; si no lo da, no importa
		if n, perr := strconv.ParseInt(strings.TrimSpace(msg), 10, 64); perr == nil {
			r.track.setTotal(n)
		}
	}
	dc, err := c.data(ctx)
	if err != nil {
		return err
	}
	defer dc.Close()
	if _, _, err := c.cmd(150, 125, "RETR %s", file); err != nil {
		return err
	}
	if _, err := io.Copy(w, dc); err != nil {
		return err
	}
	dc.Close()
	_, _, err = c.resp(226, 250)
	return err
}

func (r *Request) ftpPut(ctx context.Context, rd io.Reader) error {
	file, err := remotePath(r.URL)
	if err != nil {
		return err
	}
	c, err := r.ftpLogin(ctx)
	if err != nil {
		return err
	}
	defer c.close()
	dc, err := c.data(ctx)
	if err != nil {
		return err
	}
	defer dc.Close()
	if _, _, err := c.cmd(150, 125, "STOR %s", file); err != nil {
		return err
	}
	if _, err := io.Copy(dc, rd); err != nil {
		return err
	}
	dc.Close()
	_, _, err = c.resp(226, 250)
	return err
}
