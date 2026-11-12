package fileserve

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// FTP pasivo mínimo (RFC 959 con EPSV de RFC 2428). Solo: USER/PASS, TYPE, PASV/EPSV,
// RETR, STOR, SIZE, PWD, CWD /, LIST/NLST (de lo publicado), QUIT y unas pocas de cortesía.
// No hay modo activo (PORT/EPRT: es el rebote de FTP), ni borrar, renombrar ni crear carpetas.

const (
	maxFTPLine   = 512
	ftpPassive   = 32 // puertos pasivos por omisión: de Addr+1 a Addr+32
	dataAccept   = 30 * time.Second
	dataIdle     = 30 * time.Second
	ftpLoginFail = 3
)

// parseFTP separa la orden (en mayúsculas) de su argumento. Rechaza líneas con NUL u otros
// caracteres de control, y órdenes que no sean de 3 o 4 letras.
func parseFTP(line string) (cmd, arg string, err error) {
	line = strings.TrimRight(line, "\r\n")
	if len(line) > maxFTPLine {
		return "", "", i18n.New("fileserve.reason.line_long", nil)
	}
	for _, r := range line {
		if r < 0x20 || r == 0x7f {
			return "", "", i18n.New("fileserve.reason.control_chars", nil)
		}
	}
	cmd, arg, _ = strings.Cut(line, " ")
	cmd = strings.ToUpper(cmd)
	if len(cmd) < 3 || len(cmd) > 4 {
		return "", "", i18n.New("fileserve.reason.bad_command", nil)
	}
	for _, r := range cmd {
		if r < 'A' || r > 'Z' {
			return "", "", i18n.New("fileserve.reason.bad_command", nil)
		}
	}
	return cmd, strings.TrimLeft(arg, " "), nil
}

// readFTPLine lee una línea terminada en \n con tope de longitud.
func readFTPLine(br *bufio.Reader) (string, error) {
	var b []byte
	for len(b) <= maxFTPLine+2 {
		c, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if c == '\n' {
			return string(b), nil
		}
		b = append(b, c)
	}
	return "", i18n.New("fileserve.reason.line_long", nil)
}

func serveFTP(ctx context.Context, c Config, src *source, rcv *receiver) error {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", c.Addr)
	if err != nil {
		return fmt.Errorf("fileserve: %w", err)
	}
	defer ln.Close()
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	lo, hi := c.PassivePorts[0], c.PassivePorts[1]
	if lo == 0 && hi == 0 {
		if p := ln.Addr().(*net.TCPAddr).Port; p > 0 && p+ftpPassive < 65536 {
			lo, hi = uint16(p+1), uint16(p+ftpPassive)
		}
	}
	lim := newLimiter()
	c.ready(Ready{Addr: ln.Addr().String(), User: c.User, Pass: c.Pass})
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("fileserve: %w", err)
		}
		ip := hostOf(nc.RemoteAddr())
		reject := func(why string) {
			nc.Close()
			c.OnTransfer(Transfer{Proto: "ftp", Client: nc.RemoteAddr().String(), Result: "error", Error: why, ReasonT: lit(why), Rejected: true})
		}
		if !c.permitsAddr(nc.RemoteAddr()) {
			reject("origen no permitido")
			continue
		}
		release, ok := lim.acquire(ip)
		if !ok {
			reject("demasiadas conexiones o contraseñas erróneas desde este origen")
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer release()
			(&ftpSession{ctx: ctx, c: c, src: src, rcv: rcv, lim: lim, lo: lo, hi: hi, conn: nc}).run()
		}()
	}
}

type ftpSession struct {
	ctx    context.Context
	c      Config
	src    *source
	rcv    *receiver
	lim    *limiter
	lo, hi uint16
	conn   net.Conn
	rw     *bufio.Writer
	client string
	pasv   net.Listener
}

func (s *ftpSession) reply(code int, msg string) {
	fmt.Fprintf(s.rw, "%d %s\r\n", code, msg)
	s.rw.Flush()
}

func (s *ftpSession) rejected(x i18n.Text) {
	s.c.OnTransfer(Transfer{Proto: "ftp", Client: s.client, Result: "error", Error: x.In(i18n.Es), ReasonT: x, Rejected: true})
}

func (s *ftpSession) run() {
	nc := s.conn
	defer nc.Close()
	stop := context.AfterFunc(s.ctx, func() { nc.Close() })
	defer stop()
	s.client = nc.RemoteAddr().String()
	ic := newIdleConn(nc, idleTimeout)
	ic.setUntil(time.Now().Add(authWindow)) // NOOP y USER no lo renuevan
	br, ip := bufio.NewReaderSize(ic, 1024), hostOf(nc.RemoteAddr())
	s.rw = bufio.NewWriter(ic)
	defer s.closePasv()
	s.reply(220, "MACUAHUITL servidor temporal de archivos")
	var user string
	authed, fails := false, 0
	for {
		line, err := readFTPLine(br)
		if err != nil {
			return
		}
		cmd, arg, err := parseFTP(line)
		if err != nil {
			s.reply(500, "orden no válida")
			continue
		}
		switch cmd {
		case "QUIT":
			s.reply(221, "adiós")
			return
		case "NOOP":
			s.reply(200, "ok")
			continue
		case "USER":
			user, authed = arg, false
			s.reply(331, "contraseña requerida")
			continue
		case "PASS":
			if user == "" {
				s.reply(503, "primero USER")
				continue
			}
			if credsOK(user, arg, s.c.User, s.c.Pass) {
				authed = true
				ic.setUntil(time.Time{})
				s.reply(230, "sesión iniciada")
				continue
			}
			s.lim.fail(ip)
			if fails++; fails >= ftpLoginFail || s.lim.blocked(ip) {
				s.reply(421, "demasiados intentos")
				return
			}
			user = ""
			s.reply(530, "credenciales incorrectas")
			continue
		}
		if !authed {
			s.reply(530, "inicia sesión")
			continue
		}
		if !s.authedCmd(cmd, arg) {
			return
		}
	}
}

// authedCmd atiende una orden de una sesión autenticada; false cierra la conexión.
func (s *ftpSession) authedCmd(cmd, arg string) bool {
	switch cmd {
	case "SYST":
		s.reply(215, "UNIX Type: L8")
	case "FEAT":
		fmt.Fprint(s.rw, "211-Extensiones\r\n SIZE\r\n EPSV\r\n211 Fin\r\n")
		s.rw.Flush()
	case "TYPE":
		if u := strings.ToUpper(arg); u == "I" || u == "L 8" || strings.HasPrefix(u, "A") {
			s.reply(200, "tipo binario") // siempre se transfiere en binario
		} else {
			s.reply(504, "tipo no soportado")
		}
	case "MODE", "STRU":
		if a := strings.ToUpper(arg); a == "S" || a == "F" {
			s.reply(200, "ok")
		} else {
			s.reply(504, "no soportado")
		}
	case "PWD", "XPWD":
		s.reply(257, `"/" es el directorio actual`)
	case "CWD", "XCWD":
		if arg == "/" || arg == "." || arg == "" {
			s.reply(250, "ok")
		} else {
			s.reply(550, "solo existe /")
		}
	case "CDUP":
		s.reply(250, "ok")
	case "PASV":
		s.openPasv(false)
	case "EPSV":
		if strings.EqualFold(arg, "ALL") {
			s.reply(200, "ok")
		} else {
			s.openPasv(true)
		}
	case "PORT", "EPRT":
		s.reply(502, "modo activo deshabilitado: usa PASV (en IOS: ip ftp passive)")
	case "SIZE":
		f, fi, err := s.src.open(arg)
		if err != nil {
			s.reply(550, "archivo no publicado")
			break
		}
		f.Close()
		s.reply(213, fmt.Sprint(fi.Size()))
	case "LIST", "NLST":
		s.list(cmd == "NLST")
	case "RETR":
		s.retr(arg)
	case "STOR":
		s.stor(arg)
	case "APPE", "STOU", "DELE", "RNFR", "RNTO", "MKD", "XMKD", "RMD", "XRMD", "SITE", "REST", "ABOR":
		s.rejected(why("request_rejected", "type", cmd))
		s.reply(550, "operación no permitida")
	default:
		s.reply(502, "orden no implementada")
	}
	return true
}

func (s *ftpSession) closePasv() {
	if s.pasv != nil {
		s.pasv.Close()
		s.pasv = nil
	}
}

// openPasv abre un puerto de datos del rango, en la misma IP del control.
func (s *ftpSession) openPasv(ext bool) {
	s.closePasv()
	local := s.conn.LocalAddr().(*net.TCPAddr)
	ip, _ := netip.AddrFromSlice(local.IP)
	ip = ip.Unmap()
	if !ext && !ip.Is4() {
		s.reply(522, "usa EPSV en IPv6")
		return
	}
	var ln net.Listener
	var err error
	if s.lo == 0 && s.hi == 0 {
		ln, err = net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	} else {
		n := int(s.hi) - int(s.lo) + 1
		off := rand.IntN(n)
		for i := 0; i < n; i++ {
			p := int(s.lo) + (off+i)%n
			if ln, err = net.Listen("tcp", net.JoinHostPort(ip.String(), fmt.Sprint(p))); err == nil {
				break
			}
		}
	}
	if err != nil || ln == nil {
		s.reply(425, "no hay puertos pasivos libres")
		return
	}
	s.pasv = ln
	port := ln.Addr().(*net.TCPAddr).Port
	if ext {
		s.reply(229, fmt.Sprintf("Entering Extended Passive Mode (|||%d|)", port))
		return
	}
	o := ip.As4()
	s.reply(227, fmt.Sprintf("Entering Passive Mode (%d,%d,%d,%d,%d,%d)", o[0], o[1], o[2], o[3], port>>8, port&255))
}

// dataConn acepta la conexión de datos, solo desde la IP del cliente de control.
func (s *ftpSession) dataConn() (net.Conn, error) {
	ln := s.pasv
	if ln == nil {
		return nil, errors.New("sin PASV")
	}
	s.pasv = nil
	defer ln.Close()
	stopLn := context.AfterFunc(s.ctx, func() { ln.Close() }) // detener el servidor no espera el plazo de aceptación
	defer stopLn()
	want := hostOf(s.conn.RemoteAddr())
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(dataAccept))
	for {
		dc, err := ln.Accept()
		if err != nil {
			return nil, err
		}
		if hostOf(dc.RemoteAddr()) != want { // otro equipo intentando colarse en la transferencia
			dc.Close()
			continue
		}
		return &ctxConn{Conn: newIdleConn(dc, dataIdle), stop: context.AfterFunc(s.ctx, func() { dc.Close() })}, nil
	}
}

// ctxConn es la conexión de datos atada al contexto del servidor: al detenerlo se corta la
// transferencia en curso; Close suelta ese enlace.
type ctxConn struct {
	net.Conn
	stop func() bool
}

func (c *ctxConn) Close() error { c.stop(); return c.Conn.Close() }

func (s *ftpSession) list(namesOnly bool) {
	if s.pasv == nil {
		s.reply(425, "usa PASV primero")
		return
	}
	s.reply(150, "listado")
	dc, err := s.dataConn()
	if err != nil {
		s.reply(425, "sin conexión de datos")
		return
	}
	defer dc.Close()
	w := bufio.NewWriter(dc)
	for _, fi := range s.src.list() { // solo lo publicado; vacío si la lectura está apagada
		if namesOnly {
			fmt.Fprintf(w, "%s\r\n", fi.Name())
		} else {
			fmt.Fprintf(w, "-rw-r--r-- 1 ftp ftp %d %s %s\r\n", fi.Size(), fi.ModTime().Format("Jan _2 15:04"), fi.Name())
		}
	}
	w.Flush()
	dc.Close()
	s.reply(226, "listado completo")
}

func (s *ftpSession) retr(name string) {
	t := Transfer{Proto: "ftp", Dir: "lectura", Client: s.client, File: name, Result: "error"}
	if !s.src.enabled() {
		s.reply(550, "lectura deshabilitada")
		t.Error, t.ReasonT, t.Rejected = "lectura deshabilitada", lit("lectura deshabilitada"), true
		s.c.OnTransfer(t)
		return
	}
	f, _, err := s.src.open(name)
	if err != nil {
		s.reply(550, "archivo no publicado")
		t.Error, t.ReasonT, t.Rejected = "archivo no publicado", lit("archivo no publicado"), true
		s.c.OnTransfer(t)
		return
	}
	defer f.Close()
	t.Path = f.Name()
	if s.pasv == nil {
		s.reply(425, "usa PASV primero")
		return
	}
	start := time.Now()
	s.reply(150, "enviando")
	dc, err := s.dataConn()
	if err != nil {
		s.reply(425, "sin conexión de datos")
		t.Error, t.ReasonT = "sin conexión de datos", lit("sin conexión de datos")
		s.c.OnTransfer(t)
		return
	}
	n, err := io.Copy(dc, f)
	dc.Close()
	t.Bytes, t.Duration = n, time.Since(start)
	if err != nil {
		t.setErr(err)
		s.reply(426, "transferencia interrumpida")
	} else {
		t.Result = "ok"
		s.reply(226, "transferencia completa")
	}
	s.c.OnTransfer(t)
}

func (s *ftpSession) stor(name string) {
	t := Transfer{Proto: "ftp", Dir: "escritura", Client: s.client, File: name, Result: "error"}
	fail := func(code int, msg string) {
		s.reply(code, msg)
		t.Error, t.ReasonT, t.Rejected = msg, lit(msg), true
		s.c.OnTransfer(t)
	}
	if s.rcv == nil {
		fail(550, "escritura deshabilitada")
		return
	}
	if s.pasv == nil {
		s.reply(425, "usa PASV primero")
		return
	}
	rf, err := s.rcv.create(name, 0)
	switch {
	case errors.Is(err, errExists):
		fail(550, errExists.Error())
		return
	case errors.Is(err, errTooBig), errors.Is(err, errTotal), errors.Is(err, errTooMany):
		fail(552, err.Error())
		return
	case err != nil:
		fail(553, "nombre no permitido")
		return
	}
	t.File = rf.name
	start := time.Now()
	s.reply(150, "recibiendo")
	dc, err := s.dataConn()
	if err != nil {
		rf.abort()
		s.reply(425, "sin conexión de datos")
		return
	}
	_, err = io.Copy(rf, dc)
	dc.Close()
	t.Duration = time.Since(start)
	if err != nil {
		rf.abort()
		t.setErr(err)
		code := 426
		if errors.Is(err, errTooBig) || errors.Is(err, errTotal) {
			code = 552
		}
		s.reply(code, "transferencia abortada: "+oneLine(err.Error()))
		s.c.OnTransfer(t)
		return
	}
	sum, n, err := rf.commit()
	t.Bytes, t.SHA256, t.Path = n, sum, rf.path
	if err != nil {
		t.setErr(err)
		s.reply(451, "error al guardar")
	} else {
		t.Result = "ok"
		s.reply(226, "recibido")
	}
	s.c.OnTransfer(t)
}

func oneLine(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }
