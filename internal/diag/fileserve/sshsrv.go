package fileserve

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Servidor SSH efímero con solo dos usos: `scp` (fuente -f y destino -t) y el subsistema
// `sftp`. Sin shell, sin exec que no sea scp, sin reenvío de puertos ni de agente. Las
// llaves de host se generan al abrir y se descartan al cerrar; su huella se muestra al usuario.

const (
	maxSessionsPerConn = 4
	maxOpenSFTP        = 16
	maxScpLine         = 2048
)

func hostSigners(legacy bool) ([]ssh.Signer, []string, error) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ed, err := ssh.NewSignerFromKey(edPriv)
	if err != nil {
		return nil, nil, err
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	rs, err := ssh.NewSignerFromKey(rk)
	if err != nil {
		return nil, nil, err
	}
	algs := []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256} // la llave RSA firma solo con SHA-2…
	if legacy {
		algs = append(algs, ssh.KeyAlgoRSA) // …salvo a pedido: IOS 15.x firma con ssh-rsa (SHA-1)
	}
	if rs, err = ssh.NewSignerWithAlgorithms(rs.(ssh.AlgorithmSigner), algs); err != nil {
		return nil, nil, err
	}
	fps := []string{ssh.FingerprintSHA256(ed.PublicKey()), ssh.FingerprintSHA256(rs.PublicKey())}
	return []ssh.Signer{ed, rs}, fps, nil
}

func serveSSH(ctx context.Context, c Config, src *source, rcv *receiver) error {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", c.Addr)
	if err != nil {
		return fmt.Errorf("fileserve: %w", err)
	}
	defer ln.Close()
	signers, fps, err := hostSigners(c.Legacy)
	if err != nil {
		return fmt.Errorf("fileserve: %w", err)
	}
	lim := newLimiter()
	cfg := &ssh.ServerConfig{
		MaxAuthTries:  3,
		ServerVersion: "SSH-2.0-macuahuitl",
		PasswordCallback: func(md ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if credsOK(md.User(), string(pw), c.User, c.Pass) {
				return nil, nil
			}
			lim.fail(hostOf(md.RemoteAddr()))
			return nil, errors.New("contraseña incorrecta")
		},
	}
	for _, s := range signers {
		cfg.AddHostKey(s)
	}
	sshAlgorithms(cfg, c.Legacy)
	stop := context.AfterFunc(ctx, func() { ln.Close() })
	defer stop()
	c.ready(Ready{Addr: ln.Addr().String(), User: c.User, Pass: c.Pass, Fingerprints: fps})
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
			c.OnTransfer(Transfer{Proto: c.Proto, Client: nc.RemoteAddr().String(), Result: "error", Error: why, Rejected: true})
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
			(&sshConn{ctx: ctx, c: c, src: src, rcv: rcv, cfg: cfg}).serve(nc)
		}()
	}
}

// sshAlgorithms fija las listas de algoritmos de forma explícita. Moderno (por omisión): solo lo
// de x/crypto marcado como seguro, sin SHA-1. Legacy (--legacy-ssh): además, y nada más, lo que
// aún negocia un IOS 15.x: diffie-hellman-group14-sha1, aes128-cbc, 3des-cbc y hmac-sha1; sin
// group1, sin RC4 y sin hmac-sha1-96.
func sshAlgorithms(cfg *ssh.ServerConfig, legacy bool) {
	sup := ssh.SupportedAlgorithms()
	cfg.KeyExchanges = slices.Clone(sup.KeyExchanges)
	cfg.Ciphers = slices.Clone(sup.Ciphers)
	cfg.MACs = slices.DeleteFunc(slices.Clone(sup.MACs), func(m string) bool { return m == ssh.HMACSHA1 })
	if legacy {
		cfg.KeyExchanges = append(cfg.KeyExchanges, ssh.InsecureKeyExchangeDH14SHA1)
		cfg.Ciphers = append(cfg.Ciphers, ssh.InsecureCipherAES128CBC, ssh.InsecureCipherTripleDESCBC)
		cfg.MACs = append(cfg.MACs, ssh.HMACSHA1)
	}
}

type sshConn struct {
	ctx context.Context
	c   Config
	src *source
	rcv *receiver
	cfg *ssh.ServerConfig
}

func (s *sshConn) serve(nc net.Conn) {
	defer nc.Close()
	stop := context.AfterFunc(s.ctx, func() { nc.Close() })
	defer stop()
	ic := newIdleConn(nc, 15*time.Second)   // handshake y autenticación
	ic.setUntil(time.Now().Add(authWindow)) // absoluto: el handshake a cuentagotas no lo renueva
	sc, chans, reqs, err := ssh.NewServerConn(ic, s.cfg)
	if err != nil {
		return // sin credenciales válidas no hay nada que registrar más allá de los intentos
	}
	ic.setUntil(time.Time{})
	ic.setIdle(idleTimeout)
	go ssh.DiscardRequests(reqs) // tcpip-forward y demás globales: se responden con rechazo
	client := sc.RemoteAddr().String()
	var live atomic.Int32
	var wg sync.WaitGroup
	defer wg.Wait()
	for nch := range chans {
		if nch.ChannelType() != "session" { // direct-tcpip, forwarded-tcpip, x11, streamlocal…
			s.reject(client, "canal "+nch.ChannelType()+" rechazado") // se registra antes de responder: el cliente ve la respuesta con la bitácora ya escrita
			nch.Reject(ssh.Prohibited, "solo sesiones scp o sftp")
			continue
		}
		if live.Add(1) > maxSessionsPerConn {
			live.Add(-1)
			nch.Reject(ssh.ResourceShortage, "demasiadas sesiones")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			live.Add(-1)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer live.Add(-1)
			s.session(ch, creqs, client)
		}()
	}
}

func (s *sshConn) reject(client, why string) {
	s.c.OnTransfer(Transfer{Proto: s.c.Proto, Client: client, Result: "error", Error: why, Rejected: true})
}

// session atiende las peticiones de un canal: solo `subsystem sftp` (proto sftp) o
// `exec scp …` (proto scp). Todo lo demás recibe respuesta negativa.
func (s *sshConn) session(ch ssh.Channel, reqs <-chan *ssh.Request, client string) {
	defer ch.Close()
	for r := range reqs {
		switch {
		case r.Type == "subsystem" && s.c.Proto == "sftp" && payloadString(r.Payload) == "sftp":
			r.Reply(true, nil)
			go discard(reqs)
			s.runSFTP(ch, client)
			return
		case r.Type == "exec" && s.c.Proto == "scp":
			mode, path, err := parseSCP(payloadString(r.Payload))
			if err != nil {
				s.reject(client, "exec rechazado: "+err.Error())
				r.Reply(false, nil)
				continue
			}
			r.Reply(true, nil)
			go discard(reqs)
			status := uint32(0)
			if err := s.runSCP(ch, mode, path, client); err != nil {
				status = 1
			}
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
			return
		case r.Type == "env" || r.Type == "window-change" || r.Type == "signal":
			r.Reply(false, nil)
		default: // shell, pty-req, exec ajeno, subsystem ajeno, x11-req, auth-agent-req…
			s.reject(client, r.Type+" rechazado")
			r.Reply(false, nil)
		}
	}
}

func discard(reqs <-chan *ssh.Request) {
	for r := range reqs {
		if r.WantReply {
			r.Reply(false, nil)
		}
	}
}

// payloadString lee el string SSH (longitud + bytes) de una petición; "" si está mal formado.
func payloadString(p []byte) string {
	var m struct{ S string }
	if ssh.Unmarshal(p, &m) != nil {
		return ""
	}
	return m.S
}

// parseSCP interpreta la orden exec de scp: `scp [-t|-f] [-vpdq] [--] ruta`. Rechaza
// recursivo (-r), cualquier otra opción, comillas raras y rutas con caracteres de control.
// Nunca se pasa a un intérprete: solo se usa la ruta y solo como nombre base.
func parseSCP(cmd string) (mode byte, path string, err error) {
	f := strings.Split(cmd, " ")
	if len(f) < 3 || f[0] != "scp" {
		return 0, "", errors.New("solo se permite scp")
	}
	i := 1
	for ; i < len(f) && strings.HasPrefix(f[i], "-"); i++ {
		if f[i] == "--" {
			i++
			break
		}
		if len(f[i]) < 2 {
			return 0, "", errors.New("opción inválida")
		}
		for _, o := range f[i][1:] {
			switch o {
			case 't', 'f':
				if mode != 0 && mode != byte(o) {
					return 0, "", errors.New("-t y -f a la vez")
				}
				mode = byte(o)
			case 'v', 'p', 'd', 'q':
			default:
				return 0, "", fmt.Errorf("opción -%c no permitida", o)
			}
		}
	}
	if mode == 0 || len(f)-i != 1 {
		return 0, "", errors.New("se esperaba -t o -f y una sola ruta")
	}
	path = f[i]
	if n := len(path); n >= 2 && (path[0] == '\'' && path[n-1] == '\'' || path[0] == '"' && path[n-1] == '"') {
		path = path[1 : n-1]
	}
	if strings.ContainsAny(path, "'\"\\`$;&|<>") || path == "" {
		return 0, "", errors.New("ruta no permitida")
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return 0, "", errors.New("ruta con caracteres de control")
		}
	}
	return mode, path, nil
}

// ---- SCP ----

func scpFail(ch ssh.Channel, msg string) { ch.Write(append([]byte{1}, msg+"\n"...)) }

func (s *sshConn) runSCP(ch ssh.Channel, mode byte, path, client string) error {
	if mode == 't' {
		return s.scpSink(ch, path, client)
	}
	return s.scpSource(ch, path, client)
}

// readScpLine lee una línea de control de scp con tope de longitud.
func readScpLine(br *bufio.Reader) (string, error) {
	var b []byte
	for len(b) < maxScpLine {
		c, err := br.ReadByte()
		if err != nil {
			return string(b), err
		}
		if c == '\n' {
			return string(b), nil
		}
		b = append(b, c)
	}
	return "", errors.New("línea de control demasiado larga")
}

// scpSink recibe archivos (scp -t): el equipo sube, p. ej. `copy running-config scp://…`.
func (s *sshConn) scpSink(ch ssh.Channel, target, client string) error {
	if s.rcv == nil {
		scpFail(ch, "escritura deshabilitada")
		s.reject(client, "escritura deshabilitada")
		return errors.New("escritura deshabilitada")
	}
	ch.Write([]byte{0})
	br := bufio.NewReaderSize(ch, 32<<10)
	for {
		line, err := readScpLine(br)
		if err != nil {
			if errors.Is(err, io.EOF) && line == "" {
				return nil // el cliente terminó
			}
			return err
		}
		if line == "" {
			scpFail(ch, "línea vacía")
			return errors.New("línea vacía")
		}
		switch line[0] {
		case 'T': // fecha y hora: se ignoran
			ch.Write([]byte{0})
			continue
		case 'C':
		default: // D (directorios) y E: no se aceptan
			scpFail(ch, "solo archivos")
			s.reject(client, "scp: directorios no soportados")
			return errors.New("solo archivos")
		}
		parts := strings.SplitN(line[1:], " ", 3)
		size, serr := int64(0), error(nil)
		if len(parts) == 3 {
			size, serr = strconv.ParseInt(parts[1], 10, 64)
		}
		if len(parts) != 3 || serr != nil || size < 0 {
			scpFail(ch, "orden C mal formada")
			return errors.New("orden C mal formada")
		}
		name := parts[2]
		if t := strings.TrimPrefix(target, "/"); t != "" && t != "." && !strings.HasSuffix(target, "/") {
			name = target // la ruta destino nombra el archivo; si es una carpeta manda el nombre de la orden C
		}
		t := Transfer{Proto: "scp", Dir: "escritura", Client: client, File: name, Result: "error"}
		start := time.Now()
		rf, err := s.rcv.create(name, size)
		if err != nil {
			scpFail(ch, err.Error())
			t.Error = err.Error()
			t.Duration = time.Since(start)
			s.c.OnTransfer(t)
			return err
		}
		t.File = rf.name
		ch.Write([]byte{0})
		_, err = io.CopyN(rf, br, size)
		if err == nil {
			var ack byte
			if ack, err = br.ReadByte(); err == nil && ack != 0 {
				err = errors.New("el cliente abortó")
			}
		}
		if err != nil {
			rf.abort()
			t.Error = err.Error()
			t.Duration = time.Since(start)
			s.c.OnTransfer(t)
			return err
		}
		sum, n, err := rf.commit()
		t.Bytes, t.SHA256, t.Path, t.Duration = n, sum, rf.path, time.Since(start)
		if err != nil {
			t.Error = err.Error()
			s.c.OnTransfer(t)
			return err
		}
		t.Result = "ok"
		s.c.OnTransfer(t)
		ch.Write([]byte{0})
	}
}

// scpSource entrega un archivo publicado (scp -f): `copy scp://… flash:`.
func (s *sshConn) scpSource(ch ssh.Channel, path, client string) error {
	one := make([]byte, 1)
	ack := func() error {
		if _, err := io.ReadFull(ch, one); err != nil {
			return err
		}
		if one[0] != 0 {
			return errors.New("el cliente abortó")
		}
		return nil
	}
	if err := ack(); err != nil {
		return err
	}
	name := strings.TrimPrefix(path, "/")
	t := Transfer{Proto: "scp", Dir: "lectura", Client: client, File: name, Result: "error"}
	if !s.src.enabled() {
		scpFail(ch, "lectura deshabilitada")
		s.reject(client, "lectura deshabilitada")
		return errors.New("lectura deshabilitada")
	}
	f, fi, err := s.src.open(name)
	if err != nil {
		scpFail(ch, "archivo no publicado")
		t.Error, t.Rejected = "archivo no publicado", true
		s.c.OnTransfer(t)
		return err
	}
	defer f.Close()
	t.Path = f.Name()
	start := time.Now()
	defer func() { t.Duration = time.Since(start); s.c.OnTransfer(t) }()
	if _, err = fmt.Fprintf(ch, "C0644 %d %s\n", fi.Size(), name); err == nil {
		if err = ack(); err == nil {
			var n int64
			n, err = io.CopyN(ch, f, fi.Size())
			t.Bytes = n
			if err == nil {
				ch.Write([]byte{0})
				err = ack()
			}
		}
	}
	if err != nil {
		t.Error = err.Error()
		return err
	}
	t.Result = "ok"
	return nil
}

// ---- SFTP ----

func (s *sshConn) runSFTP(ch ssh.Channel, client string) {
	h := &sftpHandler{s: s, client: client}
	defer h.abortOpen()
	rs := sftp.NewRequestServer(ch, sftp.Handlers{FileGet: h, FilePut: h, FileCmd: h, FileList: h},
		sftp.WithRSAllocator())
	rs.Serve() // vuelve cuando el cliente cierra
	rs.Close()
}

// sftpHandler es todo el "sistema de archivos" del SFTP: no toca el disco por rutas del
// cliente. Leer = source (nombre base publicado); escribir = receiver (archivo nuevo); el
// resto se rechaza. Así no hay árbol que escapar.
type sftpHandler struct {
	s      *sshConn
	client string
	mu     sync.Mutex
	open   map[io.Closer]struct{}
}

func (h *sftpHandler) track(c io.Closer) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.open == nil {
		h.open = map[io.Closer]struct{}{}
	}
	if len(h.open) >= maxOpenSFTP {
		return sftp.ErrSSHFxFailure
	}
	h.open[c] = struct{}{}
	return nil
}

func (h *sftpHandler) untrack(c io.Closer) {
	h.mu.Lock()
	delete(h.open, c)
	h.mu.Unlock()
}

// abortOpen descarta lo que quedó abierto al cortarse la sesión: nada se queda a medias.
func (h *sftpHandler) abortOpen() {
	h.mu.Lock()
	open := h.open
	h.open = nil
	h.mu.Unlock()
	for c := range open {
		if w, ok := c.(*sftpWriter); ok {
			w.fail(errors.New("sesión cerrada antes de terminar"))
		}
		c.Close()
	}
}

func (h *sftpHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	if !h.s.src.enabled() {
		h.s.reject(h.client, "lectura deshabilitada")
		return nil, sftp.ErrSSHFxPermissionDenied
	}
	f, fi, err := h.s.src.open(r.Filepath)
	if err != nil {
		h.s.c.OnTransfer(Transfer{Proto: "sftp", Dir: "lectura", Client: h.client, File: r.Filepath, Result: "error", Error: "archivo no publicado", Rejected: true})
		return nil, os.ErrNotExist
	}
	rd := &sftpReader{File: f, h: h, t: Transfer{Proto: "sftp", Dir: "lectura", Client: h.client, File: fi.Name(), Path: f.Name(), Result: "error"}, start: time.Now()}
	if err := h.track(rd); err != nil {
		f.Close()
		return nil, err
	}
	return rd, nil
}

// sftpReader cuenta lo leído y registra la transferencia al cerrarse.
type sftpReader struct {
	*os.File
	h     *sftpHandler
	t     Transfer
	start time.Time
	max   atomic.Int64
	once  sync.Once
}

func (r *sftpReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.File.ReadAt(p, off)
	for end := off + int64(n); ; {
		cur := r.max.Load()
		if end <= cur || r.max.CompareAndSwap(cur, end) {
			break
		}
	}
	return n, err
}

func (r *sftpReader) Close() error {
	r.once.Do(func() {
		r.h.untrack(r)
		r.t.Bytes, r.t.Duration = r.max.Load(), time.Since(r.start)
		if st, err := r.File.Stat(); err == nil && r.t.Bytes >= st.Size() {
			r.t.Result = "ok"
		} else {
			r.t.Error = "lectura incompleta"
		}
		r.h.s.c.OnTransfer(r.t)
	})
	return r.File.Close()
}

func (h *sftpHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	if h.s.rcv == nil {
		h.s.reject(h.client, "escritura deshabilitada")
		return nil, sftp.ErrSSHFxPermissionDenied
	}
	t := Transfer{Proto: "sftp", Dir: "escritura", Client: h.client, File: r.Filepath, Result: "error"}
	rf, err := h.s.rcv.create(r.Filepath, 0) // SafeName toma solo el nombre base
	if err != nil {
		t.Error = err.Error()
		h.s.c.OnTransfer(t)
		if errors.Is(err, errExists) {
			return nil, os.ErrExist
		}
		return nil, sftp.ErrSSHFxFailure
	}
	t.File = rf.name
	w := &sftpWriter{rf: rf, h: h, t: t, start: time.Now()}
	if err := h.track(w); err != nil {
		rf.abort()
		return nil, err
	}
	return w, nil
}

// sftpWriter: si algún WriteAt falló (tope, disco), el archivo se descarta al cerrar.
type sftpWriter struct {
	rf    *recvFile
	h     *sftpHandler
	t     Transfer
	start time.Time
	mu    sync.Mutex
	err   error
	once  sync.Once
}

func (w *sftpWriter) fail(err error) {
	w.mu.Lock()
	if w.err == nil {
		w.err = err
	}
	w.mu.Unlock()
}

// TransferError lo llama pkg/sftp antes de cerrar un handle que se cortó (cliente caído,
// servidor detenido): sin esto el cierre daría por buena una subida a medias.
func (w *sftpWriter) TransferError(err error) { w.fail(err) }

func (w *sftpWriter) WriteAt(p []byte, off int64) (int, error) {
	n, err := w.rf.WriteAt(p, off)
	if err != nil {
		w.fail(err)
	}
	return n, err
}

func (w *sftpWriter) Close() error {
	w.once.Do(func() {
		w.h.untrack(w)
		w.mu.Lock()
		err := w.err
		w.mu.Unlock()
		w.t.Duration = time.Since(w.start)
		if err != nil {
			w.rf.abort()
			w.t.Error = err.Error()
		} else {
			sum, n, cerr := w.rf.commit()
			w.t.Bytes, w.t.SHA256, w.t.Path = n, sum, w.rf.path
			if cerr != nil {
				w.t.Error = cerr.Error()
			} else {
				w.t.Result = "ok"
			}
		}
		w.h.s.c.OnTransfer(w.t)
	})
	return nil
}

// Filecmd: ni borrar, ni renombrar, ni crear carpetas ni enlaces. Setstat se acepta sin
// hacer nada (clientes como `sftp put -p` lo mandan tras subir un archivo).
func (h *sftpHandler) Filecmd(r *sftp.Request) error {
	if r.Method == "Setstat" {
		return nil
	}
	h.s.reject(h.client, "sftp "+r.Method+" rechazado")
	return sftp.ErrSSHFxPermissionDenied
}

func (h *sftpHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	root := r.Filepath == "/" || r.Filepath == "."
	switch r.Method {
	case "List":
		if !root {
			return nil, os.ErrNotExist
		}
		return listerAt(h.s.src.list()), nil
	case "Stat":
		if root {
			return listerAt{rootInfo{}}, nil
		}
		f, fi, err := h.s.src.open(r.Filepath)
		if err != nil {
			return nil, os.ErrNotExist
		}
		f.Close()
		return listerAt{renamed{fi, strings.TrimPrefix(r.Filepath, "/")}}, nil
	}
	return nil, sftp.ErrSSHFxOpUnsupported
}

type listerAt []os.FileInfo

func (l listerAt) ListAt(f []os.FileInfo, off int64) (int, error) {
	if off >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(f, l[off:])
	if n < len(f) {
		return n, io.EOF
	}
	return n, nil
}

type rootInfo struct{}

func (rootInfo) Name() string       { return "/" }
func (rootInfo) Size() int64        { return 0 }
func (rootInfo) Mode() os.FileMode  { return os.ModeDir | 0o555 }
func (rootInfo) ModTime() time.Time { return time.Time{} }
func (rootInfo) IsDir() bool        { return true }
func (rootInfo) Sys() any           { return nil }
