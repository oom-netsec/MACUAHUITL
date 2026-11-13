package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

var ErrAuth error = i18n.New("transport.err.auth", nil)

var errAlreadySent = errors.New("transport: contraseña ya enviada; no se reintenta")

// SSHOptions viene del perfil del equipo. Los ceros toman los valores de spec §6.
type SSHOptions struct {
	AllowLegacy      bool
	Keepalive        time.Duration // 15 s
	HandshakeTimeout time.Duration // 15 s
	// OnLegacy recibe los algoritmos negociados cuando AllowLegacy está activo, para auditoría (spec §3).
	OnLegacy func(negotiated string)
}

// Algoritmos que solo negocian equipos viejos; se activan por perfil (spec §3).
var (
	legacyKex     = []string{"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"}
	legacyCiphers = []string{"aes128-cbc", "3des-cbc"} // x/crypto no implementa aes256-cbc
	legacyHostKey = []string{ssh.KeyAlgoRSA}
)

// Session es una conexión SSH autenticada a un equipo.
type Session struct {
	client *ssh.Client
	sess   *ssh.Session
	stop   chan struct{}
	rx     atomic.Int64 // bytes leídos del shell: si siguen llegando, la sesión está viva aunque no conteste el keepalive
}

// OpenSSH conecta pasando por el Guard y autentica una sola vez.
// Al volver, cred.Password y cred.SSHKey ya fueron destruidos; cred.Enable queda para el driver.
func OpenSSH(ctx context.Context, g *Guard, jobID, host string, port uint16, cred vault.Credential, hk ssh.HostKeyCallback, o SSHOptions) (*Session, error) {
	defer cred.Password.Destroy()
	defer cred.SSHKey.Destroy()
	if o.Keepalive == 0 {
		o.Keepalive = 15 * time.Second
	}
	if o.HandshakeTimeout == 0 {
		o.HandshakeTimeout = 15 * time.Second
	}
	cfg := &ssh.ClientConfig{User: cred.Username, HostKeyCallback: hk, Timeout: o.HandshakeTimeout}
	if !cred.SSHKey.Empty() {
		signer, err := ssh.ParsePrivateKey(cred.SSHKey.Bytes())
		if err != nil {
			return nil, fmt.Errorf("transport: llave SSH: %w", err)
		}
		cfg.Auth = append(cfg.Auth, ssh.PublicKeys(signer))
	}
	if !cred.Password.Empty() {
		// La contraseña se manda una sola vez por conexión, por password o por keyboard-interactive:
		// nunca se reintenta un rechazo (spec §6, bloqueo de cuentas TACACS).
		// Límite declarado (THREAT_MODEL §Límites 1): x/crypto/ssh exige string, que no se puede borrar;
		// se crea en el momento del envío y no queda guardado en la configuración de la sesión.
		sent := false
		once := func() (string, error) {
			if sent {
				return "", errAlreadySent
			}
			sent = true
			return string(cred.Password.Bytes()), nil
		}
		cfg.Auth = append(cfg.Auth,
			ssh.PasswordCallback(once),
			ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
				if len(qs) == 0 {
					return nil, nil
				}
				pw, err := once()
				if err != nil {
					return nil, err
				}
				ans := make([]string, len(qs))
				for i := range ans {
					ans[i] = pw
				}
				return ans, nil
			}))
	}
	if o.AllowLegacy {
		def := ssh.SupportedAlgorithms()
		cfg.KeyExchanges = append(def.KeyExchanges, legacyKex...)
		cfg.Ciphers = append(def.Ciphers, legacyCiphers...)
		cfg.HostKeyAlgorithms = append(def.HostKeys, legacyHostKey...)
	}

	conn, err := g.Dial(ctx, jobID, host, port)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(o.HandshakeTimeout))
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		var he *HostKeyError
		if errors.As(err, &he) {
			return nil, he
		}
		// x/crypto no exporta un error de autenticación; se reconoce por su texto o por nuestro centinela.
		if errors.Is(err, errAlreadySent) || strings.Contains(err.Error(), errAlreadySent.Error()) || strings.Contains(err.Error(), "unable to authenticate") {
			return nil, fmt.Errorf("%w: %s", ErrAuth, addr)
		}
		return nil, fmt.Errorf("transport: ssh %s: %w", addr, err)
	}
	conn.SetDeadline(time.Time{})
	if o.AllowLegacy && o.OnLegacy != nil {
		if am, ok := c.(ssh.AlgorithmsConnMetadata); ok {
			a := am.Algorithms()
			o.OnLegacy(fmt.Sprintf("kex=%s cipher=%s mac=%s hostkey=%s", a.KeyExchange, a.Write.Cipher, a.Write.MAC, a.HostKey))
		}
	}
	s := &Session{client: ssh.NewClient(c, chans, reqs), stop: make(chan struct{})}
	send := func() error {
		_, _, err := s.client.SendRequest("keepalive@openssh.com", true, nil)
		return err
	}
	go keepaliveLoop(o.Keepalive, send, s.rx.Load, func() { s.client.Close() }, s.stop)
	return s, nil
}

// keepaliveLoop cierra la sesión tras 3 fallos seguidos (spec §6). Una respuesta que no llega
// en un intervalo cuenta como fallo: en un enlace caído SendRequest se bloquea minutos. Pero si
// rx avanzó, llegaron datos: un equipo ocupado mandando una salida grande no contesta el keepalive
// y la sesión sigue viva, así que eso no cuenta como fallo.
func keepaliveLoop(every time.Duration, send func() error, rx func() int64, closeFn func(), stop <-chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	fails := 0
	last := rx()
	var res chan error // envío en vuelo: mientras no conteste no se lanza otro (SendRequest se encola y acumularía goroutines)
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		if res == nil {
			res = make(chan error, 1)
			go func(c chan<- error) { c <- send() }(res)
		}
		var err error
		select {
		case <-stop:
			return
		case err = <-res:
			res = nil
		case <-time.After(every):
			err = errors.New("sin respuesta")
		}
		now := rx()
		if err == nil || now != last {
			fails, last = 0, now
			continue
		}
		if fails++; fails >= 3 {
			closeFn()
			return
		}
	}
}

// Client es la conexión SSH ya autenticada, para quien abre su propio canal (scp, sftp).
// Cerrar la Session la cierra.
func (s *Session) Client() *ssh.Client { return s.client }

// Shell abre un shell interactivo con PTY vt100 de 200×24.
func (s *Session) Shell() (io.Reader, io.Writer, error) { return s.ShellSize(24, 200) }

// ShellSize abre el shell con un PTY vt100 del tamaño dado (la terminal manual usa el de su ventana).
func (s *Session) ShellSize(rows, cols int) (io.Reader, io.Writer, error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return nil, nil, fmt.Errorf("transport: %w", err)
	}
	if err := sess.RequestPty("vt100", rows, cols, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		sess.Close()
		return nil, nil, fmt.Errorf("transport: pty: %w", err)
	}
	w, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		return nil, nil, err
	}
	out, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, nil, err
	}
	r := countingReader{out, &s.rx}
	if err := sess.Shell(); err != nil {
		sess.Close()
		return nil, nil, fmt.Errorf("transport: shell: %w", err)
	}
	s.sess = sess
	return r, w, nil
}

// Resize avisa al equipo del nuevo tamaño de la ventana; solo tras ShellSize.
func (s *Session) Resize(rows, cols int) error {
	if s.sess == nil {
		return errors.New("transport: sin shell abierto")
	}
	return s.sess.WindowChange(rows, cols)
}

func (s *Session) Close() error {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	if s.sess != nil {
		s.sess.Close()
	}
	return s.client.Close()
}

// countingReader cuenta los bytes que entrega, para que el keepalive sepa que llegan datos.
type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}
