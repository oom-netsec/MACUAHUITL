// Package serialcon abre la consola serie de un equipo (USB-serie /dev/ttyUSB*,
// /dev/ttyACM*) con termios directo, sin dependencias: 9600 8N1 sin control de
// flujo por defecto, como espera la consola de Cisco. No usa red.
package serialcon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

type Config struct {
	Path     string // absoluto, bajo /dev
	Baud     int    // 9600 por defecto
	DataBits int    // 5 a 8; 8 por defecto
	Parity   string // none, even, odd
	StopBits int    // 1 o 2
	Flow     string // none, rtscts, xonxoff
}

var bauds = map[int]uint32{
	1200: unix.B1200, 2400: unix.B2400, 4800: unix.B4800, 9600: unix.B9600, 19200: unix.B19200, 38400: unix.B38400,
	57600: unix.B57600, 115200: unix.B115200, 230400: unix.B230400, 460800: unix.B460800, 921600: unix.B921600,
}

var csize = map[int]uint32{5: unix.CS5, 6: unix.CS6, 7: unix.CS7, 8: unix.CS8}

func (c Config) withDefaults() Config {
	if c.Baud == 0 {
		c.Baud = 9600
	}
	if c.DataBits == 0 {
		c.DataBits = 8
	}
	if c.Parity == "" {
		c.Parity = "none"
	}
	if c.StopBits == 0 {
		c.StopBits = 1
	}
	if c.Flow == "" {
		c.Flow = "none"
	}
	return c
}

// String resume la configuración al estilo "9600 8N1".
func (c Config) String() string {
	return fmt.Sprintf("%d %d%c%d flujo=%s", c.Baud, c.DataBits, strings.ToUpper(c.Parity)[0], c.StopBits, c.Flow)
}

func (c Config) validate() error {
	if !filepath.IsAbs(c.Path) || !strings.HasPrefix(filepath.Clean(c.Path), "/dev/") {
		return fmt.Errorf("serialcon: %q no es un dispositivo bajo /dev", c.Path)
	}
	if _, ok := bauds[c.Baud]; !ok {
		return fmt.Errorf("serialcon: velocidad %d no soportada", c.Baud)
	}
	if _, ok := csize[c.DataBits]; !ok {
		return fmt.Errorf("serialcon: bits de datos %d inválidos (5 a 8)", c.DataBits)
	}
	if !slices.Contains([]string{"none", "even", "odd"}, c.Parity) {
		return fmt.Errorf("serialcon: paridad %q inválida (none, even, odd)", c.Parity)
	}
	if c.StopBits != 1 && c.StopBits != 2 {
		return fmt.Errorf("serialcon: bits de parada %d inválidos (1 o 2)", c.StopBits)
	}
	if !slices.Contains([]string{"none", "rtscts", "xonxoff"}, c.Flow) {
		return fmt.Errorf("serialcon: control de flujo %q inválido (none, rtscts, xonxoff)", c.Flow)
	}
	return nil
}

// ErrPermission indica que el usuario no puede abrir el puerto (falta el grupo dialout).
var ErrPermission = errors.New("sin permiso sobre el puerto serie")

type Port struct {
	f   *os.File
	Cfg Config
}

// Normalize aplica los valores por defecto y valida.
func (c Config) Normalize() (Config, error) {
	c = c.withDefaults()
	return c, c.validate()
}

// Open abre el puerto en exclusiva y en modo crudo.
func Open(c Config) (*Port, error) {
	c, err := c.Normalize()
	if err != nil {
		return nil, err
	}
	return open(c)
}

func open(c Config) (*Port, error) {
	// O_NONBLOCK deja el descriptor en el poller de Go: Close desbloquea un Read pendiente.
	f, err := os.OpenFile(c.Path, os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, openErr(c.Path, err)
	}
	p := &Port{f: f, Cfg: c}
	var cerr error
	p.control(func(fd int) {
		tio, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if err != nil {
			cerr = fmt.Errorf("serialcon: %s no es un puerto serie: %w", c.Path, err)
			return
		}
		// TIOCEXCL: un segundo programa no puede abrirlo y mezclar lo que se teclea.
		if err := unix.IoctlSetInt(fd, unix.TIOCEXCL, 0); err != nil {
			cerr = fmt.Errorf("serialcon: %s: %w", c.Path, err)
			return
		}
		raw(tio, c)
		if err := unix.IoctlSetTermios(fd, unix.TCSETS, tio); err != nil {
			cerr = fmt.Errorf("serialcon: configurar %s: %w", c.Path, err)
		}
	})
	if cerr != nil {
		f.Close()
		return nil, cerr
	}
	return p, nil
}

func openErr(path string, err error) error {
	switch {
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("%w %s: agrega tu usuario al grupo dialout con «sudo usermod -aG dialout $USER» y cierra todas tus sesiones o reinicia para que el servicio macuahuitld tome el grupo (no hace falta ejecutar MACUAHUITL como root)", ErrPermission, path)
	case errors.Is(err, unix.EBUSY):
		return fmt.Errorf("serialcon: %s está en uso por otro programa (minicom, screen…)", path)
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("serialcon: %s no existe; ¿está conectado el cable USB-serie?", path)
	}
	return fmt.Errorf("serialcon: %w", err)
}

// raw equivale a cfmakeraw más los parámetros de línea pedidos.
func raw(t *unix.Termios, c Config) {
	t.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON | unix.IXOFF | unix.IXANY
	t.Oflag &^= unix.OPOST
	t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	t.Cflag &^= unix.CSIZE | unix.PARENB | unix.PARODD | unix.CSTOPB | unix.CRTSCTS | unix.CBAUD
	t.Cflag |= csize[c.DataBits] | unix.CLOCAL | unix.CREAD | bauds[c.Baud]
	t.Ispeed, t.Ospeed = bauds[c.Baud], bauds[c.Baud]
	switch c.Parity {
	case "even":
		t.Cflag |= unix.PARENB
	case "odd":
		t.Cflag |= unix.PARENB | unix.PARODD
	}
	if c.StopBits == 2 {
		t.Cflag |= unix.CSTOPB
	}
	switch c.Flow {
	case "rtscts":
		t.Cflag |= unix.CRTSCTS
	case "xonxoff":
		t.Iflag |= unix.IXON | unix.IXOFF
	}
	t.Cc[unix.VMIN], t.Cc[unix.VTIME] = 1, 0
}

func (p *Port) control(fn func(fd int)) {
	rc, err := p.f.SyscallConn()
	if err != nil {
		return
	}
	rc.Control(func(fd uintptr) { fn(int(fd)) })
}

func (p *Port) Read(b []byte) (int, error)  { return p.f.Read(b) }
func (p *Port) Write(b []byte) (int, error) { return p.f.Write(b) }
func (p *Port) Close() error                { return p.f.Close() }

// Break envía una señal BREAK de 0.25 a 0.5 s (tcsendbreak): entra a ROMMON durante
// el arranque para recuperar la contraseña.
func (p *Port) Break() error {
	var err error
	p.control(func(fd int) { err = unix.IoctlSetInt(fd, unix.TCSBRK, 0) })
	if err != nil {
		return fmt.Errorf("serialcon: BREAK: %w", err)
	}
	return nil
}

// List devuelve los adaptadores USB-serie presentes (ttyUSB: FTDI, Prolific, CP210x;
// ttyACM: la consola USB mini-B/USB-C de los Catalyst e ISR).
func List() []string { return list("/dev") }

func list(dir string) []string {
	var out []string
	for _, pat := range []string{"ttyACM*", "ttyUSB*"} {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		out = append(out, m...)
	}
	return out
}

// Pty abre un pseudo-terminal y devuelve el maestro y la ruta del esclavo. El
// esclavo se comporta como un puerto serie: sirve de equipo falso en pruebas.
func Pty() (*os.File, string, error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, "", err
	}
	rc, _ := m.SyscallConn()
	var n int
	var perr error
	rc.Control(func(fd uintptr) {
		if perr = unix.IoctlSetPointerInt(int(fd), unix.TIOCSPTLCK, 0); perr == nil {
			n, perr = unix.IoctlGetInt(int(fd), unix.TIOCGPTN)
		}
	})
	if perr != nil {
		m.Close()
		return nil, "", perr
	}
	return m, fmt.Sprintf("/dev/pts/%d", n), nil
}
