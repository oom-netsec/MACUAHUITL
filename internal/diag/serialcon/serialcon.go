// Package serialcon abre la consola serie de un equipo (USB-serie /dev/ttyUSB*,
// /dev/ttyACM* en Linux con termios; COMn en Windows con DCB) sin dependencias
// externas: 9600 8N1 sin control de flujo por defecto, como espera la consola de
// Cisco. No usa red. Lo propio de cada sistema vive en serialcon_linux.go y
// serialcon_windows.go.
package serialcon

import (
	"fmt"
	"slices"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

type Config struct {
	Path     string // Linux: absoluto, bajo /dev; Windows: COMn
	Baud     int    // 9600 por defecto
	DataBits int    // 5 a 8; 8 por defecto
	Parity   string // none, even, odd
	StopBits int    // 1 o 2
	Flow     string // none, rtscts, xonxoff
}

var validBauds = []int{1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600}

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

// StringIn es String en el idioma pedido.
func (c Config) StringIn(loc string) string {
	return fmt.Sprintf("%d %d%c%d %s=%s", c.Baud, c.DataBits, strings.ToUpper(c.Parity)[0], c.StopBits, i18n.Msg(loc, "serial.val.flow", nil), c.Flow)
}

// AuditString es String para la auditoría, que va siempre en inglés (flow en vez de flujo).
func (c Config) AuditString() string {
	return fmt.Sprintf("%d %d%c%d flow=%s", c.Baud, c.DataBits, strings.ToUpper(c.Parity)[0], c.StopBits, c.Flow)
}

func (c Config) validate() error {
	if err := validPath(c.Path); err != nil {
		return err
	}
	if !slices.Contains(validBauds, c.Baud) {
		return i18n.New("serial.err.baud", i18n.A("baud", c.Baud))
	}
	if c.DataBits < 5 || c.DataBits > 8 {
		return i18n.New("serial.err.data_bits", i18n.A("bits", c.DataBits))
	}
	if !slices.Contains([]string{"none", "even", "odd"}, c.Parity) {
		return i18n.New("serial.err.parity", i18n.A("parity", c.Parity))
	}
	if c.StopBits != 1 && c.StopBits != 2 {
		return i18n.New("serial.err.stop_bits", i18n.A("bits", c.StopBits))
	}
	if !slices.Contains([]string{"none", "rtscts", "xonxoff"}, c.Flow) {
		return i18n.New("serial.err.flow", i18n.A("flow", c.Flow))
	}
	return nil
}

// ErrPermission indica que el usuario no puede abrir el puerto (falta el grupo dialout).
var ErrPermission error = i18n.New("serial.err.permission", nil)

// Normalize aplica los valores por defecto y valida.
func (c Config) Normalize() (Config, error) {
	c = c.withDefaults()
	if err := c.validate(); err != nil {
		return c, err
	}
	c.Path = normPath(c.Path)
	return c, nil
}

// Open abre el puerto en exclusiva y en modo crudo.
func Open(c Config) (*Port, error) {
	c, err := c.Normalize()
	if err != nil {
		return nil, err
	}
	return open(c)
}
