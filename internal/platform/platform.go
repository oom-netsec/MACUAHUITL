// Package platform define la interfaz común de los drivers por plataforma
// Cisco (iosxe, nxos, aireos, ftd, ise, catcenter): prompts, paginación,
// modos y detección (spec §7.1).
//
// No hace: abrir conexiones por su cuenta; recibe el shell de transport.
package platform

import (
	"context"
	"io"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
)

var (
	ErrPromptTimeout   error = i18n.New("platform.err.prompt_timeout", nil)
	ErrEnableFailed    error = i18n.New("platform.err.enable_failed", nil)
	ErrUnknownPlatform error = i18n.New("platform.err.unknown", nil)
	ErrClosed          error = i18n.New("platform.err.closed", nil)
)

// Output es la salida limpia de un comando: sin eco, sin prompt y sin --More--.
type Output struct {
	Command        string
	Text           string
	Invalid        bool
	Incomplete     bool // el comando falló o se cortó: Text es parcial
	Started, Ended time.Time
}

// ErrConfigLine: la línea no puede enviarse en modo configuración (cambiaría de modo o ejecutaría
// un comando de exec).
var ErrConfigLine error = i18n.New("platform.err.config_line", nil)

// LineResult es una línea de configuración enviada y lo que el equipo respondió.
type LineResult struct {
	Line   string
	Output string
	Failed bool // la respuesta fue % Invalid input, % Incomplete command, % Ambiguous command o % Error
}

// ConfigResult es lo ocurrido en una sesión de configuración. Lines solo trae las líneas
// enviadas: tras un error no se manda ninguna más y el modo se cierra con "end".
type ConfigResult struct {
	Lines  []LineResult
	Failed bool
}

// Driver habla con un shell ya abierto.
type Driver interface {
	// Open espera el prompt, entra a privilegiado con enable y desactiva la paginación.
	// Destruye enable al volver.
	Open(ctx context.Context, r io.Reader, w io.Writer, enable *secret.Secret) error
	// Run manda un comando y espera el prompt. timeout es de inactividad: se reinicia con cada pedazo de salida, así
	// que una salida grande y lenta no se corta mientras siga llegando; un tope fijo del driver la acota igual.
	Run(ctx context.Context, cmd string, timeout time.Duration) (Output, error)
	// Configure entra con "configure terminal", manda las líneas una por una y sale con "end".
	// Tras el primer error de configuración no manda las restantes. No decide qué líneas son
	// aceptables: eso lo hace quien arma el plan; solo rechaza las que cambian de modo.
	Configure(ctx context.Context, lines []string, timeout time.Duration) (ConfigResult, error)
	// Detect devuelve el ID de plataforma de los playbooks (p. ej. "ios-xe").
	Detect(ctx context.Context) (string, error)
	// Hostname es el nombre que mostró el prompt; vacío antes de Open.
	Hostname() string
	// Err es nil si la sesión sigue utilizable. Detecta también un cierre que llegó mientras el
	// driver estaba ocioso (exec-timeout del equipo): quien lo reciba debe reconectar.
	Err() error
	// Close suelta el lector del shell. Tras cualquier error el driver queda inservible
	// y devuelve ese error en cada llamada: el worker debe reconectar.
	Close()
}
