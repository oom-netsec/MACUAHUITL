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
	ErrFirstLogin      error = i18n.New("platform.err.first_login", nil)
	ErrDesync          error = i18n.New("platform.err.desync", nil)
	ErrUnknownPlatform error = i18n.New("platform.err.unknown", nil)
	ErrClosed          error = i18n.New("platform.err.closed", nil)
	ErrLoginFailed     error = i18n.New("platform.err.login_failed", nil)
	ErrConfirmPrompt   error = i18n.New("platform.err.confirm_prompt", nil)
	ErrConfigPrompt    error = i18n.New("platform.err.config_prompt", nil)
	// ErrChangetoUnsupported: se pidió un cambio de contexto a un driver o plataforma que no lo tiene (solo ASA).
	ErrChangetoUnsupported error = i18n.New("platform.err.changeto_unsupported", nil)
	// ErrUnexpectedPrompt: un «User:» o «Password:» llegó fuera del login (a mitad de un comando); no se contesta.
	ErrUnexpectedPrompt error = i18n.New("platform.err.unexpected_prompt", nil)
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

// ShellLogin es la interfaz opcional de los drivers cuyo equipo pide usuario y clave ya dentro del shell SSH
// (AireOS: «User:» y «Password:»). Solo Patrol la llama, antes de Open, si el driver la implementa. El driver clona la
// clave (pw sigue siendo de quien llama), la destruye tras usarla y en Close, y nunca la deja en errores, logs ni evidencia.
type ShellLogin interface {
	SetLogin(user string, pw *secret.Secret)
}

// Prompt son los segmentos de un prompt de ASA (host/ctx/pri/act...). Host y Context son los estables; el rol
// (Priority, State, Cluster) cambia en un failover o un cambio de unidad de control y se informa aparte.
type Prompt struct {
	Host     string // hostname
	Context  string // contexto; vacío en el espacio del sistema o con un solo contexto
	Domain   string // dominio (lleva puntos)
	Unit     string // unidad de cluster
	Priority string // pri o sec
	State    string // act, stby, actNoFailover o stbyNoFailover
	Cluster  string // control, data (9.19 en adelante), master o slave
}

// ContextSwitcher es la interfaz opcional de los drivers que cambian de contexto con changeto (ASA multicontexto).
// Solo el ejecutor de Patrol la llama, nunca un texto de playbook (ADR 0011).
type ContextSwitcher interface {
	// Prompt es el último prompt visto, ya separado en segmentos; vacío si el driver no lo reconoce.
	Prompt() Prompt
	// ChangeTo manda «changeto system» (target "system") o «changeto context <target>» y verifica el prompt nuevo:
	// mismo hostname y el contexto pedido. Si no coincide, la sesión queda inservible y devuelve el error.
	ChangeTo(ctx context.Context, target string, timeout time.Duration) error
}
