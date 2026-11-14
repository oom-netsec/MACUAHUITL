// Package iosxe es el driver para IOS e IOS-XE (también Catalyst 9000 y WLC 9800).
package iosxe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
)

const openTimeout = 15 * time.Second

// maxRun es lo más que corre un comando aunque su salida siga llegando (el timeout de Run es de inactividad).
var maxRun = 30 * time.Minute

// maxDetect es lo más que tarda Detect: una reconexión no debe quedar retenida por un equipo que contesta a goteo.
var maxDetect = 2 * time.Minute

var (
	anyPrompt = regexp.MustCompile(`(?:^|\n)([\w.\-@/:]{1,63})([>#]) ?$`)
	more      = regexp.MustCompile(` ?--More-- ?`)
	// Secuencias con que el equipo borra el --More--: "\r    \r" o retrocesos "\b\b  \b\b".
	erase = regexp.MustCompile(`\r +\r|\x08+ +\x08+`)
)

// Prompts de configuración: SW1(config)#, SW1(config-if)#, SW1(config-if-range)#...
var cfgPrompt = regexp.MustCompile(`^\(config[\w\-]*\)#$`)

// Errores de configuración que detienen la sesión (regla 5 del ADR 0007).
// «Command rejected: ...» (a veces sin %) es que IOS no admitió la línea por un conflicto con otra configuración del puerto.
// «% Specify remote-as...» es que el neighbor ya no existe; «% Interface X removed» es que un comando borró una interfaz entera.
// Los demás avisos con % (%Warning de portfast, %LINK, «Not all config may be removed») son informativos: no detienen la ejecución y
// quedan en la bitácora con la respuesta de cada línea.
var cfgErrors = []string{"% Invalid input", "% Incomplete command", "% Ambiguous command", "% Error", "% Specify remote-as", "Command rejected", "% Command rejected"}

var interfaceRemoved = regexp.MustCompile(`^% Interface \S+ removed`)

// Avisos que IOS da cuando la línea sí se aplicó pero creó algo que nadie pidió (una VLAN nueva, que con VTP servidor se propaga).
var cfgWarnings = []string{"Creating vlan", "does not exist"}

var passwordPrompt = regexp.MustCompile(`(?i)password: ?$`)

type driver struct {
	w        io.Writer
	chunks   chan []byte
	readErr  chan error
	quit     chan struct{}
	err      error // primer error; desde ahí el driver no se reutiliza
	buf      []byte
	hostname string
}

// fail guarda el primer error y suelta al lector.
func (d *driver) fail(err error) error {
	if d.err == nil {
		d.err = err
		close(d.quit)
	}
	return d.err
}

func (d *driver) Err() error {
	if d.err != nil {
		return d.err
	}
	for { // lo que llega sin pedirlo se descarta; un canal cerrado es que el equipo cerró la sesión
		select {
		case _, ok := <-d.chunks:
			if !ok {
				err := <-d.readErr
				d.readErr <- err
				return d.fail(fmt.Errorf("%w: %v", platform.ErrClosed, err))
			}
		default:
			return nil
		}
	}
}

func (d *driver) Close() {
	if d.quit != nil {
		d.fail(platform.ErrClosed)
	}
}

func New() platform.Driver { return &driver{} }

func (d *driver) Open(ctx context.Context, r io.Reader, w io.Writer, enable *secret.Secret) error {
	defer enable.Destroy()
	d.w, d.chunks, d.readErr, d.quit = w, make(chan []byte, 64), make(chan error, 1), make(chan struct{})
	go d.pump(r)

	ctx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	text, err := d.until(ctx, func(s string) bool { return anyPrompt.MatchString(s) })
	if err != nil {
		return d.fail(err)
	}
	m := anyPrompt.FindStringSubmatch(text)
	d.hostname = m[1]
	if m[2] == ">" {
		if err := d.enable(ctx, enable); err != nil {
			return d.fail(err)
		}
	}
	for _, c := range []string{"terminal length 0", "terminal width 0"} {
		out, err := d.Run(ctx, c, 10*time.Second)
		if err != nil {
			return err
		}
		// NX-OS no admite ancho 0 («% Invalid number, range is (24:511)», «% Invalid parameter…»): su máximo es 511. Así las tablas no se parten
		// aunque la plataforma del host sea fija y no se llame a Detect.
		if c == "terminal width 0" && hasPercentLine(out.Text) {
			if _, err := d.Run(ctx, "terminal width 511", 10*time.Second); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *driver) enable(ctx context.Context, enable *secret.Secret) error {
	if _, err := io.WriteString(d.w, "enable\n"); err != nil {
		return err
	}
	isPw := func(s string) bool { return passwordPrompt.MatchString(s) }
	text, err := d.until(ctx, func(s string) bool { return isPw(s) || d.atPrompt(s) })
	if err != nil {
		return err
	}
	if isPw(text) {
		if enable.Empty() {
			return platform.ErrEnableFailed
		}
		line := append(append([]byte(nil), enable.Bytes()...), '\n')
		_, err := d.w.Write(line)
		for i := range line {
			line[i] = 0
		}
		if err != nil {
			return err
		}
		// IOS vuelve a pedir "Password:" si el secreto es incorrecto: es rechazo, no se reintenta.
		if text, err = d.until(ctx, func(s string) bool { return isPw(s) || d.atPrompt(s) }); err != nil {
			return err
		}
		if isPw(text) {
			return platform.ErrEnableFailed
		}
	}
	if !strings.HasSuffix(text, d.hostname+"#") && !strings.HasSuffix(text, d.hostname+"# ") {
		return platform.ErrEnableFailed
	}
	return nil
}

func (d *driver) pump(r io.Reader) {
	for {
		b := make([]byte, 4096)
		n, err := r.Read(b)
		if n > 0 {
			select {
			case d.chunks <- b[:n]:
			case <-d.quit:
				return
			}
		}
		if err != nil {
			d.readErr <- err
			close(d.chunks)
			return
		}
	}
}

func (d *driver) atPrompt(s string) bool {
	last := s[strings.LastIndexByte(s, '\n')+1:]
	last = strings.TrimSuffix(last, " ")
	return last == d.hostname+"#" || last == d.hostname+">"
}

// until acumula salida normalizada hasta que done la acepta. Responde a --More-- con espacio.
func (d *driver) until(ctx context.Context, done func(string) bool) (string, error) {
	return d.untilIdle(ctx, 0, done)
}

// untilIdle es until con plazo de inactividad: con idle > 0 falla si pasa idle sin que llegue nada, y cada pedazo
// de salida reinicia el reloj (una salida grande y lenta no se corta mientras siga llegando). ctx es el tope absoluto.
func (d *driver) untilIdle(ctx context.Context, idle time.Duration, done func(string) bool) (string, error) {
	var quiet <-chan time.Time
	var timer *time.Timer
	if idle > 0 {
		timer = time.NewTimer(idle)
		defer timer.Stop()
		quiet = timer.C
	}
	for {
		// El prompt y el --More-- están siempre en la última línea: se revisa solo desde el último salto (incluido,
		// por los patrones con (?:^|\n)). Limpiar todo el búfer en cada pedazo costaba tiempo cuadrático: 63 s con 1 MB.
		from := max(bytes.LastIndexByte(d.buf, '\n'), 0)
		tail := string(d.buf[from:])
		if strings.HasSuffix(strings.TrimRight(tail, " "), "--More--") {
			tail = more.ReplaceAllString(tail, "")
			d.buf = append(d.buf[:from], tail...)
			if _, err := io.WriteString(d.w, " "); err != nil {
				return clean(string(d.buf)), err
			}
		}
		if done(clean(tail)) {
			text := clean(string(d.buf))
			d.buf = nil
			return text, nil
		}
		select {
		case <-ctx.Done():
			return clean(string(d.buf)), fmt.Errorf("%w: %w", platform.ErrPromptTimeout, ctx.Err())
		case <-quiet:
			select { // llegó un pedazo justo al vencer el plazo: cuenta como actividad
			case c, ok := <-d.chunks:
				if !ok {
					return d.closedErr()
				}
				d.buf = append(d.buf, c...)
				timer.Reset(idle)
				continue
			default:
			}
			return clean(string(d.buf)), platform.ErrPromptTimeout
		case c, ok := <-d.chunks:
			if !ok {
				return d.closedErr()
			}
			d.buf = append(d.buf, c...)
			if timer != nil {
				timer.Reset(idle)
			}
		}
	}
}

// closedErr: el lector del shell terminó; se devuelve lo que había y la causa del cierre.
func (d *driver) closedErr() (string, error) {
	err := <-d.readErr
	d.readErr <- err
	return clean(string(d.buf)), fmt.Errorf("%w: %v", platform.ErrClosed, err)
}

func clean(s string) string {
	s = erase.ReplaceAllString(s, "")
	s = more.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "")
}

func (d *driver) Run(ctx context.Context, cmd string, timeout time.Duration) (platform.Output, error) {
	out := platform.Output{Command: cmd, Started: time.Now()}
	if d.err != nil {
		return out, d.err
	}
	if strings.ContainsAny(cmd, "\r\n") {
		return out, i18n.New("iosxe.err.newline", i18n.A("cmd", cmd))
	}
	ctx, cancel := context.WithTimeout(ctx, maxRun) // timeout es de inactividad; maxRun, el tope fijo
	defer cancel()
	if _, err := io.WriteString(d.w, cmd+"\n"); err != nil {
		return out, fmt.Errorf("%w: %v", platform.ErrClosed, err)
	}
	text, err := d.untilIdle(ctx, timeout, d.atPrompt)
	out.Ended = time.Now()
	if err != nil {
		d.fail(err)
	}
	// Quitar eco (primera línea) y prompt (última línea).
	if i := strings.IndexByte(text, '\n'); i >= 0 && strings.TrimSpace(text[:i]) == cmd {
		text = text[i+1:]
	}
	if err == nil {
		text = text[:strings.LastIndexByte(text, '\n')+1]
	}
	out.Text = text
	out.Invalid = invalidOutput(text)
	return out, err
}

// Respuestas de error de IOS («% Invalid input») y de NX-OS («% Invalid command», «% Invalid parameter», «% Incomplete command»).
var invalidMarks = []string{"% Invalid input", "% Invalid command", "% Invalid parameter", "% Incomplete command"}

func invalidOutput(text string) bool {
	for _, m := range invalidMarks {
		if strings.Contains(text, m) {
			return true
		}
	}
	return false
}

// hasPercentLine: alguna línea de text empieza por «%» (el equipo rechazó el comando).
func hasPercentLine(text string) bool {
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "%") {
			return true
		}
	}
	return false
}

func (d *driver) Hostname() string { return d.hostname }

// wlc9800 busca «C9800» solo en la línea del software, no en el hostname ni en el resto de show version.
var wlc9800 = regexp.MustCompile(`(?m)^Cisco IOS Software.*, C9800`)

// nxos busca la cabecera de show version de NX-OS al inicio de línea; un IOS-XE que mencione «NX-OS» en texto libre no cuenta.
var nxos = regexp.MustCompile(`(?m)^Cisco Nexus Operating System \(NX-OS\) Software`)

func (d *driver) Detect(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, maxDetect)
	defer cancel()
	out, err := d.Run(ctx, "show version", 60*time.Second)
	if err != nil {
		return "", err
	}
	switch {
	case nxos.MatchString(out.Text):
		return "nx-os", nil
	case wlc9800.MatchString(out.Text) && strings.Contains(out.Text, "Cisco IOS XE Software"): // antes de la regla genérica
		return "wlc-9800", nil
	case strings.Contains(out.Text, "Cisco IOS XE Software"):
		return "ios-xe", nil
	case strings.Contains(out.Text, "Cisco IOS Software"):
		return "ios", nil
	}
	return "", platform.ErrUnknownPlatform
}

func (d *driver) atConfigPrompt(s string) bool {
	last := strings.TrimSuffix(s[strings.LastIndexByte(s, '\n')+1:], " ")
	// IOS acorta el nombre en el prompt de configuración; se compara lo mismo que Netmiko: 16 caracteres.
	host := d.hostname
	if len(host) > 16 {
		host = host[:16]
	}
	rest, ok := strings.CutPrefix(last, host)
	return ok && cfgPrompt.MatchString(rest)
}

// cfgError dice si la salida de una línea de configuración trae un error de los que detienen.
func cfgError(text string) bool {
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		for _, e := range cfgErrors {
			if strings.HasPrefix(l, e) {
				return true
			}
		}
		if interfaceRemoved.MatchString(l) {
			return true
		}
		for _, w := range cfgWarnings {
			if strings.HasPrefix(l, "%") && strings.Contains(l, w) {
				return true
			}
		}
	}
	return false
}

// refuseConfigLine rechaza lo que sacaría al driver del modo configuración o ejecutaría exec.
func refuseConfigLine(l string) error {
	// Fuera de 0x20-0x7e: con exec-character-bits 7 el equipo quita el bit alto y "Í" llega como 'C' + CR.
	for _, r := range l {
		if r < 0x20 || r > 0x7e || r == '?' {
			return i18n.Wrap("iosxe.err.cfg_chars", platform.ErrConfigLine, i18n.A("line", l))
		}
	}
	f := strings.Fields(strings.ToLower(l))
	if len(f) == 0 {
		return i18n.Wrap("iosxe.err.cfg_empty", platform.ErrConfigLine, nil)
	}
	for _, w := range []string{"end", "exit", "do", "configure", "write", "copy", "reload"} {
		if playbook.Abbrev(f[0], w) { // IOS ejecuta cualquier prefijo único: "en", "ex", "wr", "conf t"
			return i18n.Wrap("iosxe.err.cfg_mode", platform.ErrConfigLine, i18n.A("line", l))
		}
	}
	return nil
}

// step manda una línea y espera el prompt que acepte ok; devuelve la salida sin eco ni prompt.
// wrote dice si la línea llegó a escribirse en el shell (con un error posterior pudo haberse ejecutado).
func (d *driver) step(ctx context.Context, line string, ok func(string) bool) (text string, wrote bool, err error) {
	if _, err := io.WriteString(d.w, line+"\n"); err != nil {
		return "", false, d.fail(fmt.Errorf("%w: %v", platform.ErrClosed, err))
	}
	text, err = d.until(ctx, ok)
	if err != nil {
		return text, true, d.fail(err)
	}
	if i := strings.IndexByte(text, '\n'); i >= 0 && strings.TrimSpace(text[:i]) == line {
		text = text[i+1:]
	}
	return text[:strings.LastIndexByte(text, '\n')+1], true, nil
}

func (d *driver) Configure(ctx context.Context, lines []string, timeout time.Duration) (platform.ConfigResult, error) {
	var res platform.ConfigResult
	if d.err != nil {
		return res, d.err
	}
	for _, l := range lines {
		if err := refuseConfigLine(l); err != nil {
			return res, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, _, err := d.step(ctx, "configure terminal", d.atConfigPrompt)
	if err != nil {
		d.tryEnd() // pudo entrar a configuración aunque el prompt no llegó
		return res, err
	}
	if cfgError(out) {
		return res, i18n.New("iosxe.err.no_config_mode", i18n.A("output", strings.TrimSpace(out)))
	}
	for _, l := range lines {
		out, wrote, err := d.step(ctx, l, d.atConfigPrompt)
		if err != nil {
			if wrote { // si ni se escribió, el equipo no la vio: no cuenta como enviada
				res.Lines = append(res.Lines, platform.LineResult{Line: l})
			}
			d.tryEnd()
			return res, err
		}
		lr := platform.LineResult{Line: l, Output: out, Failed: cfgError(out)}
		res.Lines = append(res.Lines, lr)
		if lr.Failed {
			res.Failed = true
			break
		}
	}
	if _, _, err := d.step(ctx, "end", d.atPrompt); err != nil {
		return res, err
	}
	return res, nil
}

// tryEnd intenta salir de configuración tras un fallo del driver, sin esperar respuesta: si la
// sesión sigue viva el equipo no queda en modo configuración; si no, el error ya está registrado.
func (d *driver) tryEnd() { io.WriteString(d.w, "end\n") }
