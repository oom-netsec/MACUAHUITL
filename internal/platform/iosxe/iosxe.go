// Package iosxe es el driver para IOS e IOS-XE (también Catalyst 9000 y WLC 9800).
package iosxe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
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

// maxOutput es el tope de bytes que se guardan de la salida de un comando (igual que maxFile de fleet, 64 MiB). Al pasarlo
// se conservan el inicio y los últimos outTail bytes (para seguir viendo el prompt), el resto se descarta mientras el
// equipo termina de hablar y la salida sale Incomplete. No es error: el equipo y la sesión siguen sanos, solo falta el medio.
var maxOutput = 64 << 20

// outTail es la cola que se revisa en busca de prompt y --More--: un prompt mide a lo sumo ~130 bytes.
const outTail = 4096

// maxDetect es lo más que tarda Detect: una reconexión no debe quedar retenida por un equipo que contesta a goteo.
var maxDetect = 2 * time.Minute

var (
	anyPrompt = regexp.MustCompile(`(?:^|\n)([\w.\-@/:]{1,63})([>#]) ?$`)
	// FTD: la CLI normal tiene el prompt «> » sin nombre de host. Una línea de salida que empiece con «>» (BGP, tablas)
	// se confunde con él, así que solo cuenta al final del búfer y tras una pausa (ftdSettle) sin más datos.
	ftdPrompt = regexp.MustCompile(`(?:^|\n)> ?$`)
	// Primer inicio de sesión de FTD: cambio de contraseña obligatorio o EULA. Responder cambiaría el equipo.
	// Solo cuenta al final de la salida (un MOTD que cite la frase y siga no es un primer login) y pasa por moreComing.
	ftdFirstLogin = regexp.MustCompile(`(?i)(?:you must change your password|you must accept the eula|press <enter> to display the eula|enter new password:|confirm new password:|unix password:|to agree to the eula|please enter 'yes')[.:]? *$`)
	// Primer inicio de sesión de ISE (ADE-OS): contraseña vencida o cambio obligatorio, o una pregunta (y/n) o (yes/no).
	// Responder cambiaría el nodo: se aborta sin escribir. Solo cuenta al final de la salida.
	iseFirstLogin = regexp.MustCompile(`(?i)(?:password (?:has )?expired|(?:must|required to) change (?:your |the )?password|changing password for|(?:enter|confirm|retype|re-enter) new password:|new password:|\(current\) password:|current password:|[(\[](?:y/n|yes/no)[)\]][?:]?) *$`)
	// Primer inicio de sesión de un usuario nuevo del ASA 9.x: pide cambiar la contraseña. Responder cambiaría el equipo:
	// se aborta sin escribir. Solo cuenta al final de la salida (un banner que cite la frase y siga no es un primer login).
	asaFirstLogin = regexp.MustCompile(`(?i)(?:this is your first login\.?|please set a new password(?: before proceeding)?\.?|(?:enter )?old password:) *$`)
	more          = regexp.MustCompile(` ?(?:--More-- or \(q\)uit|--More or \(q\)uit current module or <ctrl-z> to abort|--More--|<--- More --->) ?`) // el segundo es el de ASA, el primero el de AireOS
	// AireOS: prompt «(Nombre) >» (el nombre puede llevar espacios), el de configuración «(Nombre) config>» y el login
	// «User:»/«Password:» dentro del shell. La pregunta de confirmación se detecta solo al final de la salida.
	airePrompt = regexp.MustCompile(`(?:^|\n)\(([^()\r\n]{1,63})\) ?>\s?$`)
	aireConfig = regexp.MustCompile(`(?:^|\n)\([^()\r\n]{1,63}\) config[\w\-]*>\s?$`)
	aireUser   = regexp.MustCompile(`(?:^|\n)User: ?$`) // solo «User:» exacto: «Username:» es de IOS/ASA/NX-OS y no se contesta
	// aireCue: el login del shell solo se contesta si la línea anterior a «User:» es el nombre del controlador entre paréntesis.
	aireCue     = regexp.MustCompile(`(?:^|\n)\([^()\r\n]{1,63}\) *\n *User: ?$`)
	aireMore    = regexp.MustCompile(`--More-- or \(q\)uit$|--More or \(q\)uit current module or <ctrl-z> to abort$`)
	airePass    = regexp.MustCompile(`(?i)(?:^|\n)password: ?$`)
	aireConfirm = regexp.MustCompile(`(?i)(?:[(\[](?:y/n|yes/no)[)\]]|\[confirm\]|are you sure[^\n]*\?|proceed\?) *$`)
	aireSysinfo = regexp.MustCompile(`(?m)^Product Name\.*\s*Cisco Controller`)
	// Secuencias con que el equipo borra el --More--: "\r    \r" o retrocesos "\b\b  \b\b".
	erase = regexp.MustCompile(`\r +\r|\x08+ +\x08+`)
)

// Prompts de configuración: SW1(config)#, SW1(config-if)#, SW1(config-if-range)#...
var cfgPrompt = regexp.MustCompile(`^\(config[\w\-]*\)#$`)

// Errores de configuración que detienen la sesión (regla 5 del ADR 0007).
// «Command rejected: ...» (a veces sin %) es que IOS no admitió la línea por un conflicto con otra configuración del puerto.
// «% Specify remote-as...» es que el neighbor ya no existe; «% Interface X removed» es que un comando borró una interfaz entera.
// Cualquier otro «% texto» también detiene (falla cerrado), salvo los avisos informativos conocidos de infoPercent
// (%Warning/%Portfast de portfast, «Not all config may be removed», etc.); %LINK (syslog) no lleva espacio y no entra.
// Lo que no detiene queda en la bitácora con la respuesta de cada línea.
var cfgErrors = []string{"% Invalid input", "% Incomplete command", "% Ambiguous command", "% Error", "% Specify remote-as", "Command rejected", "% Command rejected"}

var interfaceRemoved = regexp.MustCompile(`^% Interface \S+ removed`)

// Avisos que IOS da cuando la línea sí se aplicó pero creó algo que nadie pidió (una VLAN nueva, que con VTP servidor se propaga).
var cfgWarnings = []string{"Creating vlan", "does not exist"}

// infoPercent son los «% …» informativos de IOS en modo configuración: no detienen la ejecución.
var infoPercent = regexp.MustCompile(`(?i)^% ?(?:info|notice|portfast|applying|please|remember|note|warning|generating|not all config may be removed|default route without gateway|no matching route to delete)`)

// syslogLine es un mensaje de syslog (%FACILIDAD-severidad-MNEMÓNICO:) que el equipo intercala en la consola: no es una respuesta al comando.
var syslogLine = regexp.MustCompile(`^%[A-Z0-9_]+(?:-[A-Z0-9_]+)*-\d-[A-Z0-9_]+:`)

var asaSetPassword = regexp.MustCompile(`(?i)The enable password is not set|(?:enter|repeat)\s+password: ?$`)

var passwordPrompt = regexp.MustCompile(`(?i)password: ?$`)

type driver struct {
	w        io.Writer
	chunks   chan []byte
	readErr  chan error
	quit     chan struct{}
	err      error // primer error; desde ahí el driver no se reutiliza
	buf      []byte
	hostname string
	serials  []string // las series que mostró el show version de Detect (todas las del stack, ordenadas); vacío si no trae
	// AireOS: aire se activa al ver su prompt; user/login son la credencial del shell (login se destruye tras usarla).
	aire  bool
	user  string
	login *secret.Secret
	// FTD (hostname vacío): sentinel = Run manda un Enter vacío tras el comando; el fin confirmado son dos prompts
	// seguidos. confirmed/incomplete los deja untilIdle para Run.
	sentinel, confirmed, incomplete bool
	dropped                         bool // add descartó bytes del medio por maxOutput
	headLen, markLen, omitted       int  // con dropped: bytes de la cabeza, del separador y omitidos
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
	d.dropLogin()
	if d.quit != nil {
		d.fail(platform.ErrClosed)
	}
}

func New() platform.Driver { return &driver{} }

// SetLogin guarda user y un clon de pw (sin pasar por string) para el «User:»/«Password:» del shell de AireOS.
func (d *driver) SetLogin(user string, pw *secret.Secret) {
	d.dropLogin()
	d.user = user
	if !pw.Empty() {
		d.login = secret.New(append([]byte(nil), pw.Bytes()...)) // New pone el intermedio en ceros
	}
}

func (d *driver) dropLogin() { d.login.Destroy(); d.login = nil }

// aireLogin contesta «User:» y «Password:» una sola vez, solo antes del primer prompt. Un rechazo (vuelve a pedir
// User: o Password:), la falta de credencial o un prompt inesperado abortan sin reintentar ni escribir de más. Ningún
// error ni texto lleva la clave.
func (d *driver) aireLogin(ctx context.Context) (string, error) {
	defer d.dropLogin()
	if d.user == "" || d.login.Empty() || strings.ContainsAny(d.user, "\r\n") || bytes.ContainsAny(d.login.Bytes(), "\r\n") {
		return "", platform.ErrLoginFailed
	}
	next := func(s string) bool { // anyPrompt: un IOS que imitó el banner responde con su prompt y no hay que esperar a que venza Open
		return airePass.MatchString(s) || aireUser.MatchString(s) || airePrompt.MatchString(s) || anyPrompt.MatchString(s)
	}
	if _, err := io.WriteString(d.w, d.user+"\n"); err != nil {
		return "", fmt.Errorf("%w: %v", platform.ErrClosed, err)
	}
	text, err := d.until(ctx, next)
	if err != nil {
		return "", err
	}
	if !airePass.MatchString(text) {
		return "", platform.ErrLoginFailed
	}
	line := append(append([]byte(nil), d.login.Bytes()...), '\n')
	_, err = d.w.Write(line)
	clear(line)
	if err != nil {
		return "", fmt.Errorf("%w: %v", platform.ErrClosed, err)
	}
	if text, err = d.until(ctx, next); err != nil {
		return "", err
	}
	if !airePrompt.MatchString(text) {
		return "", platform.ErrLoginFailed
	}
	return text, nil
}

// loginCue: el búfer termina en «(Nombre)» + «User:» (las dos últimas líneas).
func (d *driver) loginCue() bool {
	i := bytes.LastIndexByte(d.buf, '\n')
	if i > 0 {
		i = bytes.LastIndexByte(d.buf[:i], '\n')
	}
	return aireCue.MatchString(clean(string(d.buf[max(i, 0):])))
}

func (d *driver) Open(ctx context.Context, r io.Reader, w io.Writer, enable *secret.Secret) error {
	defer enable.Destroy()
	defer d.dropLogin()
	d.w, d.chunks, d.readErr, d.quit = w, make(chan []byte, 64), make(chan error, 1), make(chan struct{})
	go d.pump(r)

	ctx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	text, err := d.until(ctx, func(s string) bool {
		return anyPrompt.MatchString(s) || ftdPrompt.MatchString(s) || ftdFirstLogin.MatchString(s) ||
			airePrompt.MatchString(s) || aireConfig.MatchString(s) || d.loginCue() || iseFirstLogin.MatchString(s) ||
			asaFirstLogin.MatchString(s)
	})
	if err != nil {
		return d.fail(err)
	}
	if aireConfig.MatchString(text) {
		return d.fail(platform.ErrConfigPrompt)
	}
	if aireCue.MatchString(text) {
		var err error
		if text, err = d.aireLogin(ctx); err != nil {
			d.clearBuf() // el equipo pudo repetir la clave con eco
			return d.fail(err)
		}
	}
	if m := airePrompt.FindStringSubmatch(text); m != nil {
		d.aire, d.hostname = true, m[1]
		return nil // AireOS: sin enable y sin «terminal …» (config paging disable es configuración)
	}
	m := anyPrompt.FindStringSubmatch(text)
	if m == nil {
		if !ftdPrompt.MatchString(text) { // primer inicio de sesión: no se escribe nada, ni siquiera un Enter
			return d.fail(platform.ErrFirstLogin)
		}
		m = []string{"", "", ">"}
	}
	d.hostname = m[1]
	if m[2] == ">" && d.hostname != "" { // FTD no tiene enable
		if err := d.enable(ctx, enable); err != nil {
			return d.fail(err)
		}
	}
	for _, c := range []string{"terminal length 0", "terminal width 0"} {
		out, err := d.Run(ctx, c, 10*time.Second)
		if err != nil {
			return err
		}
		// ISE (prompt host/admin#, con «/»; IOS no admite «/» en el nombre y ASA rechaza length 0): ADE-OS acepta
		// «terminal length 0» y no tiene «terminal width», así que no se le manda.
		if c == "terminal length 0" && strings.Contains(d.hostname, "/") && !hasPercentLine(out.Text) {
			break
		}
		// ASA no admite «terminal length 0»: su paginación se apaga con «terminal pager 0».
		if c == "terminal length 0" && hasPercentLine(out.Text) {
			if _, err := d.Run(ctx, "terminal pager 0", 10*time.Second); err != nil {
				return err
			}
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
	// ASA 9.12+ sin clave de enable pide fijarla («Enter Password:» / «Repeat Password:»): mandar el secreto cambiaría la configuración.
	if asaSetPassword.MatchString(text) {
		return platform.ErrEnableFailed
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
	if d.aire {
		return last == "("+d.hostname+") >" || last == "("+d.hostname+")>"
	}
	if d.hostname == "" { // FTD: solo «>»
		return last == ">"
	}
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
		// Sin saltos (un «| json» de una línea, un equipo hostil) la «última línea» sería todo el búfer: se acota a outTail.
		// El salto se busca solo en esa ventana final: buscarlo en todo el búfer recorría 16 MiB en cada lectura.
		w := max(len(d.buf)-outTail, 0)
		from := w
		if i := bytes.LastIndexByte(d.buf[w:], '\n'); i >= 0 {
			from = w + i
		}
		tail := string(d.buf[from:])
		// AireOS: solo el «--More-- or (q)uit» completo (un «--More--» partido entre dos lecturas no se contesta a medias).
		if t := strings.TrimRight(tail, " "); d.aire && aireMore.MatchString(t) || !d.aire && strings.HasSuffix(t, "--More--") || strings.HasSuffix(t, "<--- More --->") {
			tail = more.ReplaceAllString(tail, "")
			d.buf = append(d.buf[:from], tail...)
			if _, err := io.WriteString(d.w, " "); err != nil {
				return cleanBuf(d.buf), err
			}
		}
		if d.aire {
			if err := d.aireGuard(ctx, clean(tail)); err != nil {
				return cleanBuf(d.buf), err
			}
		}
		if d.sentinel {
			if bareConfirmed(d.buf) { // dos prompts seguidos: el comando terminó, salvo que un trozo corte justo ahí y la salida siga
				if d.dataWithin(ctx, ftdConfirmSettle) {
					continue
				}
				d.confirmed = true
				text := cleanBuf(d.buf)
				d.clearBuf()
				return text, nil
			}
			if ftdPrompt.MatchString(clean(tail)) {
				if !d.quiet(ctx, 3) { // llegaron datos (o venció el plazo): se revisa de nuevo
					continue
				}
				d.incomplete = true // un solo «> » y nada más en ~1,2 s: se acepta, pero incompleto
				text := cleanBuf(d.buf)
				d.clearBuf()
				return text, nil
			}
		} else if ct := clean(tail); done(ct) {
			if d.moreComing(ctx, ct) { // llegaron datos en la pausa: se revisa de nuevo
				continue
			}
			text := cleanBuf(d.buf)
			d.clearBuf()
			return text, nil
		}
		select {
		case <-ctx.Done():
			return cleanBuf(d.buf), fmt.Errorf("%w: %w", platform.ErrPromptTimeout, ctx.Err())
		case <-quiet:
			select { // llegó un pedazo justo al vencer el plazo: cuenta como actividad
			case c, ok := <-d.chunks:
				if !ok {
					return d.closedErr()
				}
				d.add(c)
				timer.Reset(idle)
				continue
			default:
			}
			return cleanBuf(d.buf), platform.ErrPromptTimeout
		case c, ok := <-d.chunks:
			if !ok {
				return d.closedErr()
			}
			d.add(c)
			if timer != nil {
				timer.Reset(idle)
			}
		}
	}
}

// clearBuf vacía el búfer al terminar de leer un comando y reinicia el estado del recorte: el siguiente comando cuenta sus propios bytes omitidos.
func (d *driver) clearBuf() { d.buf, d.headLen, d.markLen, d.omitted = nil, 0, 0, 0 }

// add agrega un pedazo al búfer respetando maxOutput: pasado el tope se conserva el inicio y se reemplaza la cola
// por los últimos outTail bytes, de modo que el prompt final se siga reconociendo y la memoria no crezca.
func (d *driver) add(c []byte) {
	if len(d.buf)+len(c) <= maxOutput {
		d.buf = append(d.buf, c...)
		return
	}
	d.dropped = true
	// Cabeza | separador | cola: la cola (los últimos outTail bytes) empieza en línea nueva y dice cuántos bytes se omitieron entre las dos.
	head, tail := min(len(d.buf), max(maxOutput-outTail, 0)), []byte(nil)
	if d.omitted > 0 && len(d.buf) >= d.headLen+d.markLen { // ya recortado antes: cabeza y cola de siempre
		head, tail = d.headLen, d.buf[d.headLen+d.markLen:]
	} else {
		d.omitted, tail = 0, d.buf[head:]
	}
	win := append(append([]byte(nil), tail...), c...)
	cut := max(len(win)-outTail, 0)
	d.omitted += cut
	mark := fmt.Appendf(nil, "\n[… output truncated: %d bytes omitted …]\n", d.omitted)
	d.headLen, d.markLen = head, len(mark)
	d.buf = append(append(d.buf[:head], mark...), win[cut:]...)
}

// aireGuard corta el comando si el final de la salida es algo que el driver nunca contesta: un «User:»/«Password:»
// fuera del login (no se escribe nada), el prompt de configuración o una pregunta de confirmación (y/N).
func (d *driver) aireGuard(ctx context.Context, tail string) error {
	switch {
	case aireUser.MatchString(tail) || airePass.MatchString(tail): // no es un rechazo de credencial: no debe disparar el respaldo
		return platform.ErrUnexpectedPrompt
	case aireConfig.MatchString(tail):
		return platform.ErrConfigPrompt
	case aireConfirm.MatchString(tail):
		if d.dataWithin(ctx, ftdConfirmSettle) { // «(y/N)» a mitad de una línea que sigue llegando no es una pregunta
			return nil
		}
		return platform.ErrConfirmPrompt
	}
	return nil
}

// ftdSettle es la pausa sin datos tras un «> » para aceptarlo como prompt de FTD.
// Límites sin un marcador del equipo (no se distinguen): dos líneas seguidas tipo prompt dentro de la salida («>\n> ») con
// una pausa de ~200 ms o más cortan en silencio; la defensa es que el siguiente comando no traiga su eco y se reconecte.
// Es una heurística: una pausa mayor a mitad de la salida, justo tras una línea «> », aún la cortaría (sin un marcador del equipo no se cierra del todo).
var ftdSettle = 400 * time.Millisecond

// bareConfirmed: el búfer termina en dos líneas de prompt de FTD seguidas: la penúltima es exactamente «>» o «> » y la
// última es «> » sin salto después. Una línea «> » dentro de la salida no va seguida de otro prompt idéntico.
func bareConfirmed(buf []byte) bool {
	n := len(buf)
	for n > 0 && buf[n-1] == ' ' {
		n--
	}
	if n == 0 || buf[n-1] != '>' {
		return false
	}
	n-- // la última línea es «>» o «> »
	if n == 0 || buf[n-1] != '\n' {
		return false
	}
	n-- // salto antes de la última línea
	if n > 0 && buf[n-1] == '\r' {
		n--
	}
	for n > 0 && buf[n-1] == ' ' {
		n--
	}
	if n == 0 || buf[n-1] != '>' {
		return false
	}
	n--
	return n == 0 || buf[n-1] == '\n'
}

// echoNorm quita lo que el eco puede alterar (saltos, «$» de scroll, espacios) y aplica los retrocesos.
func echoNorm(s string) string {
	var out []byte
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\x08':
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		case '\r', '\n', '$', ' ':
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

// echoFirst: la respuesta empieza con el eco de cmd. Vale el eco completo o un prefijo suyo (envuelto o truncado),
// pero no cualquier otra primera línea.
func echoFirst(text, cmd string) bool {
	c := echoNorm(cmd)
	first, _, _ := strings.Cut(text, "\n")
	f := echoNorm(first)
	// Sufijo: un comando largo con scroll horizontal se ve como «$» + su final; 16+ caracteres para no tomar un resto corto por eco.
	return c == "" || strings.HasPrefix(echoNorm(text), c) || f != "" && strings.HasPrefix(c, f) || len(f) >= 16 && strings.HasSuffix(c, f)
}

// ftdConfirmSettle es la calma corta antes de dar por confirmado el par de prompts: un trozo puede terminar justo en «\n>\n> ».
var ftdConfirmSettle = 150 * time.Millisecond // var para que las pruebas la bajen, como ftdSettle

// dataWithin espera hasta dur por datos; si llegan, los agrega y devuelve true.
func (d *driver) dataWithin(ctx context.Context, dur time.Duration) bool {
	select {
	case c, ok := <-d.chunks:
		if ok {
			d.add(c)
		}
		return ok
	case <-time.After(dur):
	case <-ctx.Done():
	}
	return false
}

// quiet espera n pausas ftdSettle seguidas sin datos; true si pasaron todas. Si llegan datos, los agrega y devuelve false.
func (d *driver) quiet(ctx context.Context, n int) bool {
	for range n {
		select {
		case c, ok := <-d.chunks:
			if ok {
				d.add(c)
			}
			return false
		case <-time.After(ftdSettle):
		case <-ctx.Done():
			return false
		}
	}
	return true
}

// moreComing: si tail es el «> » de FTD, espera ftdSettle por más datos; si llegan, no era el prompt (era el inicio
// de una línea de salida) y se agregan al búfer.
func (d *driver) moreComing(ctx context.Context, tail string) bool {
	// «User:», «(y/n)», «New password:», «(Cisco Controller) >» o un aviso de contraseña de un banner pueden ir seguidos del prompt de otra plataforma.
	// Límite conocido: con una pausa mayor a ftdSettle antes del prompt (banner lento) «\r\n> » se toma por FTD y «(y/n)» o
	// «password has expired» dan ErrFirstLogin; es heurística y falla cerrada: nunca se escribe una credencial, aunque con
	// «\r\n> » Open sí manda «terminal length 0» y el Enter de cola antes de fallar.
	aireOpen := !d.aire && (airePrompt.MatchString(tail) || aireConfig.MatchString(tail)) // solo al abrir: en el Run de AireOS no se espera
	if !ftdPrompt.MatchString(tail) && !aireUser.MatchString(tail) && !iseFirstLogin.MatchString(tail) && !ftdFirstLogin.MatchString(tail) &&
		!asaFirstLogin.MatchString(tail) && !aireOpen {
		return false
	}
	select {
	case c, ok := <-d.chunks:
		if ok {
			d.add(c)
			return true
		}
		return false // el cierre lo reporta la vuelta siguiente
	case <-time.After(ftdSettle):
		return false
	case <-ctx.Done():
		return false
	}
}

// closedErr: el lector del shell terminó; se devuelve lo que había y la causa del cierre.
func (d *driver) closedErr() (string, error) {
	err := <-d.readErr
	d.readErr <- err
	return cleanBuf(d.buf), fmt.Errorf("%w: %v", platform.ErrClosed, err)
}

// cleanBuf es clean(string(b)) sin las 5 o 6 copias de la salida entera: clean no cruza un salto de línea (ni el borrado de
// --More-- ni el «\r\n»), así que se limpia por trozos que terminan en «\n» y el resultado se arma una sola vez.
func cleanBuf(b []byte) string {
	const chunk = 64 << 10
	if len(b) <= chunk {
		return clean(string(b))
	}
	var sb strings.Builder
	sb.Grow(len(b))
	for len(b) > 0 {
		n := len(b)
		if n > chunk {
			if i := bytes.IndexByte(b[chunk:], '\n'); i >= 0 {
				n = chunk + i + 1
			}
		}
		c := b[:n]
		if bytes.IndexByte(c, 8) < 0 && !bytes.Contains(c, []byte("\r ")) && !bytes.Contains(c, []byte("More")) {
			// Sin borrados ni --More--, clean solo quita los retornos de carro: sin copias intermedias.
			for len(c) > 0 {
				i := bytes.IndexByte(c, '\r')
				if i < 0 {
					i = len(c)
				}
				sb.Write(c[:i])
				c = c[min(i+1, len(c)):]
			}
		} else {
			sb.WriteString(clean(string(c)))
		}
		b = b[n:]
	}
	return sb.String()
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
	d.confirmed, d.incomplete, d.dropped = false, false, false
	d.headLen, d.markLen, d.omitted = 0, 0, 0
	if d.sentinel = d.hostname == ""; d.sentinel { // FTD: un Enter vacío en cola da el segundo prompt cuando el comando termina
		defer func() { d.sentinel = false }()
		if _, err := io.WriteString(d.w, "\n"); err != nil {
			return out, fmt.Errorf("%w: %v", platform.ErrClosed, err)
		}
	}
	text, err := d.untilIdle(ctx, timeout, d.atPrompt)
	out.Ended = time.Now()
	if err != nil {
		d.fail(err)
	}
	// FTD: la primera línea de la respuesta debe ser el eco del comando (normalizado; envuelto o truncado también vale);
	// si no, es la cola del comando anterior: la sesión está desfasada.
	desync := d.sentinel && err == nil && !echoFirst(text, cmd)
	// Quitar eco (primera línea) y prompt (última línea).
	if i := strings.IndexByte(text, '\n'); i >= 0 && strings.TrimSpace(text[:i]) == cmd {
		text = text[i+1:]
	}
	if err == nil {
		text = text[:strings.LastIndexByte(text, '\n')+1]
		if d.confirmed { // el prompt del comando y el del Enter de cola: se quitan los dos
			text = text[:strings.LastIndexByte(strings.TrimSuffix(text, "\n"), '\n')+1]
		}
		// Cierre por calma: incompleto, pero la sesión sigue (si el equipo descarta el Enter de cola, todos los comandos
		// cerrarían así). Respuesta sin eco: es la cola del comando anterior, la sesión ya no sirve y se debe reconectar.
		out.Incomplete = d.incomplete || d.dropped || desync
		if desync {
			err = d.fail(platform.ErrDesync)
		}
	}
	out.Text = text
	out.Invalid = invalidOutput(text)
	out.Incomplete = out.Incomplete || errors.Is(err, platform.ErrConfirmPrompt)
	return out, err
}

// Respuestas de error de IOS («% Invalid input») y de NX-OS («% Invalid command», «% Invalid parameter», «% Incomplete command»).
var invalidMarks = []string{"% Invalid input", "% Invalid command", "% Invalid parameter", "% Incomplete command"}

// invalidOutput mira solo las primeras 3 líneas (el error de un comando va al inicio, tras el eco y el «^»): una
// running-config o un log que cite la frase más abajo no es un comando inválido.
func invalidOutput(text string) bool {
	head := strings.Join(strings.SplitN(text, "\n", 4)[:min(3, strings.Count(text, "\n")+1)], "\n")
	for _, m := range invalidMarks {
		if strings.Contains(head, m) {
			return true
		}
	}
	return false
}

// hasPercentLine: alguna línea de text empieza por «%» o «ERROR: %» (el equipo rechazó el comando).
func hasPercentLine(text string) bool {
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "%") || strings.HasPrefix(l, "ERROR: %") { // el segundo es la forma de ASA
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

// asa busca la cabecera de show version de ASA al inicio de línea; un IOS que diga «Adaptive Security» en texto libre no cuenta.
// ftd: línea «Model : Cisco … Threat Defense» (Firepower, Secure Firewall, «Cisco Firepower 1120», «Cisco ASA5508-X», «Cisco ISA 3000»). Un ASA real no trae «Model :» seguido de Cisco.
var ftd = regexp.MustCompile(`(?m)^Model\s*:\s*Cisco .*Threat Defense`)

// ise: show version de ISE (ADE-OS): cabecera del sistema y, más abajo, la aplicación; ambas al inicio de línea.
var (
	adeOS  = regexp.MustCompile(`(?m)^Cisco Application Deployment Engine OS Release`)
	iseApp = regexp.MustCompile(`(?m)^Cisco Identity Services Engine`)
)

var asa = regexp.MustCompile(`(?m)^Cisco Adaptive Security Appliance Software Version`)

// serialRe: «System serial number» (cada miembro de un stack), «Processor board ID» (IOS, IOS-XE, NX-OS), «Serial Number:»
// (ASA) y el UUID de FTD.
var serialRe = regexp.MustCompile(`(?im)^\s*(?:System serial number\s*:|Processor board ID\s|Serial Number\s*:|UUID\s*:)\s*(\S+)`)

// parseSerials da las series de un show version, sin duplicados y ordenadas; nil si no trae ninguna.
func parseSerials(text string) []string {
	var out []string
	for _, m := range serialRe.FindAllStringSubmatch(text, -1) {
		out = append(out, m[1])
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Serials son las series que vio Detect (vacío si no trae ninguna): la identidad del equipo, a diferencia del prompt, que
// un par en failover repite y un clúster cambia de unidad a unidad.
func (d *driver) Serials() []string { return d.serials }

func (d *driver) Detect(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, maxDetect)
	defer cancel()
	if d.aire { // AireOS no tiene «show version» («Incorrect usage»): se identifica con show sysinfo
		out, err := d.Run(ctx, "show sysinfo", 60*time.Second)
		if err != nil {
			return "", err
		}
		if aireSysinfo.MatchString(out.Text) {
			return "wlc-aireos", nil
		}
		return "", platform.ErrUnknownPlatform
	}
	out, err := d.Run(ctx, "show version", 60*time.Second)
	if err != nil {
		return "", err
	}
	d.serials = parseSerials(out.Text)
	switch {
	case adeOS.MatchString(out.Text) && iseApp.MatchString(out.Text): // ADE-OS de otro producto no es ISE
		return "ise", nil
	case ftd.MatchString(out.Text): // antes que asa: la salida de FTD puede citar la versión de lina
		return "ftd", nil
	case asa.MatchString(out.Text):
		return "asa", nil
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
		// Cualquier otro «% texto» es un error de IOS que la lista cerrada no conoce (falla cerrado): solo los avisos
		// conocidos pasan. Con o sin espacio tras el «%» («%VTP VLAN configuration not allowed…» también es un error); solo el syslog
		// («%LINK-3-UPDOWN: …») no entra aquí.
		if strings.HasPrefix(l, "%") && !syslogLine.MatchString(l) && !infoPercent.MatchString(l) {
			return true
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
