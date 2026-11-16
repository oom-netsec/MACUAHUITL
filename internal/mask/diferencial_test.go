package mask_test

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/syslogd"
	"github.com/oom-netsec/MACUAHUITL/internal/mask"
	"github.com/oom-netsec/MACUAHUITL/internal/mask/internal/ref065"
	"github.com/oom-netsec/MACUAHUITL/internal/terminal"
)

// Propiedad diferencial: la versión nueva solo puede tapar MÁS que la v0.6.5 congelada (ref065), nunca menos. Todo
// marcador Zq##### visible en la salida nueva tiene que verse también en la de ref065. Se corre por cada vía que
// repite un comando (Apply, Cmd, Stream, Typed, Prompted, syslogd y la terminal) con las mismas entradas.

type sesionRec interface {
	Input([]byte)
	Output([]byte)
	Close()
}

// impl: las vías de una versión del enmascarado.
type impl struct {
	apply    func(plat, text string) string
	cmd      func(plat, c string) string
	raw      func(raw string) string
	typed    func(plat, c string) string
	prompted func(plat, c, block string) string
	stream   func(plat, text string) string
	rec      func(w io.Writer, now func() time.Time) sesionRec
}

var nuevo = impl{
	apply: func(p, t string) string { o, _ := mask.Apply(p, t); return o },
	cmd:   mask.Cmd,
	raw:   func(r string) string { return string(syslogd.MaskRaw([]byte(r))) },
	typed: func(p, c string) string {
		st := mask.Stream{Platform: p}
		o, _ := mask.CutCommand("", c, st.Typed(c))
		return o
	},
	prompted: func(p, c, b string) string {
		st := mask.Stream{Platform: p}
		o, _ := mask.CutCommand(b, c, st.Prompted(c, b))
		return o
	},
	stream: func(p, t string) string {
		st := mask.Stream{Platform: p, MaxSkip: 50}
		var b strings.Builder
		for _, raw := range strings.SplitAfter(t, "\n") {
			if l, ok := st.Line(raw); ok {
				b.WriteString(l)
			}
		}
		return b.String()
	},
	rec: func(w io.Writer, now func() time.Time) sesionRec { return terminal.NewRecorder(w, now) },
}

var viejo = impl{
	apply: func(p, t string) string { o, _ := ref065.Apply(p, t); return o },
	cmd:   ref065.Cmd,
	raw:   func(r string) string { return string(ref065.MaskRaw([]byte(r))) },
	typed: func(p, c string) string {
		st := ref065.Stream{Platform: p}
		return st.Typed(c)
	},
	prompted: func(p, c, b string) string {
		st := ref065.Stream{Platform: p}
		return st.Prompted(c, b)
	},
	stream: func(p, t string) string {
		st := ref065.Stream{Platform: p, MaxSkip: 50}
		var b strings.Builder
		for _, raw := range strings.SplitAfter(t, "\n") {
			if l, ok := st.Line(raw); ok {
				b.WriteString(l)
			}
		}
		return b.String()
	},
	rec: func(w io.Writer, now func() time.Time) sesionRec { return ref065.NewRecorder(w, now) },
}

// ev: un trozo de la sesión: lo que teclea el ingeniero (in) o lo que devuelve el equipo.
type ev struct {
	in bool
	b  string
}

// guion arma una sesión de modo config: cada comando tecleado y su eco; con paste, todos pegados de una vez; con
// shifted, el eco llega desplazado («R1(config)#$cola»); con async, un syslog parte el eco.
func guion(prompt string, cmds []string, paste, shifted, async bool) []ev {
	echo := func(c string) string {
		switch {
		case shifted:
			return "$" + c[max(0, len(c)-40):]
		case async && len(c) > 8:
			return c[:len(c)/2] + "\r\n%SYS-5-CONFIG_I: Configured from console by vty0\r\n" + c[len(c)/2:]
		}
		return c
	}
	evs := []ev{{false, prompt}}
	if paste {
		evs = append(evs, ev{true, strings.Join(cmds, "\r") + "\r"})
		for _, c := range cmds {
			evs = append(evs, ev{false, echo(c) + "\r\n" + prompt})
		}
		return evs
	}
	for _, c := range cmds {
		evs = append(evs, ev{true, c + "\r"}, ev{false, echo(c) + "\r\n" + prompt})
	}
	return evs
}

// sesion corre el guion en una grabadora, partiendo cada trozo en pedazos al azar (semilla fija por caso).
func sesion(im impl, evs []ev, seed int64) string {
	var buf bytes.Buffer
	t0 := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	rec := im.rec(&buf, func() time.Time { return t0 })
	r := rand.New(rand.NewSource(seed))
	for _, e := range evs {
		for b := e.b; b != ""; {
			n := len(b)
			if r.Intn(3) > 0 {
				n = 1 + r.Intn(len(b))
			}
			if e.in {
				rec.Input([]byte(b[:n]))
			} else {
				rec.Output([]byte(b[:n]))
			}
			b = b[n:]
		}
	}
	rec.Close()
	return buf.String()
}

var prompts = []string{"R1(config)#", "R1(config-if)#", "SW1(config-line)#", "R1(config-server-tacacs)#", "fw(config)#", "ise/admin(config)#", "(Cisco Controller) config>"}

// via: un canal por el que un comando llega a un log. f recibe la implementación para poder correr la misma vía en
// las dos versiones.
type via struct {
	nombre string
	f      func(im impl, plat, c string) string
}

// sueltas: vías de una línea de configuración impresa, no de un comando: solo cuenta la propiedad diferencial.
var sueltas = map[string]bool{"Apply suelto": true, "Stream suelto": true}

func conSalto(c string) string { return c + "\n" }

var vias = []via{
	{"Typed", func(im impl, p, c string) string { return im.typed(p, c) }},
	{"Prompted línea", func(im impl, p, c string) string { return im.prompted(p, c, "line") }},
	{"Prompted tacacs", func(im impl, p, c string) string { return im.prompted(p, c, "tacacs") }},
	{"Cmd", func(im impl, p, c string) string { return im.cmd(p, c) }},
	{"Apply suelto", func(im impl, p, c string) string { return im.apply(p, conSalto(c)) }},
	{"Stream suelto", func(im impl, p, c string) string { return im.stream(p, conSalto(c)) }},
	{"CFGLOG", func(im impl, p, c string) string {
		return im.apply(p, "%PARSER-5-CFGLOG_LOGGEDCMD: User:bob  logged command:"+c+"\n")
	}},
	{"archive log", func(im impl, p, c string) string { return im.apply(p, "  7     3    bob@vty0   |  "+c+"\n") }},
	{"accounting", func(im impl, p, c string) string {
		return im.apply(p, "Sun Nov 15 10:00:00 2026:type=update:id=10.1.1.1@pts/0:user=admin:cmd=configure terminal ; "+c+" (SUCCESS)\n")
	}},
	{"ASA 111008", func(im impl, _, c string) string {
		return im.apply("asa", "%ASA-5-111008: User 'enable_15' executed the '"+c+"' command.\n")
	}},
	{"ASA 111010", func(im impl, _, c string) string {
		return im.apply("asa", "%ASA-5-111010: User 'bob', running 'CLI' from IP 10.1.1.1, executed '"+c+"'\n")
	}},
	{"ASA 111009", func(im impl, _, c string) string {
		return im.apply("asa", "%ASA-5-111009: User 'bob' executed cmd: "+c+"\n")
	}},
	{"CMD", func(im impl, p, c string) string {
		return im.apply(p, "CMD: '"+c+"' 10:00:00 UTC Sun Nov 15 2026\n")
	}},
	{"diff +", func(im impl, p, c string) string { return im.apply(p, "+"+c+"\n") }},
	{"diff - no", func(im impl, p, c string) string { return im.apply(p, "-no "+c+"\n") }},
	{"no CFGLOG", func(im impl, p, c string) string {
		return im.apply(p, "%PARSER-5-CFGLOG_LOGGEDCMD: User:bob  logged command:no "+c+"\n")
	}},
	{"show tech ASA", func(im impl, p, c string) string {
		return im.apply(p, "*** Output from config line 9, \""+c+"\"\n")
	}},
	{"ERROR comillas", func(im impl, p, c string) string { return im.apply(p, "ERROR: \""+c+"\"\n") }},
	{"ERROR comilla impar", func(im impl, p, c string) string { return im.apply(p, "ERROR: \""+c+"\n") }},
	{"syslog multilínea", func(im impl, _, c string) string {
		i := strings.IndexByte(c[len(c)/2:], ' ')
		if i < 0 {
			return im.raw("%PARSER-5-CFGLOG_LOGGEDCMD: User:bob  logged command:" + c)
		}
		i += len(c) / 2
		return im.raw("%PARSER-5-CFGLOG_LOGGEDCMD: User:bob  logged command:" + c[:i] + "\n" + c[i+1:])
	}},
	{"syslog ASA", func(im impl, _, c string) string {
		return im.raw("%ASA-5-111008: User 'enable_15' executed the '" + c + "' command.")
	}},
	{"terminal eco normal", func(im impl, _, c string) string {
		return sesion(im, guion("R1(config)#", []string{c}, false, false, false), 1)
	}},
	{"terminal eco desplazado", func(im impl, _, c string) string {
		return sesion(im, guion("R1(config)#", []string{c}, false, true, false), 2)
	}},
	{"terminal eco partido por syslog", func(im impl, _, c string) string {
		return sesion(im, guion("R1(config)#", []string{c}, false, false, true), 3)
	}},
	{"terminal pegado", func(im impl, _, c string) string {
		return sesion(im, guion("R1(config)#", []string{"interface Gi0/1", c, "exit"}, true, false, false), 4)
	}},
}

var marca = regexp.MustCompile(`Zq\d{5}`)

// marcas: los marcadores que se ven en s.
func marcas(s string) map[string]bool {
	m := map[string]bool{}
	for _, x := range marca.FindAllString(s, -1) {
		m[x] = true
	}
	return m
}

var (
	markerOK  = regexp.MustCompile(`<MASKED:[^<>]*>`)
	markerBad = regexp.MustCompile(`<MASKED:|MASKED:[^<>]*>`)
)

// bienFormada: tras quitar los <MASKED:…> completos no queda ningún resto de uno partido por un corte.
func bienFormada(s string) bool { return !markerBad.MatchString(markerOK.ReplaceAllString(s, "")) }

// fuzzCmd arma un comando al azar con vocabulario de secretos, tipos, algoritmos, separadores y comillas.
func fuzzCmd(r *rand.Rand, n int) string {
	voc := []string{"enable", "secret", "sec", "password", "pass", "key", "key-string", "community", "comm", "snmp-server", "snmp-s", "host", "ho",
		"username", "user", "u1", "auth", "priv", "md5", "sha", "sha256", "aes", "128", "0", "5", "7", "9", "level", "15", "RO", "RW", "peer",
		"10.1.1.1", "tacacs-server", "radius-server", "ntp", "authentication-key", "message-digest-key", "pre-shared-key", "local", "remote", ";", "|",
		"show", "no", "description", "token", "psk", "crypto", "isakmp", "address", "scp://a:%s@1.1.1.1/f", "\"two words\"", "'q'", `a\b`, "role", "network-admin",
		"timeout", "5", "version", "2c", "vrf", "MGMT", "lisp", "site", "dialer", "sntp", "macsec", "repository", "webauth", "group-policy"}
	k := 2 + r.Intn(9)
	var parts []string
	for i := 0; i < k; i++ {
		parts = append(parts, voc[r.Intn(len(voc))])
	}
	// un secreto sembrado en una posición cualquiera, con símbolos
	v := fmt.Sprintf("%sZq%05d%s", canalSimbolos[r.Intn(len(canalSimbolos))], n, canalSimbolos[r.Intn(len(canalSimbolos))])
	if r.Intn(4) == 0 { // una parte de los valores es una frase de varias palabras con palabras clave adentro
		kw := []string{"key", "password", "secret", "community", "text", "pass", "comm", "k"}
		v += fmt.Sprintf(" %s Zq%05d", kw[r.Intn(len(kw))], 50000+n)
		if r.Intn(2) == 0 {
			v += fmt.Sprintf(" %s Zq%05d", kw[r.Intn(len(kw))], 60000+n)
		}
	}
	pos := r.Intn(len(parts) + 1)
	parts = append(parts[:pos], append([]string{v}, parts[pos:]...)...)
	c := strings.Join(parts, " ")
	if strings.Contains(c, "%s") {
		c = fmt.Sprintf(c, v)
	}
	return c
}

// casosDif: las entradas de la propiedad diferencial: las plantillas de los dos generadores y comandos al azar.
func casosDif() (cmds, plats []string) {
	vueltas, azar := 3, 1500
	if raceOn { // ver raceOn
		vueltas, azar = 1, 0
	}
	cmds, plats = canalCasos(len(canalPlantillas) * vueltas)
	c2, p2 := gen2Casos()
	cmds, plats = append(cmds, c2...), append(plats, p2...)
	r := rand.New(rand.NewSource(77))
	pl := []string{"ios-xe", "nx-os", "asa", "ftd", "wlc-aireos", "ise", ""}
	for n := 0; n < azar; n++ {
		cmds, plats = append(cmds, fuzzCmd(r, 90000+n)), append(plats, pl[r.Intn(len(pl))])
	}
	return
}

func TestDiferencialNuevoNuncaMuestraMas(t *testing.T) {
	cmds, plats := casosDif()
	malos := 0
	for i, c := range cmds {
		for _, v := range vias {
			n, o := v.f(nuevo, plats[i], c), v.f(viejo, plats[i], c)
			ref := marcas(o)
			bad := !bienFormada(n)
			for m := range marcas(n) {
				bad = bad || !ref[m]
			}
			if bad {
				if malos++; malos <= 25 {
					t.Errorf("[%s] (%s)\n  entrada: %q\n  nueva:   %q\n  v0.6.5:  %q", v.nombre, plats[i], c, n, o)
				}
			}
		}
	}
	if malos > 25 {
		t.Errorf("%d violaciones en total", malos)
	}
}

// Sesiones de terminal de varias líneas, con pegado y troceo al azar: la grabación nueva no muestra más que la v0.6.5.
func TestDiferencialSesionesTerminal(t *testing.T) {
	cmds, plats := casosDif()
	r := rand.New(rand.NewSource(5))
	malos := 0
	for i := 0; i+3 < len(cmds); i += 3 {
		lote := []string{cmds[i], "interface Gi0/1", cmds[i+1], cmds[i+2]}
		if r.Intn(2) == 0 {
			lote[1], lote[3] = lote[3], lote[1]
		}
		evs := guion(prompts[r.Intn(len(prompts))], lote, r.Intn(2) == 0, r.Intn(4) == 0, r.Intn(4) == 0)
		seed := int64(i)
		n, o := sesion(nuevo, evs, seed), sesion(viejo, evs, seed)
		ref := marcas(o)
		bad := !bienFormada(n)
		for m := range marcas(n) {
			bad = bad || !ref[m]
		}
		if bad {
			if malos++; malos <= 15 {
				t.Errorf("(%s) %q\n  nueva:  %q\n  v0.6.5: %q", plats[i], lote, n, o)
			}
		}
	}
	if malos > 15 {
		t.Errorf("%d violaciones en total", malos)
	}
}

// Idempotencia: aplicar dos veces no cambia lo aplicado una.
func TestIdempotencia(t *testing.T) {
	cmds, plats := casosDif()
	envolturas := []string{"%s", "%%PARSER-5-CFGLOG_LOGGEDCMD: User:bob  logged command:%s", "ERROR: \"%s\"", "CMD: '%s' 10:00:00 UTC", "  7     3    bob@vty0   |  %s", "+%s"}
	malos := 0
	for i, c := range cmds {
		for _, w := range envolturas {
			in := fmt.Sprintf(strings.ReplaceAll(w, "%%", "\x00"), c)
			in = strings.ReplaceAll(in, "\x00", "%")
			a, _ := mask.Apply(plats[i], in+"\n")
			b, _ := mask.Apply(plats[i], a)
			if a != b {
				if malos++; malos <= 25 {
					t.Errorf("(%s)\n  entrada: %q\n  1.ª: %q\n  2.ª: %q", plats[i], in, a, b)
				}
			}
		}
	}
	if malos > 25 {
		t.Errorf("%d casos no idempotentes en total", malos)
	}
}

// Negativos: lo que no es un secreto no se tapa de más; la salida nueva es igual a la de la v0.6.5.
func TestNegativosIgualAV065(t *testing.T) {
	negativos := []string{
		"show running-config | section snmp", "show run | sec snmp", "show run | include password", "do show run | i key",
		"show crypto key mypubkey rsa", "sh run | sec community", "show snmp community",
		"route-map RM permit 10 ; set community 65000:100", "set community 65000:1 additive", "match community CL1", "route-map X ; match community 5",
		"spanning-tree vlan 1 priority 4096", "standby 1 priority 110", "standby 1 pri 110", "vrrp 1 priority 120", "stp pri 4096",
		"interface Tunnel0 ; tunnel key 5", "tunnel key 100", "tunnel source Gi0/1",
		"ntp server 10.1.1.1 key 5", "ntp peer 10.1.1.1 key 7", "ntp server 10.1.1.1 prefer key 3",
		"description password rotation due", "interface Gi0/1 description snmp community lab",
		"snmp-server group G v3 priv read V", "int te 1/0/1", "interface Te1/0/1",
		"show tech-support | include secret",
	}
	cit := []string{`ERROR: "Password mismatch for user bob"`, `ERROR: "password failed for bob"`, `%ERR: "secret expired for admin"`,
		`WARNING: "key changed on Gi0/1"`, `ERROR: "password will expire in 3 days"`, `INFO: "community is not configured"`,
		`ERROR: "key has been rotated"`, `ERROR: "password for user bob rejected"`, `ERROR: "secret from vty rejected"`,
		`Interface "outside" key exchange failed`}
	var malos []string
	for _, c := range negativos {
		for _, v := range vias {
			if n, o := v.f(nuevo, "ios-xe", c), v.f(viejo, "ios-xe", c); n != o {
				malos = append(malos, fmt.Sprintf("[%s] %q\n  nueva:  %q\n  v0.6.5: %q", v.nombre, c, n, o))
			}
		}
	}
	for _, l := range cit {
		if n, o := nuevo.apply("asa", l+"\n"), viejo.apply("asa", l+"\n"); n != o {
			malos = append(malos, fmt.Sprintf("prosa %q\n  nueva:  %q\n  v0.6.5: %q", l, n, o))
		}
	}
	for i, m := range malos {
		if i < 25 {
			t.Error(m)
		}
	}
	if len(malos) > 25 {
		t.Errorf("%d diferencias en total", len(malos))
	}
}
