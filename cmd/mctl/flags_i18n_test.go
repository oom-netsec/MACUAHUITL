package main

import (
	"bufio"
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// españolEnBandera son letras y palabras que no deben quedar en la descripción en inglés de una bandera.
var españolEnBandera = regexp.MustCompile(`(?i)[áéíóúñ¿¡]|\b(sin|ningún|equipo|equipos|tiene|puerto|las|los|del|una|con|por|para|según|línea|líneas|regla|reglas|salida|archivo|ruta|nombre|valor|por defecto|segundos|cada)\b`)

// subcomandos son las palabras de «uso: mctl <comando> a|b|c» (o «… listen [--x]»): los comandos que reparten por su
// tercera palabra (pki ca, snmp traps, scripts col) no se ven con «-h» solo.
func subcomandos(c cli.Command) (subs []string) {
	defer func() {
		if recover() != nil {
			subs = nil // un comando sin banderas usa la conexión con cualquier argumento
		}
	}()
	err := c.Run(&cli.Env{In: bufio.NewReader(strings.NewReader("")), Out: io.Discard}, nil)
	if err == nil {
		return nil
	}
	m := regexp.MustCompile(`uso: mctl ` + regexp.QuoteMeta(c.Name) + ` ([a-z][a-z0-9|-]*)`).FindStringSubmatch(err.Error())
	if m == nil {
		return nil
	}
	return strings.Split(m[1], "|")
}

// flagSets recorre los comandos reales de todas las áreas (las de main.go) y sus subcomandos con -h, sin conexión, y
// devuelve el FlagSet de cada uno. Un comando que toque la conexión antes de leer sus banderas hace fallar la prueba.
func flagSets(t *testing.T) map[string]*flag.FlagSet {
	t.Helper()
	got := map[string]*flag.FlagSet{}
	cli.FlagSetHook = func(name string, fs *flag.FlagSet) { got[name] = fs }
	cli.ResetHelp(io.Discard)
	t.Cleanup(func() { cli.FlagSetHook = nil; cli.ResetHelp(os.Stdout) })
	try := func(c cli.Command, args []string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("mctl %s %v: %v (¿usa la conexión antes de leer las banderas?)", c.Name, args, r)
			}
		}()
		_ = c.Run(&cli.Env{In: bufio.NewReader(strings.NewReader("")), Out: io.Discard}, args)
	}
	for _, a := range areas {
		for _, c := range a.Commands {
			try(c, []string{"-h"})
			for _, sub := range subcomandos(c) {
				try(c, []string{sub, "-h"})
			}
		}
	}
	return got
}

var flagsLiteral = regexp.MustCompile(`cli\.(?:Flags|NoFlags)\("([^"]+)",`)

// Todo cli.Flags con nombre literal de los fuentes de cmd/mctl se alcanza por el recorrido: nada se queda fuera.
func TestRecorridoAlcanzaTodosLosFlags(t *testing.T) {
	got := flagSets(t)
	if len(got) < 100 {
		t.Fatalf("solo %d comandos con banderas", len(got))
	}
	filepath.WalkDir(".", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		src, _ := os.ReadFile(p)
		for _, m := range flagsLiteral.FindAllStringSubmatch(string(src), -1) {
			if got[m[1]] == nil {
				t.Errorf("%s: cli.Flags(%q) no se alcanza con -h: el recorrido no ve ese subcomando", p, m[1])
			}
		}
		return nil
	})
}

// Toda bandera de todo comando tiene su descripción en inglés y en español en el catálogo, y la inglesa no deja español.
func TestBanderasConDescripcionEnAmbosIdiomas(t *testing.T) {
	var n int
	for name, fs := range flagSets(t) {
		fs.VisitAll(func(f *flag.Flag) {
			n++
			var en, es string
			for _, code := range []string{cli.FlagCode(name, f.Name), "mctl.flag." + f.Name} {
				if i18n.Msg(i18n.En, code, nil) != code {
					en, es = i18n.Msg(i18n.En, code, nil), i18n.Msg(i18n.Es, code, nil)
					break
				}
			}
			if en == "" || es == "" {
				t.Errorf("mctl %s --%s: falta la descripción en inglés o en español", name, f.Name)
				return
			}
			if m := españolEnBandera.FindString(en); m != "" {
				t.Errorf("mctl %s --%s: español en el inglés: %q (%s)", name, f.Name, en, m)
			}
		})
	}
	t.Logf("%d banderas", n)
}

// mctl <área> <cmd> -h (o --help, --help=false, -h=1, -h tras un argumento…) escribe las banderas con su descripción en
// el idioma de mctl, sale sin error, sin pánico, sin conectar al núcleo (aquí no hay socket) y sin tocar el disco.
func TestAyudaDeBanderasSigueElIdioma(t *testing.T) {
	for _, c := range []struct {
		cmd  []string
		en   string
		es   string
		flag string
	}{
		{[]string{"syslog", "listen"}, "listen address", "dirección de escucha", "-addr"},
		{[]string{"calc", "mtu"}, "physical IP MTU", "MTU IP física", "-mtu"},
		{[]string{"dns", "trace"}, "request DNSSEC records", "pide registros DNSSEC", "-dnssec"},
		{[]string{"pki", "ca", "init"}, "name of the CA", "nombre de la CA", "-name"},
		{[]string{"snmp", "traps", "listen"}, "listen address", "dirección de escucha", "-v3-cred"},
		{[]string{"scripts", "col", "list"}, "JSON output", "salida JSON", "-json"},
	} {
		for _, h := range [][]string{{"-h"}, {"--help"}, {"--help=false"}, {"-h=1"}, {"x", "-h"}} {
			t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
			dir := t.TempDir()
			t.Chdir(dir)
			args := append(append([]string{}, c.cmd...), h...)
			en, err := mctlRaw(t, "", args...)
			if err != nil || !strings.Contains(en, "usage: mctl "+strings.Join(c.cmd, " ")) || !strings.Contains(en, c.en) || !strings.Contains(en, c.flag) {
				t.Errorf("%v en: err=%v\n%s", args, err, en)
			}
			es, err := mctlRaw(t, "", append([]string{"--lang", "es"}, args...)...)
			if err != nil || !strings.Contains(es, "uso: mctl "+strings.Join(c.cmd, " ")) || !strings.Contains(es, c.es) {
				t.Errorf("%v es: err=%v\n%s", args, err, es)
			}
			if left, _ := os.ReadDir(dir); len(left) != 0 {
				t.Errorf("%v: -h dejó archivos en el disco: %v", args, left)
			}
		}
	}
}

// «--name -- -h»: --name se come el «--» como valor y -h sigue siendo la ayuda; no se crea la carpeta de la CA.
func TestAyudaConValorYDobleGuion(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	dir := t.TempDir()
	t.Chdir(dir)
	out, err := mctlRaw(t, "", "pki", "ca", "init", "--name", "--", "-h")
	if err != nil || !strings.Contains(out, "usage: mctl pki ca init") {
		t.Errorf("err=%v\n%s", err, out)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Errorf("-h dejó archivos: %v", left)
	}
}

// Un comando sin banderas también reconoce -h y --help: muestra su uso y no manda «-h» como argumento al núcleo.
func TestAyudaDeComandoSinBanderas(t *testing.T) {
	for _, cmd := range [][]string{{"pack", "show"}, {"pack", "remove"}, {"pack", "list"}, {"transfer", "list"}, {"ports", "resume"}} {
		for _, h := range []string{"-h", "--help"} {
			t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
			out, err := mctlRaw(t, "", append(append([]string{}, cmd...), h)...)
			if err != nil || !strings.Contains(out, "usage: mctl "+strings.Join(cmd, " ")) {
				t.Errorf("%v %s: err=%v\n%s", cmd, h, err, out)
			}
		}
	}
}

// Sin XDG_RUNTIME_DIR no hay socket: mctl da el error de conexión de siempre y no corre el comando (ni crea «ca-lab»).
func TestSinXDGNoCorreElComando(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	dir := t.TempDir()
	t.Chdir(dir)
	for _, args := range [][]string{{"pki", "ca", "init", "--name", "-h"}, {"calc", "mtu", "-h"}} {
		out, err := mctlRaw(t, "", args...)
		if err == nil || strings.Contains(out, "usage:") {
			t.Errorf("%v: err=%v\n%s", args, err, out)
		}
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Errorf("dejó archivos: %v", left)
	}
}
