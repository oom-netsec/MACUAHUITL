package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
)

type langCase struct {
	name   string
	args   []string
	es, en string // texto que debe salir (salida o error) en cada idioma
}

// runLang corre cada caso sin --lang (es, texto de siempre) y con --lang en, y busca el texto en la salida o el error.
func runLang(t *testing.T, cases []langCase) {
	t.Helper()
	t.Cleanup(func() { cli.SetLang("") })
	for _, tc := range cases {
		for _, l := range []struct {
			pre  []string
			want string
		}{{nil, tc.es}, {[]string{"--lang", "en"}, tc.en}} {
			out, err := mctl(t, "", append(append([]string{}, l.pre...), tc.args...)...)
			got := out
			if err != nil {
				got += "\n" + err.Error()
			}
			if !strings.Contains(got, l.want) {
				t.Errorf("%s %v: falta %q en %q", tc.name, l.pre, l.want, got)
			}
		}
	}
}

func TestIdiomaPatrolPackBackup(t *testing.T) {
	startCore(t)
	dir := t.TempDir()
	job := filepath.Join(dir, "job.yaml")
	os.WriteFile(job, []byte("{}\n"), 0o600)
	packID := strings.Fields(must(t, "", "pack", "list"))[0]
	runLang(t, []langCase{
		{"param", []string{"job", "create", "-f", job, "--param", "a"}, `--param "a": use nombre=valor`, `--param "a": use name=value`},
		{"param dup", []string{"job", "create", "-f", job, "--param", "a=1", "--param", "a=2"}, `--param "a" repetido`, `--param "a" given more than once`},
		{"arm", []string{"job", "arm"}, "job arm necesita un ID", "job arm needs an ID"},
		{"playbooks", []string{"playbooks"}, " comandos", " commands"},
		{"pack list", []string{"pack", "list"}, "oficial", "official"},
		{"pack show", []string{"pack", "show", packID}, "núcleo mínimo:", "minimum core:"},
		{"backup puerto", []string{"backup", "run", "-d", "host:abc", "--cred", "x"}, `puerto inválido en "host:abc"`, `invalid port in "host:abc"`},
		{"backup id", []string{"backup", "diff", "foo", "--now", "-d", "h", "--cred", "x"}, `identificador "foo" inválido`, `invalid identifier "foo"`},
		{"adhoc puerto", []string{"run", "-d", "host:abc", "--cred", "x", "-c", "show version"}, `puerto inválido en "host:abc"`, `invalid port in "host:abc"`},
		{"restore", []string{"restore", "diff", "10.0.0.1", "id", "--cred", "x", "--max-lines", "2000"}, "--max-lines va de 1 a 1000", "--max-lines must be between 1 and 1000"},
	})
}

func TestIdiomaFieldDiagAclAnalysisAudit(t *testing.T) {
	startCore(t)
	dir := t.TempDir()
	img := filepath.Join(dir, "img.bin")
	os.WriteFile(img, []byte("x"), 0o600)
	edge := filepath.Join(dir, "edge.txt")
	os.WriteFile(edge, []byte("access-list EDGE extended permit tcp 10.0.0.0 255.255.255.0 any eq 22\naccess-list EDGE extended deny tcp host 10.0.0.5 any eq 22\n"), 0o600)
	runLang(t, []langCase{
		{"hash", []string{"hash", img, "--md5", strings.Repeat("0", 32)}, "el resumen no coincide con el publicado", "the digest does not match the published one"},
		{"diag interfaces", []string{"diag", "interfaces"}, "  arriba  ", "  up  "},
		{"diag opción", []string{"diag", "ping", "10.0.0.1", "-o", "mal"}, `opción "mal": usa clave=valor`, `option "mal": use key=value`},
		{"acl banderas", []string{"acl", "convert"}, "faltan --vendor/--from y -f", "--vendor/--from and -f are required"},
		{"acl regla", []string{"acl", "analyze", "--vendor", "asa", "-f", edge}, "regla 2: sombreada", "rule 2: shadowed"},
		{"acl hallazgos", []string{"acl", "analyze", "--vendor", "asa", "-f", edge}, "1 hallazgos en EDGE", "1 finding in EDGE"},
		{"analysis around", []string{"timeline", "job1", "--around", "mal"}, "--around: usa RFC 3339", "--around: use RFC 3339"},
		{"audit", []string{"audit", "verify"}, "cadena íntegra; cabeza ", "chain intact; head "},
	})
}

func TestIdiomaCalcChangeCleanerCredForensicPrefs(t *testing.T) {
	startCore(t)
	dir := t.TempDir()
	in, out := filepath.Join(dir, "in.txt"), filepath.Join(dir, "out.txt")
	os.WriteFile(in, []byte("hostname r1\n"), 0o600)
	// «escrito» necesita un archivo nuevo en cada idioma.
	if got := must(t, "", "config", "clean", in, "-o", out); !strings.Contains(got, "escrito "+out) {
		t.Errorf("es: %q", got)
	}
	out2 := out + "2"
	if got := must(t, "", "--lang", "en", "config", "clean", in, "-o", out2); !strings.Contains(got, "written "+out2) {
		t.Errorf("en: %q", got)
	}
	runLang(t, []langCase{
		{"calc vlsm", []string{"calc", "vlsm", "10.0.0.0/24", "abc"}, `necesidad "abc" inválida`, `invalid requirement "abc"`},
		{"calc mtu", []string{"calc", "mtu", "--mtu", "-5"}, "MTU -5 inválida", "invalid MTU -5"},
		{"calc mss", []string{"calc", "tcp", "--mss", "-1"}, "MSS -1 inválido", "invalid MSS -1"},
		{"change id", []string{"change", "pre"}, "necesita el ID del cambio", "needs the change ID"},
		{"cleaner igual", []string{"config", "clean", in, "-o", in}, "la salida no puede ser el archivo de entrada", "the output cannot be the input file"},
		{"cleaner existe", []string{"config", "clean", in, "-o", out}, "no se escribe la salida (¿ya existe?)", "the output is not written (does it already exist?)"},
		{"cred rotate", []string{"cred", "rotate", "10.0.0.1", "--user", "u", "--cred", "c", "--generate"}, "--generate exige --update-cred", "--generate requires --update-cred"},
		{"forense", []string{"logs", "patterns"}, "elige una fuente:", "choose a source:"},
		{"prefs", []string{"prefs", "show"}, "carpeta de salidas:", "outputs folder:"},
	})
}
