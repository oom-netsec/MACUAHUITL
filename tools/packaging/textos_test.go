package packaging

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/analyze"
)

func leer(t *testing.T, partes ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{repoRoot()}, partes...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// Lo que el usuario ve al instalar va en inglés (lengua canónica); los comentarios siguen en español.
// shortcut: busca letras del español, así que una frase sin tildes pasa; basta mientras los textos sean estos pocos.
func TestTextosDelPaqueteEnIngles(t *testing.T) {
	nfpm := leer(t, "deploy", "packaging", "nfpm.yaml")
	_, desc, _ := strings.Cut(nfpm, "description: |\n")
	desc, _, _ = strings.Cut(desc, "\nvendor:")
	post := leer(t, "deploy", "packaging", "postinstall.sh")
	_, msg, _ := strings.Cut(post, "<<'MSG'\n")
	msg, _, _ = strings.Cut(msg, "\nMSG")
	visibles := map[string]string{
		"nfpm.yaml description": desc,
		"postinstall.sh":        msg,
		"macuahuitl.desktop":    "",
		"macuahuitld.service":   "",
	}
	// Las claves traducidas (Comment[es]=…) sí pueden ir en español.
	traducida := regexp.MustCompile(`^\s*[A-Za-z]+\[[a-zA-Z_@]+\]\s*=`)
	for _, l := range strings.Split(leer(t, "deploy", "packaging", "macuahuitl.desktop"), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") && !traducida.MatchString(l) {
			visibles["macuahuitl.desktop"] += l + "\n"
		}
	}
	for _, m := range regexp.MustCompile(`(?m)^\s*Description\s*=(.*)$`).FindAllStringSubmatch(leer(t, "deploy", "systemd", "macuahuitld.service"), -1) {
		visibles["macuahuitld.service"] += m[1]
	}
	espanol := regexp.MustCompile(`[áéíóúñÁÉÍÓÚÑ¿¡]`)
	for donde, txt := range visibles {
		if strings.TrimSpace(txt) == "" {
			t.Errorf("%s: no se encontró el texto", donde)
		}
		if m := espanol.FindString(txt); m != "" {
			t.Errorf("%s lleva texto en español (%q):\n%s", donde, m, txt)
		}
	}
}

// La tabla de plataformas del README cuenta los playbooks que trae cada paquete de packs/.
func TestReadmeCuentaPlaybooksDePacks(t *testing.T) {
	fila := regexp.MustCompile("(?m)^\\|[^|]+\\| `oom/([a-z0-9-]+)` \\| (\\d+) \\|")
	filas := fila.FindAllStringSubmatch(leer(t, "README.md"), -1)
	dirs, _ := filepath.Glob(filepath.Join(repoRoot(), "packs", "*", "manifest.yaml"))
	faltan := map[string]bool{}
	for _, d := range dirs {
		faltan[filepath.Base(filepath.Dir(d))] = true
	}
	for _, f := range filas {
		if !faltan[f[1]] {
			t.Errorf("README: oom/%s repetido o sin carpeta en packs/", f[1])
		}
		delete(faltan, f[1])
	}
	for d := range faltan {
		t.Errorf("README: falta la fila de oom/%s", d)
	}
	for _, f := range filas {
		pbs, _ := filepath.Glob(filepath.Join(repoRoot(), "packs", f[1], "playbooks", "*.yaml"))
		if n, _ := strconv.Atoi(f[2]); n != len(pbs) {
			t.Errorf("README dice %d playbooks en oom/%s; packs/%s/playbooks trae %d", n, f[1], f[1], len(pbs))
		}
	}
}

// El README (tabla y texto alternativo de bento.jpg) y el roadmap dicen cuántas reglas de análisis trae el núcleo; render.cjs
// dibuja en la imagen las que cuenta con «^- id:», así que ese conteo también tiene que dar lo mismo.
func TestReadmeCuentaReglas(t *testing.T) {
	rules, err := analyze.DefaultRules()
	if err != nil {
		t.Fatal(err)
	}
	yamls, _ := filepath.Glob(filepath.Join(repoRoot(), "internal", "analyze", "rules", "*.yaml"))
	ids := 0
	for _, y := range yamls {
		raw, _ := os.ReadFile(y)
		ids += len(regexp.MustCompile(`(?m)^- id:`).FindAll(raw, -1))
	}
	if ids != len(rules) {
		t.Errorf("render.cjs contaría %d reglas con «^- id:» y el núcleo trae %d: ajusta su conteo", ids, len(rules))
	}
	for _, c := range []struct{ file, re string }{
		{"README.md", `\b(\d+) analysis rules\b`},
		{"README.md", `\b(\d+) rules over\b`},
		{filepath.Join("docs", "roadmap.md"), `\b(\d+) reglas\b`},
	} {
		ms := regexp.MustCompile(c.re).FindAllStringSubmatch(leer(t, c.file), -1)
		if len(ms) == 0 {
			t.Errorf("%s: no encontré %s", c.file, c.re)
		}
		for _, m := range ms {
			if m[1] != fmt.Sprint(len(rules)) {
				t.Errorf("%s dice %q y el núcleo trae %d reglas (regenera bento.jpg con docs/assets/pro/src/render.cjs)", c.file, m[0], len(rules))
			}
		}
	}
}
