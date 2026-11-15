package packaging

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
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
