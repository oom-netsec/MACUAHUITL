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
	}
	for _, l := range strings.Split(leer(t, "deploy", "packaging", "macuahuitl.desktop"), "\n") {
		if !strings.HasPrefix(l, "#") {
			visibles["macuahuitl.desktop"] += l + "\n"
		}
	}
	for _, l := range strings.Split(leer(t, "deploy", "systemd", "macuahuitld.service"), "\n") {
		if strings.HasPrefix(l, "Description=") {
			visibles["macuahuitld.service"] = l
		}
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
	if len(filas) == 0 || len(filas) != len(dirs) {
		t.Fatalf("README tiene %d filas de paquetes y packs/ tiene %d paquetes", len(filas), len(dirs))
	}
	for _, f := range filas {
		pbs, _ := filepath.Glob(filepath.Join(repoRoot(), "packs", f[1], "playbooks", "*.yaml"))
		if n, _ := strconv.Atoi(f[2]); n != len(pbs) {
			t.Errorf("README dice %d playbooks en oom/%s; packs/%s/playbooks trae %d", n, f[1], f[1], len(pbs))
		}
	}
}
