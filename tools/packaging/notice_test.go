package packaging

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Toda biblioteca de JavaScript que va dentro de la app (de producción, también las transitivas) lleva su aviso en NOTICE.
func TestNoticeTraeDependenciasDeLaUI(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(), "ui", "frontend", "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Packages map[string]struct{ Dev, DevOptional, Optional bool }
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(repoRoot(), "NOTICE"))
	if err != nil {
		t.Fatal(err)
	}
	// Solo la lista de bibliotecas: en los textos de licencia salen palabras como "merge" o "copy".
	notice, _, ok := strings.Cut(string(raw), "Texto de la licencia MIT")
	if !ok {
		t.Fatal("NOTICE sin el texto de la licencia MIT")
	}
	n := 0
	for path, p := range lock.Packages {
		i := strings.LastIndex(path, "node_modules/")
		if i < 0 || p.Dev || p.DevOptional || p.Optional {
			continue
		}
		n++
		name := path[i+len("node_modules/"):]
		if !regexp.MustCompile(`(?m)(^|[\s,])` + regexp.QuoteMeta(name) + `([\s,]|$)`).MatchString(notice) {
			t.Errorf("NOTICE no menciona %s", name)
		}
	}
	if n == 0 {
		t.Fatal("package-lock.json sin dependencias de producción")
	}
}

// Go y todo módulo compilado en los binarios llevan su licencia en THIRD_PARTY_LICENSES (tools/packaging/third-party-licenses.sh).
func TestThirdPartyTraeModulosGo(t *testing.T) {
	licencias, err := os.ReadFile(filepath.Join(repoRoot(), "THIRD_PARTY_LICENSES"))
	if err != nil {
		t.Fatal(err)
	}
	// Solo stdout: go puede avisar por stderr (por ejemplo, descargas) y eso no son módulos.
	list := func(args ...string) string {
		cmd := exec.Command("go", append([]string{"list", "-deps", "-f", "{{with .Module}}{{if not .Main}}{{.Path}}{{end}}{{end}}"}, args...)...)
		cmd.Dir = repoRoot()
		cmd.Env = append(os.Environ(), "GOOS=linux")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list %v: %v", args, err)
		}
		return string(out)
	}
	// Cada sección (Go mismo y cada módulo) trae al menos un archivo de licencia, no solo su encabezado.
	trae := func(nombre string) bool {
		_, resto, ok := strings.Cut(string(licencias), "\n======== "+nombre+" ========\n")
		seccion, _, _ := strings.Cut(resto, "\n======== ")
		return ok && strings.Contains(seccion, "\n--- ")
	}
	if !trae("Go (runtime y biblioteca estándar)") {
		t.Error("THIRD_PARTY_LICENSES no trae la licencia de Go")
	}
	visto := map[string]bool{}
	for _, m := range strings.Fields(list("./cmd/...") + list("-tags", "wails gtk3", "./ui")) {
		if visto[m] {
			continue
		}
		visto[m] = true
		if !trae(m) {
			t.Errorf("THIRD_PARTY_LICENSES no trae %s: corre tools/packaging/third-party-licenses.sh", m)
		}
	}
	if len(visto) == 0 {
		t.Fatal("go list no devolvió módulos")
	}
}
