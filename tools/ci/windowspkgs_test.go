package ci

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Todo paquete con pruebas (en Windows) debe estar en windows-pkgs.txt: sin « # motivo» corre go test en el job windows,
// con él queda solo en vet. Así un paquete nuevo no se queda fuera de Windows sin que nadie lo decida.
func TestWindowsPkgsCubreLosPaquetesConPruebas(t *testing.T) {
	cmd := exec.Command("go", "list", "-f", "{{.ImportPath}} {{len .TestGoFiles}} {{len .XTestGoFiles}}", "./...")
	cmd.Env = append(os.Environ(), "GOOS=windows", "CGO_ENABLED=0")
	cmd.Dir = "../.."
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	mod, err := exec.Command("go", "list", "-m").Output()
	if err != nil {
		t.Fatal(err)
	}
	prefix := strings.TrimSpace(string(mod))
	conPruebas, todos := map[string]bool{}, map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(l)
		rel := "./" + strings.TrimPrefix(strings.TrimPrefix(f[0], prefix), "/")
		todos[rel] = true
		if f[1] != "0" || f[2] != "0" {
			conPruebas[rel] = true
		}
	}
	fh, err := os.Open("windows-pkgs.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	listados := map[string]bool{}
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		p := strings.Fields(l)[0]
		listados[p] = true
		if !todos[p] {
			t.Errorf("windows-pkgs.txt lista %s, que no existe o no compila en Windows", p)
		}
	}
	for p := range conPruebas {
		if !listados[p] {
			t.Errorf("%s tiene pruebas y no está en tools/ci/windows-pkgs.txt: agrégalo (o con « # motivo» si solo pasa vet)", p)
		}
	}
}
