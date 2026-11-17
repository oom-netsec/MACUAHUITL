package ci

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// Los binarios publicados no traen el paquete testing: el vigía de la base (internal/store/store_watch.go) va detrás
// del build tag storewatch, que solo usan CI y ./dev.sh test.
func TestBinariosSinTesting(t *testing.T) {
	for _, goos := range []string{"", "windows"} {
		cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./cmd/macuahuitld", "./cmd/mctl")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
		if goos != "" {
			cmd.Env = append(cmd.Env, "GOOS="+goos)
		}
		cmd.Dir = "../.."
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list (GOOS %q): %v", goos, err)
		}
		if pkgs := strings.Fields(string(out)); slices.Contains(pkgs, "testing") {
			t.Errorf("macuahuitld o mctl (GOOS %q) dependen del paquete testing", goos)
		}
	}
}
