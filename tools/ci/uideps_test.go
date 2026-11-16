package ci

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

const secretPkg = "github.com/oom-netsec/MACUAHUITL/internal/secret"

// internal/secret sube el working set en init() (EnsureLockQuota) y memguard hace panic si VirtualLock falla; la UI no
// llama a EnsureLockQuota, así que no debe depender de internal/secret ni de lejos (ADR 0012, b). La bóveda y sus
// llaves viven solo en el núcleo: la UI habla con él por gRPC.
func TestLaUINoDependeDeSecret(t *testing.T) {
	// El panic de memguard es de Windows (VirtualLock): también se mira con GOOS=windows, donde una dependencia puede
	// entrar por un archivo _windows.go.
	for _, c := range []struct{ goos, tags string }{{"", ""}, {"", "wails"}, {"windows", ""}, {"windows", "wails"}} {
		tags := c.tags
		args := []string{"list", "-e", "-deps", "-f", "{{.ImportPath}}"}
		if tags != "" {
			args = append(args, "-tags", tags)
		}
		cmd := exec.Command("go", append(args, "./ui/...")...)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if c.goos != "" {
			cmd.Env = append(cmd.Env, "GOOS="+c.goos)
		}
		cmd.Dir = "../.." // -e: sin frontend/dist compilado, el embed de ui falla, pero el listado de dependencias sigue
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list (GOOS %q, tags %q): %v", c.goos, tags, err)
		}
		pkgs := strings.Fields(string(out))
		if len(pkgs) < 50 {
			t.Fatalf("go list (GOOS %q, tags %q) devolvió solo %d paquetes: no se está mirando la UI", c.goos, tags, len(pkgs))
		}
		if slices.Contains(pkgs, secretPkg) {
			t.Errorf("./ui (GOOS %q, tags %q) depende de %s: memguard haría panic sin EnsureLockQuota", c.goos, tags, secretPkg)
		}
	}
}
