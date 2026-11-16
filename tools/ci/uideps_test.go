package ci

import (
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
	for _, tags := range []string{"", "wails"} {
		args := []string{"list", "-e", "-deps", "-f", "{{.ImportPath}}"}
		if tags != "" {
			args = append(args, "-tags", tags)
		}
		cmd := exec.Command("go", append(args, "./ui/...")...)
		cmd.Dir = "../.." // -e: sin frontend/dist compilado, el embed de ui falla, pero el listado de dependencias sigue
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list (tags %q): %v", tags, err)
		}
		pkgs := strings.Fields(string(out))
		if len(pkgs) < 50 {
			t.Fatalf("go list (tags %q) devolvió solo %d paquetes: no se está mirando la UI", tags, len(pkgs))
		}
		if slices.Contains(pkgs, secretPkg) {
			t.Errorf("./ui (tags %q) depende de %s: memguard haría panic sin EnsureLockQuota", tags, secretPkg)
		}
	}
}
