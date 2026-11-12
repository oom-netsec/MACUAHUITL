package packaging

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repoRoot() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..")
}

func run(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func sha(t *testing.T, p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// build compila el núcleo y la CLI con las banderas reproducibles del release.
func build(t *testing.T, out, version string) {
	t.Helper()
	ld := "-s -w -buildid= -X github.com/oom-netsec/MACUAHUITL/internal/version.Version=" + version
	run(t, repoRoot(), []string{"CGO_ENABLED=0"}, "go", "build", "-trimpath", "-buildvcs=false", "-ldflags", ld, "-o", out+"/", "./cmd/macuahuitld", "./cmd/mctl")
}

func TestReproducibleAndPackaged(t *testing.T) {
	if testing.Short() {
		t.Skip("compila dos veces y empaqueta")
	}
	for _, bin := range []string{"nfpm", "dpkg-deb"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s no está instalado", bin)
		}
	}
	// nfpm lee bin/ relativo al repo (es la carpeta de build, ignorada por git).
	a, b := filepath.Join(repoRoot(), "bin"), t.TempDir()
	os.MkdirAll(a, 0o755)
	build(t, a, "v9.9.9")
	build(t, b, "v9.9.9")
	for _, name := range []string{"macuahuitld", "mctl"} {
		if sha(t, filepath.Join(a, name)) != sha(t, filepath.Join(b, name)) {
			t.Fatalf("%s no es reproducible", name)
		}
	}
	if v := run(t, a, nil, filepath.Join(a, "mctl"), "--version"); strings.TrimSpace(v) != "macuahuitl v9.9.9" {
		t.Fatalf("--version = %q", v)
	}
	// La UI real necesita WebKitGTK; para el paquete basta un ejecutable con ese nombre.
	os.WriteFile(filepath.Join(a, "macuahuitl"), []byte("#!/bin/sh\necho ui\n"), 0o755)

	pkgDir := t.TempDir()
	run(t, repoRoot(), []string{"VERSION=9.9.9"}, "nfpm", "package", "-p", "deb", "-f", "deploy/packaging/nfpm.yaml", "-t", pkgDir)
	debs, _ := filepath.Glob(filepath.Join(pkgDir, "*.deb"))
	if len(debs) != 1 {
		t.Fatalf("debs = %v", debs)
	}
	contents := run(t, "", nil, "dpkg-deb", "-c", debs[0])
	for _, want := range []string{"./usr/bin/macuahuitld", "./usr/bin/mctl", "./usr/bin/macuahuitl", "./usr/lib/systemd/user/macuahuitld.service",
		"./usr/share/applications/macuahuitl.desktop", "./usr/share/icons/hicolor/scalable/apps/macuahuitl.svg", "./usr/share/icons/hicolor/48x48/apps/macuahuitl.png", "./usr/share/doc/macuahuitl/LICENSE", "./usr/share/doc/macuahuitl/AUDIT_GUIDE.md"} {
		if !strings.Contains(contents, want) {
			t.Errorf("el .deb no trae %s", want)
		}
	}
	if !strings.Contains(contents, "-rwxr-xr-x") {
		t.Error("binarios sin permiso de ejecución")
	}
	fields := run(t, "", nil, "dpkg-deb", "-f", debs[0], "Version", "Recommends", "Depends", "Package", "Homepage")
	// .deb no lleva License en control; va en /usr/share/doc.
	for _, want := range []string{"Version: 9.9.9", "Package: macuahuitl", "nmap", "iperf3", "wireshark-common", "libwebkit2gtk-4.1-0", "github.com/oom-netsec/MACUAHUITL"} {
		if !strings.Contains(fields, want) {
			t.Errorf("control sin %q:\n%s", want, fields)
		}
	}
}
