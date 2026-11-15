package sys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, body string) string {
	p := filepath.Join(dir, name)
	os.MkdirAll(filepath.Dir(p), 0o700)
	os.WriteFile(p, []byte(body), 0o600)
	return p
}

func TestSwapWarnings(t *testing.T) {
	d := t.TempDir()
	swaps := write(t, d, "swaps", "Filename\tType\tSize\tUsed\tPriority\n/dev/zram0 partition 8G 0 100\n/dev/mapper/vg-swap partition 8G 0 -2\n/dev/sda3 partition 8G 0 -3\n/swap.img file 2G 0 -4\n")
	w := swapWarnings(swaps)
	if len(w) != 2 || !strings.Contains(w[0].In("en"), "/dev/sda3") || !strings.Contains(w[1].In("en"), "/swap.img") {
		t.Fatalf("warnings = %v", w)
	}
	if w := swapWarnings(write(t, d, "none", "Filename\tType\tSize\tUsed\tPriority\n")); len(w) != 0 {
		t.Fatalf("no swap should not warn: %v", w)
	}
	if w := swapWarnings(filepath.Join(d, "no-existe")); len(w) != 0 {
		t.Fatalf("missing /proc/swaps should not warn: %v", w)
	}
}

func TestHibernationWarning(t *testing.T) {
	d := t.TempDir()
	if w := hibernationWarnings(write(t, d, "a/resume", "0:0\n")); len(w) != 0 {
		t.Fatalf("no resume device should not warn: %v", w)
	}
	if w := hibernationWarnings(write(t, d, "b/resume", "259:3\n")); len(w) != 1 {
		t.Fatalf("resume device should warn: %v", w)
	}
}

func TestHardenSetsNotDumpable(t *testing.T) {
	Harden()
	if dumpable() != 0 {
		t.Fatal("process still dumpable")
	}
	if c := coreLimit(); c != 0 {
		t.Fatalf("RLIMIT_CORE = %d", c)
	}
}

func TestMlockSkippedWithFiniteLimit(t *testing.T) {
	if w := mlockWarning(8 << 20); w.Empty() || !strings.Contains(w.In("en"), "LimitMEMLOCK") {
		t.Fatalf("finite limit should skip mlockall with a warning, got %v", w)
	}
}

// El aviso de MEMLOCK sale completo en cada idioma, sin mezclar.
func TestMlockWarningIdiomas(t *testing.T) {
	w := mlockWarning(8 << 20)
	if got, want := w.In("en"), "RLIMIT_MEMLOCK is 8388608 bytes; not all memory is locked. raise it for the user manager with LimitMEMLOCK=infinity in /etc/systemd/system/user@.service.d/ (README, Install)"; got != want {
		t.Fatalf("en = %q", got)
	}
	if got, want := w.In("es"), "RLIMIT_MEMLOCK es de 8388608 bytes; no toda la memoria queda bloqueada. súbelo para el gestor de usuario con LimitMEMLOCK=infinity en /etc/systemd/system/user@.service.d/ (README, Install)"; got != want {
		t.Fatalf("es = %q", got)
	}
}
