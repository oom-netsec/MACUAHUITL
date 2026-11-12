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
	if len(w) != 2 || !strings.Contains(w[0], "/dev/sda3") || !strings.Contains(w[1], "/swap.img") {
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
	if w := mlockWarning(8 << 20); w == "" || !strings.Contains(w, "LimitMEMLOCK") {
		t.Fatalf("finite limit should skip mlockall with a warning, got %q", w)
	}
}
