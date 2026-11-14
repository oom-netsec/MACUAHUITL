package transport

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestErroresDeTransportConCodigo(t *testing.T) {
	err := (&Session{}).Resize(1, 1)
	if err == nil || err.Error() != "transport: sin shell abierto" || i18n.English(err) != "transport: no shell is open" {
		t.Errorf("shell: %v / %q", err, i18n.English(err))
	}
	p := filepath.Join(t.TempDir(), "known_hosts")
	os.WriteFile(p, []byte("host basura\n"), 0o600)
	k, _ := OpenKnownHosts(p)
	_, err = k.load()
	if !errors.Is(err, ErrKnownHosts) || err.Error() != "transport: known_hosts ilegible o dañado: línea 1" ||
		i18n.English(err) != "transport: known_hosts unreadable or damaged: line 1" {
		t.Errorf("línea: %v / %q", err, i18n.English(err))
	}
}
