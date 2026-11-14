package capture

import (
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestReadDirSinManifestTieneCodigo(t *testing.T) {
	dir := t.TempDir()
	_, err := ReadDir(dir)
	if err == nil || !strings.HasPrefix(err.Error(), "capture: "+dir+" no es una captura terminada de Patrol: ") {
		t.Fatalf("es: %v", err)
	}
	if got := i18n.English(err); !strings.HasPrefix(got, "capture: "+dir+" is not a finished Patrol capture: ") {
		t.Fatalf("en: %q", got)
	}
}
