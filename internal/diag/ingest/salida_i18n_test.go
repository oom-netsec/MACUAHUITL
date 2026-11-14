package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// El fallo del disco al preparar la salida conserva su texto es y con en no deja palabras en español.
func TestErroresDeSalidaEsEn(t *testing.T) {
	f := filepath.Join(t.TempDir(), "archivo")
	os.WriteFile(f, nil, 0o600)
	_, err := NewWriter(Sink{Dir: filepath.Join(f, "sub"), Template: "t"}, time.Now)
	if err == nil || !strings.HasPrefix(err.Error(), "carpeta de salida: ") {
		t.Fatalf("es: %v", err)
	}
	if en := i18n.English(err); !strings.HasPrefix(en, "output folder: ") || strings.Contains(en, "carpeta") {
		t.Errorf("en: %q", en)
	}
}
