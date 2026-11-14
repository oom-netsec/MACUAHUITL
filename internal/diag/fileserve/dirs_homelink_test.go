package fileserve

import (
	"os"
	"path/filepath"
	"testing"
)

// Con $HOME bajo un enlace (/home -> /var/home) la ruta real elegida también cae en las carpetas sensibles.
func TestValidateDirHomeEsEnlace(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	for _, d := range []string{".config/autostart", "bin"} {
		if err := os.MkdirAll(filepath.Join(real, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(base, "enlace")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", link)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	for _, d := range []string{".config/autostart", "bin"} {
		if _, err := ValidateDir(filepath.Join(real, d)); err == nil {
			t.Errorf("%s bajo el $HOME real debió rechazarse", d)
		}
	}
}
