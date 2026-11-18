package service

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// En Windows «/» también separa: C:\a/../b lleva «..» aunque no lo separe una «\».
func TestCheckOutputsWindowsPuntoPuntoConBarraNormal(t *testing.T) {
	base := t.TempDir()
	for _, dir := range []string{base + `/../x`, base + `\..\x`, filepath.Join(base, "a") + `/..`} {
		_, err := CheckOutputs(dir, NewCoreSettings("fabrica", t.TempDir()), true)
		var e *i18n.Error
		if !errors.As(err, &e) || e.Code != "prefs.outputs.punto_punto" {
			t.Errorf("%q: %v", dir, err)
		}
	}
}
