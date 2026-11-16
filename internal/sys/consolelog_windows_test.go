package sys_test

import (
	"path/filepath"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/sys"
	"github.com/oom-netsec/MACUAHUITL/internal/sys/systest"
)

// En Windows el registro nace con la DACL protegida (OpenNewPrivate), no con la ACL heredada de la carpeta.
func TestOpenLogNacePrivadoEnWindows(t *testing.T) {
	p := filepath.Join(t.TempDir(), "macuahuitld.log")
	f, err := sys.OpenLog(p, sys.LogMax)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	systest.Private(t, p, 0o600)
}
