package patrol

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestZipDeNoRegularTieneCodigo(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "sub"), 0o700)
	_, err := zipFiles(dir, "x", []string{"sub"}, false)
	if err == nil || err.Error() != "sub no es un archivo regular" || i18n.English(err) != "sub is not a regular file" {
		t.Fatalf("%v / %q", err, i18n.English(err))
	}
}
