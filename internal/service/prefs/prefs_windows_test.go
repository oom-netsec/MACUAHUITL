//go:build windows

package prefs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Una carpeta con ACL laxa (dentro del checkout, que hereda la escritura de Users) no se acepta como carpeta de
// salidas: SetCorePrefs pasa por CheckOutputs y sys.PrivateDir de verdad.
func TestOutputsConAclLaxaSeRechaza(t *testing.T) {
	s, d, _ := montar(t)
	laxa, err := os.MkdirTemp(".", "laxa-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(laxa) })
	if laxa, err = filepath.Abs(laxa); err != nil {
		t.Fatal(err)
	}
	err = fija(s, laxa)
	m := status.Convert(err).Message()
	r := reasonDe(err) // el motivo viaja en ErrorInfo y ya no va pegado al texto (43e-9)
	if status.Code(err) != codes.InvalidArgument || r != "prefs.outputs.permisos" && r != "prefs.outputs.ancestro_inseguro" || strings.Contains(m, "prefs.outputs.") {
		t.Fatalf("esperaba permisos o ancestro_inseguro, salió: %v", err)
	}
	if d.Outputs() == laxa {
		t.Fatal("la carpeta laxa quedó como salidas")
	}
}
