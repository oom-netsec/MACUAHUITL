package sys

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// El runtime de Go pone estos bits al arrancar (preventErrorDialogs); NoDump no debe quitarlos. Con GOTRACEBACK=wer el
// runtime quita SEM_NOGPFAULTERRORBOX, así que la prueba se salta si esa variable vale «wer».
func TestNoDumpDejaElErrorModeDelRuntime(t *testing.T) {
	if os.Getenv("GOTRACEBACK") == "wer" {
		t.Skip("GOTRACEBACK=wer: el runtime quita SEM_NOGPFAULTERRORBOX")
	}
	const want = windows.SEM_FAILCRITICALERRORS | windows.SEM_NOGPFAULTERRORBOX | windows.SEM_NOOPENFILEERRORBOX
	get := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetErrorMode")
	NoDump()
	if got, _, _ := get.Call(); got&want != want {
		t.Fatalf("modo de error %#x sin FAILCRITICALERRORS|NOGPFAULTERRORBOX|NOOPENFILEERRORBOX", got)
	}
}
