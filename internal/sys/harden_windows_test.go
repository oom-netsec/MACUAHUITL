package sys

import (
	"testing"

	"golang.org/x/sys/windows"
)

// El runtime de Go pone estos bits al arrancar (preventErrorDialogs); NoDump no debe quitarlos.
func TestNoDumpDejaElErrorModeDelRuntime(t *testing.T) {
	const want = windows.SEM_FAILCRITICALERRORS | windows.SEM_NOGPFAULTERRORBOX | windows.SEM_NOOPENFILEERRORBOX
	get := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetErrorMode")
	NoDump()
	if got, _, _ := get.Call(); got&want != want {
		t.Fatalf("modo de error %#x sin FAILCRITICALERRORS|NOGPFAULTERRORBOX|NOOPENFILEERRORBOX", got)
	}
}
