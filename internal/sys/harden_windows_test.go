package sys

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestNoDumpFijaErrorMode(t *testing.T) {
	prev := windows.SetErrorMode(0)
	defer windows.SetErrorMode(prev)
	NoDump()
	got := windows.SetErrorMode(0)
	if got&errorMode != errorMode {
		t.Fatalf("modo de error %#x sin SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX", got)
	}
}
