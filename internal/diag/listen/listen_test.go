package listen

import (
	"runtime"
	"testing"
)

func TestValidateAddr(t *testing.T) {
	privilegedPorts = true
	t.Cleanup(func() { privilegedPorts = runtime.GOOS != "windows" })
	for addr, ok := range map[string]bool{"127.0.0.1:1162": true, "127.0.0.1:0": true, "127.0.0.1:162": false, "0.0.0.0:1162": false,
		"[::]:2055": false, "localhost:1162": false, "127.0.0.1": false, "10.0.0.5:6343": true} {
		if err := ValidateAddr(addr, false); (err == nil) != ok {
			t.Errorf("%s: err = %v", addr, err)
		}
	}
	if err := ValidateAddr("0.0.0.0:1162", true); err != nil {
		t.Fatal(err)
	}
}

// ADR 0012 h: sin puertos privilegiados (Windows) se aceptan 69, 21 y 162; el 0 y las demás reglas siguen.
func TestValidateAddrSinPrivilegiados(t *testing.T) {
	privilegedPorts = false
	t.Cleanup(func() { privilegedPorts = runtime.GOOS != "windows" })
	for addr, ok := range map[string]bool{"127.0.0.1:162": true, "10.0.0.5:69": true, "10.0.0.5:21": true, "127.0.0.1:0": true,
		"0.0.0.0:162": false, "localhost:162": false, "127.0.0.1:70000": false} {
		if err := ValidateAddr(addr, false); (err == nil) != ok {
			t.Errorf("%s: err = %v", addr, err)
		}
	}
}
