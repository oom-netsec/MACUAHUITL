package diag

import (
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/diag"
)

// preferV4 conserva lo que cada herramienta habría elegido con el nombre.
func TestPreferV4(t *testing.T) {
	df := map[string]string{"df": "true"}
	for _, c := range []struct {
		tool diag.Tool
		goos string
		o    map[string]string
		want bool
	}{
		{diag.Traceroute, "linux", nil, true},    // traceroute de Linux prefiere IPv4
		{diag.Traceroute, "windows", nil, false}, // tracert: la primera tal cual
		{diag.Ping, "linux", nil, false},
		{diag.Ping, "linux", df, false},
		{diag.Ping, "windows", nil, false},
		{diag.Ping, "windows", df, true}, // ping.exe -f solo vale para IPv4
	} {
		if got := preferV4(c.tool, c.o, c.goos); got != c.want {
			t.Errorf("%s %s %v: %v, quería %v", c.tool, c.goos, c.o, got, c.want)
		}
	}
}
