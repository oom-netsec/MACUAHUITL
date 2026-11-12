package visibility

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	"github.com/oom-netsec/MACUAHUITL/internal/termcolor"
)

func TestOutputSanitizesDeviceText(t *testing.T) {
	js := `{"Time":"2026-01-01T00:00:00Z","System":{"sysName":"sw\u001b[2J"},"Interfaces":[{"Name":"Gi1\u001b]52;c;ZXZpbA==\u0007\u001b[2J x\ty","Oper":"up"}]}`
	for _, color := range []bool{false, true} {
		var buf bytes.Buffer
		c := &cli.Env{Out: cli.NewOut(&buf, color, termcolor.Lookup("p1"), false)}
		printSample(c, js)
		got := buf.String()
		if color {
			got = regexp.MustCompile(`\x1b\[[0-9;]*m`).ReplaceAllString(got, "") // solo el color propio
		}
		if strings.ContainsAny(got, "\x1b\a") || !strings.Contains(got, "Gi1 x\ty") {
			t.Fatalf("color=%v: salida con control: %q", color, got)
		}
	}
}
