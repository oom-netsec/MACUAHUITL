package visibility

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"

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

func TestVisibilityHoraConZona(t *testing.T) {
	old := i18n.DisplayZone
	i18n.DisplayZone = time.FixedZone("CST", -6*3600)
	defer func() { i18n.DisplayZone = old }()
	var out bytes.Buffer
	c := &cli.Env{Out: &out}
	printSample(c, `{"Time":"2026-11-18T04:13:09Z","System":{"sysName":"sw1"}}`)
	if !strings.Contains(out.String(), "== 2026-11-17 22:13:09 CST sw1") {
		t.Errorf("sample: %q", out.String())
	}
	out.Reset()
	printFlows(c, `{}`, false)
	if !regexp.MustCompile(`\d{4}-\d\d-\d\d \d\d:\d\d:\d\d CST`).MatchString(out.String()) {
		t.Errorf("flows: %q", out.String())
	}
}
