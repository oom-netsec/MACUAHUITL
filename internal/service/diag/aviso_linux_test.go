package diag

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

type captura struct {
	fakeRun
	lines []string
}

func (c *captura) Send(r *v1.RunResponse) error {
	if r.OutputLine != "" {
		c.lines = append(c.lines, r.OutputLine)
	}
	return nil
}

// nmap simulado: imprime la línea final de -oG que se le pasa; Run debe avisar una sola vez.
func TestRunEnviaAvisoUnaVez(t *testing.T) {
	for _, c := range []struct {
		line string
		want int
	}{{cero, 1}, {uno, 0}} {
		bin := filepath.Join(t.TempDir(), "nmap")
		os.WriteFile(bin, []byte("#!/bin/sh\necho '"+c.line+"'\n"), 0o755)
		d := servicetest.New(t)
		d.Look = func(string) (string, error) { return bin, nil }
		st := &captura{fakeRun: fakeRun{ctx: context.Background()}}
		req := &v1.RunRequest{Tool: v1.DiagTool_DIAG_TOOL_NMAP, Targets: []*v1.Target{{Address: "192.0.2.1"}}}
		if err := (&diagSvc{d: d}).Run(req, st); err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, l := range st.lines {
			if strings.Contains(l, "skip_discovery") {
				n++
			}
		}
		if n != c.want {
			t.Errorf("%q: avisos %d, quería %d (%q)", c.line, n, c.want, st.lines)
		}
	}
}
