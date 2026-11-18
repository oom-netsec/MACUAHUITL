package diag

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/resolve"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

type eventos struct {
	fakeRun
	ev []*v1.RunResponse
}

func (e *eventos) Send(r *v1.RunResponse) error { e.ev = append(e.ev, r); return nil }

func corre(t *testing.T, tool v1.DiagTool, target string, lookup func(context.Context, string, string) ([]netip.Addr, error)) *eventos {
	old := resolve.Lookup
	resolve.Lookup = lookup
	t.Cleanup(func() { resolve.Lookup = old })
	bin := filepath.Join(t.TempDir(), "x")
	os.WriteFile(bin, []byte("#!/bin/sh\necho \"$@\"\n"), 0o755)
	d := servicetest.New(t)
	d.Look = func(string) (string, error) { return bin, nil }
	st := &eventos{fakeRun: fakeRun{ctx: context.Background()}}
	if err := (&diagSvc{d: d}).Run(&v1.RunRequest{Tool: tool, Targets: []*v1.Target{{Address: target}}}, st); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestRunResolved(t *testing.T) {
	ok := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
	}
	st := corre(t, v1.DiagTool_DIAG_TOOL_TRACEROUTE, "sw1.example", ok)
	if r := st.ev[0].GetResolved(); st.ev[0].RunId == "" || r.GetName() != "sw1.example" || r.GetIp() != "2001:db8::1" || r.GetFamily() != "ipv6" {
		t.Errorf("primer evento: %v", st.ev[0])
	}
	lineas := ""
	for _, e := range st.ev {
		if e.GetResolved() != nil && e != st.ev[0] {
			t.Errorf("resolved solo va en el primero")
		}
		lineas += e.OutputLine
	}
	if strings.Contains(lineas, "sw1.example") || !strings.Contains(lineas, "2001:db8::1") {
		t.Errorf("la herramienta debía recibir la IP: %q", lineas)
	}
	// una IP: name = ip
	if r := corre(t, v1.DiagTool_DIAG_TOOL_PING, "192.0.2.5", ok).ev[0].GetResolved(); r.GetName() != "192.0.2.5" || r.GetIp() != "192.0.2.5" || r.GetFamily() != "ipv4" {
		t.Errorf("IP: %v", r)
	}
	// no resuelve: sin resolved y la herramienta recibe el nombre
	st = corre(t, v1.DiagTool_DIAG_TOOL_PING, "mdns.local", func(context.Context, string, string) ([]netip.Addr, error) { return nil, os.ErrNotExist })
	if st.ev[0].GetResolved() != nil {
		t.Errorf("no debía haber resolved")
	}
}
