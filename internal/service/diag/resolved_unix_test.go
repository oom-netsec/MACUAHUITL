//go:build unix

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

func TestRunNombreInvalidoNoResuelve(t *testing.T) {
	for _, n := range []string{"a_b.example", "-c", "x\nAUDIT forged"} {
		llamado := false
		old := resolve.Lookup
		resolve.Lookup = func(context.Context, string, string) ([]netip.Addr, error) { llamado = true; return nil, nil }
		d := servicetest.New(t)
		st := &eventos{fakeRun: fakeRun{ctx: context.Background()}}
		err := (&diagSvc{d: d}).Run(&v1.RunRequest{Tool: v1.DiagTool_DIAG_TOOL_PING, Targets: []*v1.Target{{Address: n}}}, st)
		resolve.Lookup = old
		if err == nil || llamado {
			t.Errorf("%q: err=%v lookup llamado=%v", n, err, llamado)
		}
	}
}

func TestRunAuditaResolvedCitado(t *testing.T) {
	ok := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	old := resolve.Lookup
	resolve.Lookup = ok
	defer func() { resolve.Lookup = old }()
	bin := filepath.Join(t.TempDir(), "x")
	os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755)
	d := servicetest.New(t)
	d.Look = func(string) (string, error) { return bin, nil }
	st := &eventos{fakeRun: fakeRun{ctx: context.Background()}}
	if err := (&diagSvc{d: d}).Run(&v1.RunRequest{Tool: v1.DiagTool_DIAG_TOOL_PING, Targets: []*v1.Target{{Address: "sw1.example"}}}, st); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.AuditText(), `resolved=\"sw1.example\"→192.0.2.1`) {
		t.Errorf("auditoría sin resolved citado: %s", d.AuditText())
	}
}

func TestRunTracerouteLinuxPrefiereV4(t *testing.T) {
	dual := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1")}, nil
	}
	if r := corre(t, v1.DiagTool_DIAG_TOOL_TRACEROUTE, "sw1.example", dual).ev[0].GetResolved(); r.GetIp() != "192.0.2.1" {
		t.Errorf("traceroute con doble pila: %v", r)
	}
}
