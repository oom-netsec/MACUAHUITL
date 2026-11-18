package diag

import (
	"errors"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Una opción desconocida lista las válidas de esa herramienta, en orden estable, en es y en.
func TestOpcionDesconocidaListaValidas(t *testing.T) {
	pingIfaces(t)
	for tool, keys := range validOptions {
		r := Request{Tool: tool, Targets: targetsFor(tool), Options: map[string]string{"zzz": "1"}, OutputDir: "/x"}
		if tool == Pcap {
			r.Options["interface"] = "eth0" // sin interfaz falla antes de revisar las claves
		}
		_, _, err := Build(r)
		var ie *i18n.Error
		if !errors.As(err, &ie) || ie.Code != "diag.err.option" {
			t.Fatalf("%s: se esperaba diag.err.option, llegó %v", tool, err)
		}
		want := strings.Join(keys, ", ")
		for _, loc := range []string{i18n.Es, i18n.En} {
			if got := ie.Localize(loc); !strings.Contains(got, want) || !strings.Contains(got, "zzz") {
				t.Errorf("%s/%s: %q no lista %q", tool, loc, got, want)
			}
		}
	}
}

// validOptions no se desincroniza: cada clave listada la lee buildPlan (nunca da «no existe»).
func TestOpcionesValidasLasLeeBuildPlan(t *testing.T) {
	pingIfaces(t)
	for tool, keys := range validOptions {
		for _, k := range keys {
			leida := false
			// iperf3: bind solo se lee en modo servidor, parallel/reverse/udp solo en cliente; basta una de las dos.
			for _, mode := range []string{"client", "server"} {
				o := map[string]string{k: "x", "mode": mode}
				if tool != Iperf3 {
					o = map[string]string{k: "x"}
				}
				_, _, err := Build(Request{Tool: tool, Targets: targetsFor(tool), Options: o, OutputDir: "/x"})
				var ie *i18n.Error
				leida = leida || !(errors.As(err, &ie) && ie.Code == "diag.err.option")
			}
			if !leida {
				t.Errorf("%s: la clave %q figura como válida pero buildPlan no la lee", tool, k)
			}
		}
	}
}

// tos en Windows falla y el error dice que es por Windows.
func TestTosEnWindowsMencionaWindows(t *testing.T) {
	pingIfaces(t)
	_, _, err := buildWindows(Request{Tool: Ping, Targets: []string{"192.0.2.1"}, Options: map[string]string{"tos": "184"}})
	var ie *i18n.Error
	if !errors.As(err, &ie) || ie.Code != "diag.err.opt_windows" {
		t.Fatalf("se esperaba diag.err.opt_windows, llegó %v", err)
	}
	for _, loc := range []string{i18n.Es, i18n.En} {
		if !strings.Contains(ie.Localize(loc), "Windows") {
			t.Errorf("%s: no menciona Windows: %q", loc, ie.Localize(loc))
		}
	}
}

func targetsFor(t Tool) []string {
	if t == Pcap {
		return nil
	}
	return []string{"192.0.2.1"}
}
