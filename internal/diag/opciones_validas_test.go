package diag

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// caso es una herramienta (y modo de iperf3) con lo mínimo para que buildPlan llegue a revisar las claves.
type caso struct {
	name string
	req  func(opts map[string]string) Request
}

func casos() []caso {
	mk := func(tool Tool, base map[string]string, targets ...string) func(map[string]string) Request {
		return func(o map[string]string) Request {
			m := map[string]string{}
			for k, v := range base {
				m[k] = v
			}
			for k, v := range o {
				m[k] = v
			}
			return Request{Tool: tool, Targets: targets, Options: m, OutputDir: "/x"}
		}
	}
	return []caso{
		{"ping", mk(Ping, nil, "192.0.2.1")},
		{"traceroute", mk(Traceroute, nil, "192.0.2.1")},
		{"nmap", mk(Nmap, nil, "192.0.2.1")},
		{"iperf3/client", mk(Iperf3, map[string]string{"mode": "client"}, "192.0.2.1")},
		{"iperf3/server", mk(Iperf3, map[string]string{"mode": "server", "bind": "192.0.2.9"})},
		{"pcap", mk(Pcap, map[string]string{"interface": pcapIface()})},
	}
}

func esOpcion(err error) (*i18n.Error, bool) {
	var ie *i18n.Error
	return ie, errors.As(err, &ie) && ie.Code == "diag.err.option"
}

// Una opción desconocida lista las válidas de esa herramienta y modo, en orden estable, en es y en.
func TestOpcionDesconocidaListaValidas(t *testing.T) {
	pingIfaces(t)
	for _, c := range casos() {
		_, _, err := Build(c.req(map[string]string{"zzz": "1"}))
		ie, ok := esOpcion(err)
		if !ok {
			t.Fatalf("%s: se esperaba diag.err.option, llegó %v", c.name, err)
		}
		want := strings.Join((&opts{tool: c.name, win: runtime.GOOS == "windows"}).validKeys(), ", ") // en Windows ping sin tos ni interval
		for _, loc := range []string{i18n.Es, i18n.En} {
			if got := ie.Localize(loc); !strings.Contains(got, want) || !strings.Contains(got, "zzz") {
				t.Errorf("%s/%s: %q no lista %q", c.name, loc, got, want)
			}
		}
	}
}

// iperf3 no se contradice: cada modo lista solo lo que lee, y lo del otro modo no figura.
func TestOpcionesIperf3SegunModo(t *testing.T) {
	pingIfaces(t)
	cs := map[string]caso{}
	for _, c := range casos() {
		cs[c.name] = c
	}
	for _, x := range []struct{ caso, key string }{{"iperf3/client", "bind"}, {"iperf3/server", "udp"}, {"iperf3/server", "parallel"}, {"iperf3/server", "reverse"}} {
		_, _, err := Build(cs[x.caso].req(map[string]string{x.key: "true"}))
		ie, ok := esOpcion(err)
		if !ok {
			t.Fatalf("%s %s: se esperaba diag.err.option, llegó %v", x.caso, x.key, err)
		}
		valid := fmt.Sprint(ie.Args["valid"])
		for _, k := range strings.Split(valid, ", ") {
			if k == x.key {
				t.Errorf("%s: dice que %q no existe pero lo lista como válido: %q", x.caso, x.key, valid)
			}
		}
	}
}

// Las claves listadas son exactamente las que buildPlan lee, en los dos sentidos.
func TestOpcionesValidasCoincidenConBuildPlan(t *testing.T) {
	pingIfaces(t)
	// sentido 1: todo lo listado se lee (con lo mínimo satisfecho, la clave nunca da «no existe»).
	for _, c := range casos() {
		for _, k := range validOptions[c.name] {
			_, _, err := Build(c.req(map[string]string{k: "x"}))
			if _, ok := esOpcion(err); ok {
				t.Errorf("%s: %q figura como válida pero buildPlan no la lee", c.name, k)
			}
		}
		if !sort.StringsAreSorted(validOptions[c.name]) {
			t.Errorf("%s: la lista debe estar ordenada", c.name)
		}
	}
	// sentido 2: todo lo que el código nombra está listado en alguna herramienta.
	listadas := map[string]bool{}
	for _, ks := range validOptions {
		for _, k := range ks {
			listadas[k] = true
		}
	}
	re := regexp.MustCompile(`o\.(?:str|num|boolean|strictBool)\("([a-z_0-9]+)"|o\.m\["([a-z_0-9]+)"\]`)
	for _, f := range []string{"args.go", "args_ping.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			if k := m[1] + m[2]; !listadas[k] {
				t.Errorf("%s lee %q y no está en validOptions", f, k)
			}
		}
	}
}

// Con varias desconocidas, el error nombra la primera en orden alfabético.
func TestOpcionDesconocidaOrdenEstable(t *testing.T) {
	pingIfaces(t)
	for i := 0; i < 20; i++ {
		_, _, err := Build(Request{Tool: Ping, Targets: []string{"192.0.2.1"}, Options: map[string]string{"zzz": "1", "mmm": "1", "aaa": "1"}})
		ie, ok := esOpcion(err)
		if !ok || ie.Args["key"] != "aaa" {
			t.Fatalf("se esperaba «aaa», llegó %v", err)
		}
	}
}

// En Windows la lista de ping no ofrece tos ni interval.
func TestOpcionesValidasWindowsSinTosNiInterval(t *testing.T) {
	pingIfaces(t)
	_, _, err := buildWindows(Request{Tool: Ping, Targets: []string{"192.0.2.1"}, Options: map[string]string{"zzz": "1"}})
	ie, ok := esOpcion(err)
	if !ok {
		t.Fatal(err)
	}
	for _, k := range strings.Split(fmt.Sprint(ie.Args["valid"]), ", ") {
		if k == "tos" || k == "interval" {
			t.Errorf("Windows lista %q como válida", k)
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

// pcapIface es una interfaz válida en el sistema donde corre la prueba (en Windows, un número de dumpcap -D).
func pcapIface() string {
	if runtime.GOOS == "windows" {
		return "1"
	}
	return "eth0"
}
