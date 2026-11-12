package acl

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestGenerateMatchesSamples(t *testing.T) {
	for vendor, file := range map[string]string{"ios-xe": "iosxe.txt", "nx-os": "nxos.txt", "asa": "asa.txt"} {
		want, _ := os.ReadFile(filepath.Join("testdata", file))
		got, err := Generate(vendor, wantEdge())
		if err != nil {
			t.Fatalf("%s: %v", vendor, err)
		}
		if norm(got) != norm(string(want)) {
			t.Errorf("%s:\n got:\n%s\nwant:\n%s", vendor, got, want)
		}
	}
}

// norm compara sin distinguir "log-input" de "log", "any4" de "any" ni "ntp" de "123".
func norm(s string) string {
	r := strings.NewReplacer("log-input", "log", "any4", "any", "eq ntp", "eq 123", "  ", " ")
	var out []string
	for _, ln := range strings.Split(strings.TrimSpace(s), "\n") {
		out = append(out, strings.TrimSpace(r.Replace(ln)))
	}
	return strings.Join(out, "\n")
}

func TestRoundTrip(t *testing.T) {
	a := wantEdge()
	a.Rules = append(a.Rules, Rule{Action: Permit, Protocol: "tcp", Src: Any, Dst: Any, DstPorts: []PortRange{{0, 24}, {26, 65535}}, Established: true})
	for _, vendor := range []string{"ios-xe", "nx-os"} {
		text, err := Generate(vendor, a)
		if err != nil {
			t.Fatal(err)
		}
		back, err := Parse(vendor, text)
		if err != nil {
			t.Fatalf("%s: %v\n%s", vendor, err, text)
		}
		if !reflect.DeepEqual(back, a) {
			t.Errorf("%s round trip:\n got %+v\nwant %+v\n%s", vendor, back, a, text)
		}
	}
	if _, err := Generate("asa", a); err == nil {
		t.Fatal("ASA has no 'established'; must fail instead of dropping it")
	}
}

func TestGenerateRejectsBadInput(t *testing.T) {
	if _, err := Generate("junos", wantEdge()); err == nil {
		t.Fatal("unknown vendor accepted")
	}
	bad := ACL{Name: "X", Rules: []Rule{{Action: Permit, Protocol: "ip"}}}
	if _, err := Generate("ios-xe", bad); err == nil {
		t.Fatal("invalid rule generated")
	}
	if _, err := Generate("ios-xe", ACL{Name: "con espacio", Rules: wantEdge().Rules}); err == nil {
		t.Fatal("ACL name with spaces accepted")
	}
}
