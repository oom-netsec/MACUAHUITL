package cli

import "testing"

func TestDecision(t *testing.T) {
	for _, c := range []struct {
		in, want string
		allowed  []string
		ok       bool
	}{
		{"rename", "rename", nil, true}, {"renombrar", "rename", nil, true},
		{"replace", "replace", nil, true}, {"reemplazar", "replace", nil, true},
		{"skip", "skip", nil, true}, {"omitir", "skip", nil, true},
		{"merge", "merge", nil, false}, {"", "", nil, false},
		{"replace", "replace", []string{"rename", "skip"}, false},
		{"reemplazar", "replace", []string{"rename", "skip"}, false},
		{"omitir", "skip", []string{"rename", "skip"}, true},
	} {
		got, ok := Decision(c.in, c.allowed...)
		if got != c.want || ok != c.ok {
			t.Errorf("Decision(%q, %v) = %q, %v; quiero %q, %v", c.in, c.allowed, got, ok, c.want, c.ok)
		}
	}
}
