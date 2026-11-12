package cli

import "testing"

func TestStripFlagAndHasJSON(t *testing.T) {
	a, f := StripFlag([]string{"a", "--no-color", "b"}, "--no-color")
	if !f || len(a) != 2 || !HasJSON([]string{"x", "--json"}) || HasJSON([]string{"x"}) {
		t.Fatal(a, f)
	}
}
