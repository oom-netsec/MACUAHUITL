package version

import "testing"

func TestStringDefault(t *testing.T) {
	if got, want := String(), "macuahuitl dev"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
