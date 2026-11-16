package ipc

import "testing"

func TestSameSID(t *testing.T) {
	const me = "S-1-5-21-111-222-333-1001"
	for _, c := range []struct {
		name      string
		peer, own string
		want      bool
	}{
		{"igual", me, me, true},
		{"minúsculas", "s-1-5-21-111-222-333-1001", me, true},
		{"otro usuario", "S-1-5-21-111-222-333-1002", me, false},
		{"prefijo no es igual", "S-1-5-21-111-222-333-100", me, false},
		{"SYSTEM", "S-1-5-18", me, false},
		{"peer vacío falla cerrado", "", me, false},
		{"propio vacío falla cerrado", "", "", false},
		{"solo propio vacío", me, "", false},
	} {
		if got := sameSID(c.peer, c.own); got != c.want {
			t.Errorf("%s: sameSID(%q, %q) = %v, quería %v", c.name, c.peer, c.own, got, c.want)
		}
	}
}
