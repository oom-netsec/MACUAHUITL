package core

import "testing"

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestResolvePathsXDG(t *testing.T) {
	p := ResolvePaths(env(map[string]string{
		"HOME": "/home/u", "XDG_CONFIG_HOME": "/c", "XDG_DATA_HOME": "/d", "XDG_STATE_HOME": "/s", "XDG_RUNTIME_DIR": "/run/user/1000",
	}))
	want := Paths{Config: "/c/macuahuitl", Data: "/d/macuahuitl", State: "/s/macuahuitl", Runtime: "/run/user/1000/macuahuitl", Outputs: "/home/u/MACUAHUITL/outputs", Home: "/home/u"}
	if p != want {
		t.Fatalf("got %+v", p)
	}
}

func TestResolvePathsDefaults(t *testing.T) {
	p := ResolvePaths(env(map[string]string{"HOME": "/home/u", "XDG_RUNTIME_DIR": "/run/user/1000"}))
	want := Paths{Config: "/home/u/.config/macuahuitl", Data: "/home/u/.local/share/macuahuitl", State: "/home/u/.local/state/macuahuitl", Runtime: "/run/user/1000/macuahuitl", Outputs: "/home/u/MACUAHUITL/outputs", Home: "/home/u"}
	if p != want {
		t.Fatalf("got %+v", p)
	}
}

func TestResolvePathsIgnoresRelativeXDG(t *testing.T) {
	// La especificación XDG dice que las rutas relativas se ignoran.
	p := ResolvePaths(env(map[string]string{"HOME": "/home/u", "XDG_DATA_HOME": "rel/x"}))
	if p.Data != "/home/u/.local/share/macuahuitl" || p.Runtime != "" {
		t.Fatalf("got %+v", p)
	}
}
