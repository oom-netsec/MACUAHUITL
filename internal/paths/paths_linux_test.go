package paths

import "testing"

// Las rutas XDG son las de Linux: Resolve solo las usa fuera de Windows, y filepath.Join/IsAbs dependen del sistema.
// En Windows corren las de resolvePathsWindows (paths_test.go), que no dependen de él.

func TestResolvePathsXDG(t *testing.T) {
	p := Resolve(env(map[string]string{
		"HOME": "/home/u", "XDG_CONFIG_HOME": "/c", "XDG_DATA_HOME": "/d", "XDG_STATE_HOME": "/s", "XDG_RUNTIME_DIR": "/run/user/1000",
	}))
	want := Paths{Config: "/c/macuahuitl", Data: "/d/macuahuitl", State: "/s/macuahuitl", Runtime: "/run/user/1000/macuahuitl", Outputs: "/home/u/MACUAHUITL/outputs", Home: "/home/u"}
	if p != want {
		t.Fatalf("got %+v", p)
	}
}

func TestResolvePathsDefaults(t *testing.T) {
	p := Resolve(env(map[string]string{"HOME": "/home/u", "XDG_RUNTIME_DIR": "/run/user/1000"}))
	want := Paths{Config: "/home/u/.config/macuahuitl", Data: "/home/u/.local/share/macuahuitl", State: "/home/u/.local/state/macuahuitl", Runtime: "/run/user/1000/macuahuitl", Outputs: "/home/u/MACUAHUITL/outputs", Home: "/home/u"}
	if p != want {
		t.Fatalf("got %+v", p)
	}
}

func TestResolvePathsIgnoresRelativeXDG(t *testing.T) {
	// La especificación XDG dice que las rutas relativas se ignoran.
	p := Resolve(env(map[string]string{"HOME": "/home/u", "XDG_DATA_HOME": "rel/x"}))
	if p.Data != "/home/u/.local/share/macuahuitl" || p.Runtime != "" {
		t.Fatalf("got %+v", p)
	}
}

// HOME vacío o relativo (3.1): las rutas por omisión saldrían RELATIVAS al directorio actual. Quedan vacías y el
// núcleo no arranca; una XDG absoluta sigue valiendo para su carpeta.
func TestResolvePathsHomeInvalido(t *testing.T) {
	for _, home := range []string{"", "rel", ".", "./x", "../x", "~"} {
		p := Resolve(env(map[string]string{"HOME": home, "XDG_RUNTIME_DIR": "/run/user/1000"}))
		if p.Config != "" || p.Data != "" || p.State != "" || p.Outputs != "" || p.Home != "" {
			t.Errorf("HOME=%q: %+v", home, p)
		}
	}
	p := Resolve(env(map[string]string{"HOME": "rel", "XDG_CONFIG_HOME": "/c"}))
	if p.Config != "/c/macuahuitl" || p.Data != "" || p.Home != "" {
		t.Fatalf("got %+v", p)
	}
}
