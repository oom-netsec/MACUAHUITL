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

func TestResolvePathsWindows(t *testing.T) {
	p := resolvePathsWindows(env(map[string]string{
		"LOCALAPPDATA": `C:\Users\u\AppData\Local`, "APPDATA": `C:\Users\u\AppData\Roaming`, "USERPROFILE": `C:\Users\u`,
	}))
	want := Paths{
		Config: `C:\Users\u\AppData\Local\MACUAHUITL\config`, Data: `C:\Users\u\AppData\Local\MACUAHUITL\data`,
		State: `C:\Users\u\AppData\Local\MACUAHUITL\state`, Outputs: `C:\Users\u\MACUAHUITL\outputs`, Home: `C:\Users\u`,
	}
	if p != want {
		t.Fatalf("got %+v", p)
	}
	// Con barra final sale igual.
	if q := resolvePathsWindows(env(map[string]string{"LOCALAPPDATA": `C:\Users\u\AppData\Local\`, "USERPROFILE": `C:\Users\u`})); q != want {
		t.Fatalf("got %+v", q)
	}
}

// Sin LOCALAPPDATA absoluta las tres rutas quedan vacías: nunca se cae a %APPDATA% (roaming).
func TestResolvePathsWindowsSinLocalAppData(t *testing.T) {
	for _, la := range []string{"", `Local`, `\Users\u`, `C:Users`, `C:/Users/u/AppData/Local`, `\\host\share\x`, `//host/share/x`,
		`\\?\C:\Users\u`, `\\.\C:\x`, `C:\Users\..\x`, `C:\..`, `C:\Users\\u`, `C:`, `C:\`} {
		p := resolvePathsWindows(env(map[string]string{"LOCALAPPDATA": la, "APPDATA": `C:\Users\u\AppData\Roaming`, "USERPROFILE": `C:\Users\u`}))
		if p.Config != "" || p.Data != "" || p.State != "" {
			t.Fatalf("LOCALAPPDATA=%q: %+v", la, p)
		}
	}
}
