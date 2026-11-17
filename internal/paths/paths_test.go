package paths

import "testing"

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

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

// USERPROFILE inválida (3.2): Home y Outputs quedan vacíos y LOCALAPPDATA sigue valiendo (el núcleo lo rechaza en main).
func TestResolvePathsWindowsUserProfileInvalido(t *testing.T) {
	for _, up := range []string{"", `Users\u`, `\\host\share\u`, `\\?\C:\Users\u`, `C:\Users\..\u`, `C:`, `C:/Users/u`} {
		p := resolvePathsWindows(env(map[string]string{"LOCALAPPDATA": `C:\Users\u\AppData\Local`, "USERPROFILE": up}))
		if p.Home != "" || p.Outputs != "" || p.Config == "" {
			t.Errorf("USERPROFILE=%q: %+v", up, p)
		}
	}
}

// LOCALAPPDATA en otra unidad (3.3): es válida y se usa tal cual.
func TestResolvePathsWindowsOtraUnidad(t *testing.T) {
	p := resolvePathsWindows(env(map[string]string{"LOCALAPPDATA": `D:\datos\PROGRA~1`, "USERPROFILE": `E:\u`}))
	if p.Config != `D:\datos\PROGRA~1\MACUAHUITL\config` || p.Home != `E:\u` {
		t.Fatalf("got %+v", p)
	}
}
