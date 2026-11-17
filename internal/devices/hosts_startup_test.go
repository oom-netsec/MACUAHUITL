package devices

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestOrdenDeInicio(t *testing.T) {
	casos := []struct {
		nombre, plataforma, orden string
		valido                    bool
	}{
		{"wsl", "windows", "wsl -d Ubuntu-26.04 --cd ~", true},
		{"cmd", "windows", "cmd /c echo macuahuitl-ok", true},
		{"linux", "linux", "tmux attach || tmux", true},
		{"vacía en cisco", "ios-xe", "", true},
		{"vacía sin plataforma", "", "", true},
		{"256 letras de un byte", "linux", strings.Repeat("a", 256), true},
		{"256 letras de dos bytes", "linux", strings.Repeat("é", 256), true},
		{"256 letras de tres bytes", "linux", strings.Repeat("日", 256), true},
		{"257 letras de un byte", "linux", strings.Repeat("a", 257), false},
		{"257 letras de dos bytes", "linux", strings.Repeat("é", 257), false},
		{"257 letras de tres bytes", "linux", strings.Repeat("日", 257), false},
		{"tab", "linux", "ls\t-l", false},
		{"salto de línea", "linux", "ls\nid", false},
		{"retorno", "linux", "ls\rid", false},
		{"NUL", "linux", "ls\x00", false},
		{"DEL", "linux", "ls\x7f", false},
		{"U+0085", "linux", "ls\u0085id", false},
		{"U+2028", "linux", "ls\u2028id", false},
		{"U+2029", "linux", "ls\u2029id", false},
		{"U+202A", "linux", "ls \u202a", false},
		{"U+202E", "linux", "ls \u202e", false},
		{"U+2066", "linux", "ls \u2066", false},
		{"U+2069", "linux", "ls \u2069", false},
		{"U+200B", "linux", "ls\u200bid", false},
		{"U+200F", "linux", "ls\u200fid", false},
		{"U+FEFF", "linux", "\ufeffls", false},
		{"espacio al inicio", "linux", " ls", false},
		{"espacio al final", "linux", "ls ", false},
		{"en un ios-xe", "ios-xe", "show version", false},
		{"sin plataforma", "", "show version", false},
	}
	for _, c := range casos {
		_, err := Clean(Host{Name: "h", Address: "10.0.0.9", Platform: c.plataforma, StartupCommand: c.orden})
		if (err == nil) != c.valido {
			t.Errorf("%s: err = %v", c.nombre, err)
			continue
		}
		if err == nil {
			continue
		}
		var ce i18n.Coded
		if !errors.As(err, &ce) {
			t.Errorf("%s: el error no es i18n.Coded", c.nombre)
			continue
		}
		if f := ce.Metadata()["field"]; f != "startup_command" {
			t.Errorf("%s: metadata.field = %q", c.nombre, f)
		}
	}
}

// Todos los campos del host llevan su nombre en metadata.field, también los que usan un código con otro campo.
func TestFieldErrorLlevaElCampo(t *testing.T) {
	for campo, h := range map[string]Host{
		"name":          {Name: "", Address: "10.0.0.1"},
		"address":       {Name: "a", Address: "x@y"},
		"port":          {Name: "a", Address: "10.0.0.1", Port: 70000},
		"platform":      {Name: "a", Address: "10.0.0.1", Platform: "junos"},
		"credential_id": {Name: "a", Address: "10.0.0.1", CredentialID: "zz"},
	} {
		_, err := Clean(h)
		var ce i18n.Coded
		if !errors.As(err, &ce) || ce.Metadata()["field"] != campo {
			t.Errorf("%s: err = %v", campo, err)
			continue
		}
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != campo || fe.Localize(i18n.En) == "" || fe.Error() != fe.Msg {
			t.Errorf("%s: %+v", campo, fe)
		}
	}
}

func TestPlataformasGenericas(t *testing.T) {
	for _, p := range []string{"linux", "windows"} {
		if _, err := Clean(Host{Name: "h", Address: "10.0.0.9", Platform: p}); err != nil {
			t.Errorf("%s: %v", p, err)
		}
		if !IsGeneric(p) {
			t.Errorf("%s debe ser genérica", p)
		}
	}
	if IsGeneric("ios-xe") || IsGeneric("") {
		t.Error("ios-xe y vacía no son genéricas")
	}
}

func TestCSVOrdenDeInicio(t *testing.T) {
	hs := []FileHost{{Name: "box", Address: "10.0.0.2", Platform: "windows", StartupCommand: "wsl -d Ubuntu-26.04 --cd ~"}, {Name: "sw", Address: "10.0.0.3", Platform: "ios"}}
	b, err := MarshalHostsCSV(hs)
	if err != nil || !strings.Contains(string(b), ",notes,startup_command\n") {
		t.Fatalf("%s %v", b, err)
	}
	got, err := ParseHostsCSV(b)
	if err != nil || len(got.Errors) != 0 || len(got.Hosts) != 2 || got.Hosts[0].StartupCommand != hs[0].StartupCommand || got.Hosts[1].StartupCommand != "" {
		t.Fatalf("%+v %v", got, err)
	}
	// encabezado viejo, sin la columna: sigue entrando
	viejo := "name,address,port,platform,folder,tags,credential_label,notes\nsw,10.0.0.1,22,ios,,,,\n"
	if got, err := ParseHostsCSV([]byte(viejo)); err != nil || len(got.Errors) != 0 || len(got.Hosts) != 1 || got.Hosts[0].StartupCommand != "" {
		t.Fatalf("viejo: %+v %v", got, err)
	}
	// encabezado viejo con una fila de 9 celdas: no cuadra
	if got, _ := ParseHostsCSV([]byte(strings.Replace(viejo, "ios,,,,", "ios,,,,,x", 1))); len(got.Errors) != 1 {
		t.Fatalf("columnas de más: %+v", got)
	}
	// una fila con orden inválida sale en errors con su campo
	malo := cabecera + "\nsw,10.0.0.1,22,ios-xe,,,,,show version\nbox,10.0.0.2,22,linux,,,,,ls\u202e\n"
	got, err = ParseHostsCSV([]byte(malo))
	if err != nil || len(got.Hosts) != 0 || len(got.Errors) != 2 || got.Errors[0].Field != "startup_command" || got.Errors[1].Field != "startup_command" {
		t.Fatalf("malo: %+v %v", got, err)
	}
}

func TestJSONOrdenDeInicio(t *testing.T) {
	hs := []FileHost{{Name: "box", Address: "10.0.0.2", Platform: "linux", StartupCommand: "tmux"}, {Name: "sw", Address: "10.0.0.3"}}
	b, _ := MarshalHosts(hs, ahora)
	got, err := ParseHosts(b)
	if err != nil || len(got.Errors) != 0 || got.Hosts[0].StartupCommand != "tmux" {
		t.Fatalf("%+v %v", got, err)
	}
	// un archivo de antes (sin la clave y con su suma de entonces) sigue pasando la suma
	viejo := `{"formato":"macuahuitl-hosts","version":1,"exportado":"2026-01-01T00:00:00Z","hosts":[{"name":"sw","address":"10.0.0.3","port":0,"platform":"","folder":"","tags":[],"credential_label":"","notes":""}],"sha256":"` + sumaViejaDe(t) + `"}`
	if got, err := ParseHosts([]byte(viejo)); err != nil || len(got.Hosts) != 1 {
		t.Fatalf("viejo: %+v %v", got, err)
	}
}

func sumaViejaDe(t *testing.T) string {
	t.Helper()
	const raw = `[{"name":"sw","address":"10.0.0.3","port":0,"platform":"","folder":"","tags":[],"credential_label":"","notes":""}]`
	return sha256hex(raw)
}

func TestSameCompararLaOrden(t *testing.T) {
	a := Host{Name: "h", Address: "10.0.0.1", Port: 22, Platform: "linux", StartupCommand: "tmux"}
	b := a
	if !Same(a, b) {
		t.Fatal("iguales")
	}
	b.StartupCommand = "screen"
	if Same(a, b) {
		t.Fatal("la orden distinta debe ser distinta")
	}
}

func TestOrdenViajaEnToFile(t *testing.T) {
	h := Host{Name: "h", Address: "10.0.0.1", Platform: "linux", StartupCommand: "tmux"}
	if f := ToFile(h, ""); f.StartupCommand != "tmux" || f.Host().StartupCommand != "tmux" {
		t.Fatalf("%+v", f)
	}
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// AddrKey pone en la forma de la libreta las direcciones que la libreta nunca guarda: punto final de DNS e IPv6 entre corchetes.
func TestAddrKeyFormasEquivalentes(t *testing.T) {
	for in, want := range map[string]string{"Box.LAN.": "box.lan", "[2001:DB8::1]": "2001:db8::1", "::ffff:10.0.0.9": "10.0.0.9", "box.lan": "box.lan"} {
		if got := AddrKey(in); got != want {
			t.Errorf("AddrKey(%q) = %q, quiero %q", in, got, want)
		}
	}
}
