package devices

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

var ahora = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

func muestra(i int) FileHost {
	return FileHost{Name: fmt.Sprintf("sw-%02d", i), Address: fmt.Sprintf("10.0.0.%d", i), Port: 22, Platform: "ios-xe", Folder: "lab",
		Tags: []string{"core"}, CredentialLabel: "admin lab", Notes: "n"}
}

func TestHostsExportParseIdaYVuelta(t *testing.T) {
	var todos []FileHost
	for i := 1; i <= 15; i++ {
		todos = append(todos, muestra(i))
	}
	b, err := MarshalHosts(todos, ahora)
	if err != nil {
		t.Fatal(err)
	}
	// el archivo lleva la etiqueta de la credencial y jamás un id ni un secreto
	for _, mal := range []string{"credential_id", "credentialId", "password", "secret"} {
		if strings.Contains(string(b), mal) {
			t.Fatalf("el export contiene %q", mal)
		}
	}
	if !strings.Contains(string(b), `"credential_label":"admin lab"`) || !strings.Contains(string(b), `"formato":"macuahuitl-hosts"`) || !strings.Contains(string(b), `"sha256"`) {
		t.Fatalf("export: %s", b)
	}
	got, err := ParseHosts(b)
	if err != nil || len(got.Hosts) != 15 || len(got.Errors) != 0 || got.NoSum {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	for i, h := range got.Hosts {
		if h.Name != todos[i].Name || h.Address != todos[i].Address || h.CredentialLabel != "admin lab" || h.Tags[0] != "core" {
			t.Fatalf("host %d cambió: %+v", i, h)
		}
	}
	// listas vacías o nulas dan la misma suma, y reindentar el JSON no la rompe
	sin := muestra(1)
	sin.Tags = nil
	b1, _ := MarshalHosts([]FileHost{sin}, ahora)
	sin.Tags = []string{}
	b2, _ := MarshalHosts([]FileHost{sin}, ahora)
	if string(b1) != string(b2) {
		t.Fatal("nil y [] deben exportar igual")
	}
	if _, err := ParseHosts([]byte(strings.ReplaceAll(string(b), `"hosts":[`, "\"hosts\":[\n"))); err != nil {
		t.Fatalf("espacio en blanco: %v", err)
	}
}

func TestParseHostsRechazaUnByteCambiado(t *testing.T) {
	b, _ := MarshalHosts([]FileHost{muestra(1)}, ahora)
	mal := strings.Replace(string(b), "10.0.0.1", "10.0.0.2", 1)
	if _, err := ParseHosts([]byte(mal)); err == nil || !strings.Contains(err.Error(), "suma") {
		t.Fatalf("err = %v", err)
	}
}

// Un archivo roto de cabecera se rechaza entero; un host malo es solo el error de su entrada.
func TestParseHostsRechazosDelArchivo(t *testing.T) {
	good, _ := MarshalHosts([]FileHost{muestra(1)}, ahora)
	s := string(good)
	vacio, _ := MarshalHosts(nil, ahora)
	casos := map[string]string{
		"formato":           strings.Replace(s, "macuahuitl-hosts", "otro", 1),
		"versión":           strings.Replace(s, `"version":1`, `"version":2`, 1),
		"campo desconocido": strings.Replace(s, `"sha256"`, `"extra":1,"sha256"`, 1),
		"datos al final":    s + "{}",
		"no es JSON":        "hola",
		"pasa de 5 MB":      s + strings.Repeat(" ", MaxImportBytes),
		"suma de otro":      strings.Replace(s, `"sha256":"`, `"sha256":"0`, 1),
		// con suma, una entrada que no se puede leer no se puede verificar
		"entrada ilegible con suma": strings.Replace(s, `"port":22`, `"port":"22"`, 1),
	}
	for nombre, c := range casos {
		if _, err := ParseHosts([]byte(c)); err == nil {
			t.Errorf("%s: debió fallar", nombre)
		}
	}
	if got, err := ParseHosts(vacio); err != nil || len(got.Hosts) != 0 {
		t.Fatalf("archivo vacío: %v %v", got, err)
	}
	var muchos []FileHost
	for i := 0; i <= MaxImportHosts; i++ {
		muchos = append(muchos, FileHost{Name: fmt.Sprintf("h%d", i), Address: fmt.Sprintf("h%d.lab", i), Port: 22})
	}
	b, _ := MarshalHosts(muchos, ahora)
	if _, err := ParseHosts(b); err == nil || !strings.Contains(err.Error(), "tope") {
		t.Fatalf("tope: %v", err)
	}
}

func TestParseHostsErroresPorEntrada(t *testing.T) {
	dup := muestra(2)
	dup.Name = "SW-01" // mismo nombre sin importar mayúsculas
	mismoDestino := muestra(3)
	mismoDestino.Address = "10.0.0.1"
	malo := muestra(4)
	malo.Address = "admin@10.0.0.4"
	etq := muestra(5)
	etq.CredentialLabel = strings.Repeat("x", MaxLabel+1)
	etq2 := muestra(6)
	etq2.CredentialLabel = "a\x00b"
	bueno := muestra(7)
	b := mustMarshal(t, muestra(1), dup, mismoDestino, malo, etq, etq2, bueno)
	got, err := ParseHosts([]byte(b))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Hosts) != 2 || got.Hosts[0].Name != "sw-01" || got.Hosts[1].Name != "sw-07" {
		t.Fatalf("válidos = %+v", got.Hosts)
	}
	want := []LineError{{2, "name", ""}, {3, "address", ""}, {4, "address", ""}, {5, "credential_label", ""}, {6, "credential_label", ""}}
	if len(got.Errors) != len(want) {
		t.Fatalf("errores = %+v", got.Errors)
	}
	for i, w := range want {
		if e := got.Errors[i]; e.Line != w.Line || e.Field != w.Field || e.Reason == "" {
			t.Errorf("error %d = %+v, quiero línea %d campo %s", i, e, w.Line, w.Field)
		}
	}
	// una entrada con un campo desconocido o de otro tipo también es solo su error (sin suma no hay nada que verificar)
	raw := `{"formato":"macuahuitl-hosts","version":1,"exportado":"x","hosts":[{"name":"a","address":"10.0.0.1","port":22},{"name":"b","address":"10.0.0.2","extra":1},{"name":"c","address":"10.0.0.3","port":"x"},{"name":"d","address":"10.0.0.4"}]}`
	got, err = ParseHosts([]byte(raw))
	if err != nil || len(got.Hosts) != 2 || len(got.Errors) != 2 || got.Errors[0].Line != 2 || got.Errors[1].Line != 3 || !got.NoSum {
		t.Fatalf("sin suma: %+v %v", got, err)
	}
	if got.Hosts[1].Port != 0 && got.Hosts[1].Port != 22 {
		t.Fatalf("puerto = %d", got.Hosts[1].Port)
	}
}

func TestParseHostsSumaOpcional(t *testing.T) {
	b, _ := MarshalHosts([]FileHost{muestra(1)}, ahora)
	sinSuma := regexp.MustCompile(`,"sha256":"[0-9a-f]+"`).ReplaceAllString(string(b), "")
	got, err := ParseHosts([]byte(sinSuma))
	if err != nil || !got.NoSum || len(got.Hosts) != 1 {
		t.Fatalf("sin suma: %+v %v", got, err)
	}
	// con suma que no coincide: rechazo aunque el contenido sea válido
	if _, err := ParseHosts([]byte(strings.Replace(string(b), `"sha256":"`, `"sha256":"1`, 1))); err == nil {
		t.Fatal("suma incorrecta debe rechazarse")
	}
}

// mustMarshal arma un archivo con la suma correcta aunque los hosts no valgan, para probar las reglas de Parse.
func mustMarshal(t *testing.T, hs ...FileHost) string {
	t.Helper()
	b, err := MarshalHosts(hs, ahora)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
