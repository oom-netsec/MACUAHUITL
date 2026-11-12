package devices

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const cabecera = "name,address,port,platform,folder,tags,credential_label,notes"

func TestCSVIdaYVuelta(t *testing.T) {
	hs := []FileHost{
		{Name: "SW-1", Address: "10.0.0.1", Port: 22, Platform: "ios-xe", Folder: "Lab 1", Tags: []string{"core", "dc-1"}, CredentialLabel: "admin lab", Notes: "línea 1\nlínea 2, con \"comillas\" y coma"},
		{Name: "AP ñandú", Address: "ap1.lab", Port: 2222},
	}
	b, err := MarshalHostsCSV(hs)
	if err != nil {
		t.Fatal(err)
	}
	// el archivo empieza con un BOM UTF-8 para que Excel muestre bien los acentos; al leer se quita
	if !strings.HasPrefix(string(b), "\xef\xbb\xbf"+cabecera+"\n") || strings.Count(string(b), "\xef\xbb\xbf") != 1 || !strings.Contains(string(b), "core;dc-1") || strings.Contains(string(b), "sha256") {
		t.Fatalf("csv:\n%s", b)
	}
	got, err := ParseHostsCSV(b)
	if err != nil || len(got.Errors) != 0 || len(got.Hosts) != 2 || got.NoSum {
		t.Fatalf("got = %+v err = %v", got, err)
	}
	for i := range hs {
		if hs[i].Tags == nil {
			hs[i].Tags = []string{}
		}
		if g := got.Hosts[i]; !reflect.DeepEqual(g.Tags, hs[i].Tags) && !(len(g.Tags) == 0 && len(hs[i].Tags) == 0) || g.Name != hs[i].Name || g.Notes != hs[i].Notes || g.Port != hs[i].Port || g.CredentialLabel != hs[i].CredentialLabel {
			t.Fatalf("host %d cambió: %+v", i, g)
		}
	}
}

func TestCSVEncabezado(t *testing.T) {
	fila := "\nsw1,10.0.0.1,22,ios,,,,"
	ok := map[string]string{
		"mayúsculas y espacios": " Name , ADDRESS,Port,platform ,folder,tags,credential_label,NOTES" + fila,
		"con BOM":               "\xef\xbb\xbf" + cabecera + fila,
	}
	for n, c := range ok {
		if got, err := ParseHostsCSV([]byte(c)); err != nil || len(got.Hosts) != 1 || len(got.Errors) != 0 {
			t.Errorf("%s: %+v %v", n, got, err)
		}
	}
	mal := map[string]string{
		"vacío":             "",
		"falta una":         "name,address,port,platform,folder,tags,credential_label" + fila,
		"sobra una":         cabecera + ",extra" + fila,
		"otro orden":        "address,name,port,platform,folder,tags,credential_label,notes" + fila,
		"otro nombre":       "name,address,port,platform,folder,tags,credential,notes" + fila,
		"no es UTF-8":       cabecera + "\nsw\xff,10.0.0.1,22,,,,,",
		"pasa de 5 MB":      cabecera + fila + strings.Repeat(" ", MaxImportBytes),
		"pasa de las filas": cabecera + strings.Repeat(fila, MaxImportHosts+1),
	}
	for n, c := range mal {
		if _, err := ParseHostsCSV([]byte(c)); err == nil {
			t.Errorf("%s: debió fallar", n)
		}
	}
	// el error de encabezado dice qué falta y qué sobra
	_, err := ParseHostsCSV([]byte("name,address,puerto,platform,folder,tags,credential_label,notes\n"))
	if err == nil || !strings.Contains(err.Error(), "port") || !strings.Contains(err.Error(), "puerto") {
		t.Fatalf("mensaje = %v", err)
	}
	// justo en el tope de filas sí
	if got, err := ParseHostsCSV([]byte(cabecera + strings.Repeat("\nx,10.0.0.1,22,,,,,", MaxImportHosts))); err != nil || len(got.Hosts)+len(got.Errors) != MaxImportHosts {
		t.Fatalf("en el tope: %v", err)
	}
}

func TestCSVErroresPorLinea(t *testing.T) {
	csv := cabecera + "\n" +
		"ok1,10.0.0.1,22,ios,,,,\n" + // 2
		"mal,admin@10.0.0.2,22,ios,,,,\n" + // 3 address
		"\n" + // 4 en blanco: se salta
		"ok2,10.0.0.3,2222,wlc,Lab,a;b,etq,nota\n" + // 5
		"p,10.0.0.4,abc,ios,,,,\n" + // 6 port no numérico
		"corto,10.0.0.5,22\n" + // 7 columnas de menos
		"plat,10.0.0.6,22,junos,,,,\n" + // 8 platform
		"tag,10.0.0.7,22,ios,,MAYUS,,\n" + // 9 tags
		"OK1,10.0.0.8,22,ios,,,,\n" + // 10 nombre repetido de la línea 2
		"dup,10.0.0.1,22,ios,,,,\n" + // 11 mismo destino que la línea 2
		"\"abierta,10.0.0.9,22,ios,,,,\n" // 12 comillas sin cerrar
	got, err := ParseHostsCSV([]byte(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Hosts) != 2 || got.Hosts[0].Name != "ok1" || got.Hosts[1].Name != "ok2" || got.Hosts[1].Port != 2222 || strings.Join(got.Hosts[1].Tags, ",") != "a,b" {
		t.Fatalf("válidos = %+v", got.Hosts)
	}
	want := map[int]string{3: "address", 6: "port", 7: "", 8: "platform", 9: "tags", 10: "name", 11: "address"}
	for _, e := range got.Errors {
		if f, ok := want[e.Line]; ok && e.Field == f && e.Reason != "" {
			delete(want, e.Line)
		} else if e.Line != 12 {
			t.Errorf("error inesperado %+v", e)
		}
	}
	if len(want) != 0 {
		t.Errorf("faltan errores en las líneas %v (hay %+v)", want, got.Errors)
	}
	// la línea 12 (comillas sin cerrar) se reporta aunque sea la última, y dice que el resto se ignoró
	if last := got.Errors[len(got.Errors)-1]; last.Line != 12 || !strings.Contains(last.Reason, "comillas sin cerrar: se ignoró el resto del archivo desde la línea 12") {
		t.Errorf("último = %+v", last)
	}
	// una comilla suelta en medio del archivo no ignora nada: es solo el error de su línea
	got, _ = ParseHostsCSV([]byte(cabecera + "\nmal,10.0.0.1,22,,,,,a\"b\nbien,10.0.0.2,22,,,,,\n"))
	if len(got.Hosts) != 1 || len(got.Errors) != 1 || got.Errors[0].Line != 2 || strings.Contains(got.Errors[0].Reason, "resto del archivo") {
		t.Errorf("comilla suelta: %+v", got)
	}
	got, _ = ParseHostsCSV([]byte(cabecera + "\n\"mal\"x,10.0.0.1,22,,,,,\nbien,10.0.0.2,22,,,,,\n"))
	if len(got.Hosts) != 1 || len(got.Errors) != 1 || got.Errors[0].Line != 2 || strings.Contains(got.Errors[0].Reason, "resto del archivo") {
		t.Errorf("comilla sobrante en medio: %+v", got)
	}
}

func TestCSVProtegeContraFormulas(t *testing.T) {
	peligrosos := []string{"=1+1", "+cmd", "-2", "@SUM(A1)", "\tx", "'=ya empezaba con comilla", "''@doble", " =cmd|' /C calc'!A0", "' =cmd", "  '  @x"}
	var hs []FileHost
	for i, v := range peligrosos {
		label := v
		if strings.Contains(v, "\t") {
			label = "" // la etiqueta no admite tabuladores
		}
		hs = append(hs, FileHost{Name: "h" + string(rune('a'+i)), Address: fmt.Sprintf("10.0.0.%d", i+1), Notes: v, CredentialLabel: label})
	}
	b, err := MarshalHostsCSV(hs)
	if err != nil {
		t.Fatal(err)
	}
	// ninguna celda del archivo empieza con un carácter de fórmula
	for _, ln := range strings.Split(string(b), "\n")[1:] {
		for _, celda := range strings.Split(ln, ",") {
			celda = strings.TrimPrefix(celda, `"`)
			if celda != "" && strings.ContainsRune("=+-@\t\r", rune(celda[0])) {
				t.Fatalf("celda peligrosa %q en %q", celda, ln)
			}
		}
	}
	// con espacios o comillas antes del signo también se protege (Excel los ignora al decidir si es fórmula)
	if !strings.Contains(string(b), "' =cmd|' /C calc'!A0") || !strings.Contains(string(b), "'' =cmd") {
		t.Fatalf("falta proteger lo que empieza con espacio:\n%s", b)
	}
	if !strings.Contains(string(b), "'=1+1") || !strings.Contains(string(b), "'+cmd") {
		t.Fatalf("falta el apóstrofo:\n%s", b)
	}
	// un CR al inicio (no válido en las notas, pero el escritor no lo deja pasar) también se protege
	if cr, _ := MarshalHostsCSV([]FileHost{{Name: "x", Address: "10.0.0.1", Notes: "\rx"}}); !strings.Contains(string(cr), "\"'\rx\"") {
		t.Fatalf("CR sin proteger: %q", cr)
	}
	// al leer vuelve el texto original (también el que ya empezaba con comilla)
	got, err := ParseHostsCSV(b)
	if err != nil || len(got.Hosts) != len(hs) {
		t.Fatalf("got = %+v err = %v", got, err)
	}
	for i, h := range got.Hosts {
		if h.Notes != hs[i].Notes || h.CredentialLabel != hs[i].CredentialLabel {
			t.Errorf("host %d: notas %q, quería %q", i, h.Notes, hs[i].Notes)
		}
	}
	// una comilla suelta que no precede a un carácter de fórmula se queda
	got, _ = ParseHostsCSV([]byte(cabecera + "\nx,10.0.0.1,22,,,,,'hola\nx2,10.0.0.2,22,,,,,'=1"))
	if got.Hosts[0].Notes != "'hola" || got.Hosts[1].Notes != "=1" {
		t.Fatalf("comillas: %+v", got.Hosts)
	}
}

// El esquema es uno solo: la tabla de campos manda sobre el encabezado CSV, las claves JSON y la plantilla.
func TestEsquemaUnicoDeCampos(t *testing.T) {
	var nombres []string
	for _, f := range HostFields {
		nombres = append(nombres, f.Name)
		if f.Type == "" || f.Description == "" || f.Examples[0] == "" && f.Required {
			t.Errorf("campo incompleto: %+v", f)
		}
	}
	if strings.Join(nombres, ",") != cabecera {
		t.Fatalf("campos = %v", nombres)
	}
	rt := reflect.TypeOf(FileHost{})
	var json []string
	for i := 0; i < rt.NumField(); i++ {
		json = append(json, strings.Split(rt.Field(i).Tag.Get("json"), ",")[0])
	}
	if strings.Join(json, ",") != cabecera {
		t.Fatalf("claves JSON = %v", json)
	}
}

func TestPlantillaPasaPorElImport(t *testing.T) {
	for _, f := range []string{FormatCSV, FormatJSON} {
		b, err := Template(f, ahora)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseImport(f, b)
		if err != nil || len(got.Errors) != 0 || len(got.Hosts) != 3 {
			t.Fatalf("%s: %+v %v\n%s", f, got, err, b)
		}
		// todos nuevos frente a una libreta vacía
		var hs []Host
		for _, h := range got.Hosts {
			hs = append(hs, h.Host())
		}
		for _, it := range Plan(hs, nil) {
			if it.Estado != Nuevo {
				t.Errorf("%s: %s es %s", f, it.Host.Name, it.Estado)
			}
		}
	}
	csv, _ := Template(FormatCSV, ahora)
	if !strings.HasPrefix(string(csv), "\xef\xbb\xbf"+cabecera+"\n") || strings.Count(string(csv), "\n") != 4 {
		t.Fatalf("csv:\n%s", csv)
	}
	js, _ := Template(FormatJSON, ahora)
	if strings.Contains(string(js), "sha256") || !strings.Contains(string(js), `"formato":"macuahuitl-hosts"`) {
		t.Fatalf("json: %s", js)
	}
	if got, _ := ParseImport(FormatJSON, js); !got.NoSum {
		t.Fatal("la plantilla JSON no lleva suma")
	}
	if _, err := Template("xml", ahora); err == nil {
		t.Fatal("formato desconocido")
	}
}

func TestImportFormat(t *testing.T) {
	casos := []struct{ path, format, want string }{
		{"/a/h.csv", "", "csv"}, {"/a/H.JSON", "", "json"}, {"/a/h.txt", "json", "json"}, {"/a/h.json", "CSV", "csv"}, {"/a/h.json", " csv ", "csv"},
	}
	for _, c := range casos {
		if got, err := ImportFormat(c.path, c.format); err != nil || got != c.want {
			t.Errorf("%v: %q %v", c, got, err)
		}
	}
	for _, c := range [][2]string{{"/a/h.txt", ""}, {"/a/h", ""}, {"/a/h.csv", "xml"}} {
		if _, err := ImportFormat(c[0], c[1]); err == nil {
			t.Errorf("%v debió fallar", c)
		}
	}
}
