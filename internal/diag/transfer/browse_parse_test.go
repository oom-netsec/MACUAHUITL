package transfer

import (
	"strings"
	"testing"
	"time"
	"unicode"
)

var now = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func find(es []Entry, name string) (Entry, bool) {
	for _, e := range es {
		if e.Name == name {
			return e, true
		}
	}
	return Entry{}, false
}

func TestSanitizeName(t *testing.T) {
	cases := []struct {
		in, want string
		unsafe   bool
	}{
		{"running-config", "running-config", false},
		{"sala de juntas.txt", "sala de juntas.txt", false},
		{"evil\u202egnp.exe", "evil?gnp.exe", true},
		{"a\x00b", "a?b", true},
		{"esc\x1b[31mrojo", "esc?[31mrojo", true},
		{"ancho\u200bcero", "ancho?cero", true},
		{"mal\xffutf8", "mal?utf8", true},
		{"ñandú.cfg", "ñandú.cfg", false},
	}
	for _, c := range cases {
		got, unsafe := SanitizeName(c.in)
		if got != c.want || unsafe != c.unsafe {
			t.Errorf("%q → %q %v; quería %q %v", c.in, got, unsafe, c.want, c.unsafe)
		}
	}
}

func TestParseListUnix(t *testing.T) {
	txt := `total 48
drwxr-xr-x   2 root  root      4096 Nov  6 10:15 backups
-rw-r--r--   1 admin staff  1048576 Nov  6  2025 running config.txt
-rw-------   1 admin       7777 Jan 31 23:59 sin-grupo.cfg
lrwxrwxrwx   1 root  root         9 Oct 20  2024 latest -> image.bin
drwxr-xr-x+  3 root  root      4096 2026-11-05 08:30 iso-date
-rw-r--r--   1 admin staff     123 Dec 31 23:59 futuro.bin
crw-rw-rw-   1 root  root         0 Nov  6 10:15 dispositivo
.
..
drwxr-xr-x   2 root  root      4096 Nov  6 10:15 .
drwxr-xr-x   2 root  root      4096 Nov  6 10:15 ..
-rw-r--r--   1 admin staff       5 Nov  6 10:15 a/b
`
	es := ParseList(txt, now)
	want := map[string]struct {
		typ   string
		size  int64
		perms string
	}{
		"backups":            {"dir", 4096, "rwxr-xr-x"},
		"running config.txt": {"file", 1048576, "rw-r--r--"},
		"sin-grupo.cfg":      {"file", 7777, "rw-------"},
		"latest":             {"link", 9, "rwxrwxrwx"},
		"iso-date":           {"dir", 4096, "rwxr-xr-x"},
		"futuro.bin":         {"file", 123, "rw-r--r--"},
		"dispositivo":        {"other", 0, "rw-rw-rw-"},
	}
	if len(es) != len(want) {
		t.Fatalf("%d entradas: %+v", len(es), es)
	}
	for n, w := range want {
		e, ok := find(es, n)
		if !ok || e.Type != w.typ || e.Size != w.size || e.Perms != w.perms {
			t.Errorf("%s = %+v; quería %+v", n, e, w)
		}
	}
	// "Nov  6 10:15" sin año: este año; "Dec 31 23:59" quedaría en el futuro: el año pasado
	if e, _ := find(es, "backups"); !e.ModTime.Equal(time.Date(2026, 11, 6, 10, 15, 0, 0, time.UTC)) {
		t.Errorf("fecha = %v", e.ModTime)
	}
	if e, _ := find(es, "futuro.bin"); e.ModTime.Year() != 2025 {
		t.Errorf("fecha futura = %v", e.ModTime)
	}
	if e, _ := find(es, "running config.txt"); e.ModTime.Year() != 2025 || e.ModTime.Month() != 11 {
		t.Errorf("fecha con año = %v", e.ModTime)
	}
	if e, _ := find(es, "iso-date"); !e.ModTime.Equal(time.Date(2026, 11, 5, 8, 30, 0, 0, time.UTC)) {
		t.Errorf("fecha ISO = %v", e.ModTime)
	}
}

func TestParseListDOS(t *testing.T) {
	txt := "11-06-26  10:15AM       <DIR>          backups\r\n" +
		"11-05-2026  03:07PM            1048576 imagen grande.bin\r\n" +
		"12-31-99  11:59PM                  12 viejo.txt\r\n" +
		"01-02-85  12:00AM                  12 medianoche.txt\r\n" +
		"basura que no es una linea\r\n"
	es := ParseList(txt, now)
	if len(es) != 4 {
		t.Fatalf("%+v", es)
	}
	if e, _ := find(es, "medianoche.txt"); e.ModTime.Year() != 1985 || e.ModTime.Hour() != 0 {
		t.Errorf("medianoche = %+v", e)
	}
	if e, _ := find(es, "backups"); e.Type != "dir" || e.Size != -1 || !e.ModTime.Equal(time.Date(2026, 11, 6, 10, 15, 0, 0, time.UTC)) {
		t.Errorf("backups = %+v", e)
	}
	if e, _ := find(es, "imagen grande.bin"); e.Type != "file" || e.Size != 1048576 || e.ModTime.Hour() != 15 {
		t.Errorf("imagen = %+v", e)
	}
	if e, _ := find(es, "viejo.txt"); e.ModTime.Year() != 1999 {
		t.Errorf("viejo = %+v", e)
	}
}

func TestParseListNombresNoConfiables(t *testing.T) {
	txt := "-rw-r--r-- 1 u g 5 Nov  6 10:15 evil\u202egnp.exe\n-rw-r--r-- 1 u g 5 Nov  6 10:15 ok.cfg\n"
	es := ParseList(txt, now)
	if len(es) != 2 {
		t.Fatalf("%+v", es)
	}
	if es[0].Name != "evil?gnp.exe" || !es[0].Unsafe || es[0].Downloadable {
		t.Errorf("nombre con control = %+v", es[0])
	}
	if es[1].Unsafe || !es[1].Downloadable {
		t.Errorf("ok.cfg = %+v", es[1])
	}
	if e := ParseList("-rw-r--r-- 1 u g 5 Nov  6 10:15 sala de juntas.txt\n", now)[0]; e.Downloadable {
		t.Errorf("un nombre con espacios no pasa el filtro de la ruta remota: %+v", e)
	}
}

func TestParseMLSD(t *testing.T) {
	txt := "type=cdir;modify=20261106101500; /pub\r\n" +
		"type=pdir;modify=20261106101500; ..\r\n" +
		"type=dir;modify=20261105083000;perm=flcdmpe;UNIX.mode=0755; backups\r\n" +
		"type=file;size=1048576;modify=20261106101500.123;perm=adfrw; running config.txt\r\n" +
		"type=OS.unix=slink:image.bin;size=9;modify=20261001000000; latest\r\n" +
		"type=file;size=abc;modify=nada; raro\r\n" +
		"type=file;size=5; con;punto y coma\r\n" +
		"sin hechos\r\n" +
		"type=file;size=5; a/b\r\n"
	es := ParseMLSD(txt)
	if len(es) != 5 {
		t.Fatalf("%d: %+v", len(es), es)
	}
	if e, _ := find(es, "backups"); e.Type != "dir" || e.Perms != "0755" || e.Size != -1 || !e.ModTime.Equal(time.Date(2026, 11, 5, 8, 30, 0, 0, time.UTC)) {
		t.Errorf("backups = %+v", e)
	}
	if e, _ := find(es, "running config.txt"); e.Type != "file" || e.Size != 1048576 || e.Perms != "adfrw" || e.ModTime.Second() != 0 {
		t.Errorf("config = %+v", e)
	}
	if e, _ := find(es, "latest"); e.Type != "link" || e.Size != 9 {
		t.Errorf("latest = %+v", e)
	}
	if e, _ := find(es, "raro"); e.Size != -1 || !e.ModTime.IsZero() {
		t.Errorf("raro = %+v", e)
	}
	if _, ok := find(es, "con;punto y coma"); !ok {
		t.Errorf("el nombre puede traer ';': %+v", es)
	}
}

func TestParseHTMLIndex(t *testing.T) {
	body := `<html><head><title>Index of /imagenes</title></head><body><h1>Index of /imagenes</h1>
<pre><a href="?C=N;O=D">Name</a> <a href="?C=M;O=A">Last modified</a>
<hr><a href="/">Parent Directory</a>
<a href="../">Up</a>
<a href="c9300-universalk9.17.09.04a.SPA.bin">c9300-universalk9.17.09.04a.SPA.bin</a>  2026-11-06 10:15  1.2G
<a href="sub%20carpeta/">sub carpeta/</a>                  2026-11-05 08:30    -
<a href='notas.txt'>notas.txt</a> 06-Nov-2026 10:15  2048
<a href="http://otro.example/x.bin">externo</a>
<a href="//otro.example/x.bin">mismo esquema</a>
<a href="javascript:alert(1)">js</a>
<a href="a/b.txt">anidado</a>
<a href="mailto:x@y">mail</a>
<a href="notas.txt">duplicado</a>
<a href=sinComillas.cfg>sin comillas</a>  2026-11-06 10:15  4.5M
<a href="-rf">opcion</a>
<a href="%2e%2e/etc">trampa</a>
<a href="%0aevil">control</a>
<a href="a&amp;b.cfg">entidad</a>
<a href="k.bin">k</a> 2026-11-06 10:15  2K
</pre></body></html>`
	es, trunc := ParseHTMLIndex([]byte(body), 100)
	if trunc {
		t.Error("no debía truncar")
	}
	names := []string{}
	for _, e := range es {
		names = append(names, e.Name)
	}
	want := []string{"c9300-universalk9.17.09.04a.SPA.bin", "sub carpeta", "notas.txt", "sinComillas.cfg", "-rf", "a&b.cfg", "k.bin"}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Fatalf("nombres = %q", names)
	}
	if e := es[0]; e.Type != "file" || e.Size != 1288490188 || !e.ModTime.Equal(time.Date(2026, 11, 6, 10, 15, 0, 0, time.UTC)) {
		t.Errorf("imagen = %+v", e)
	}
	if e := es[1]; e.Type != "dir" || e.Size != -1 || e.Downloadable {
		t.Errorf("carpeta = %+v", e)
	}
	if e := es[2]; e.Size != 2048 || e.ModTime.Month() != time.November {
		t.Errorf("nginx = %+v", e)
	}
	if e := es[3]; e.Size != 4718592 {
		t.Errorf("4.5M = %+v", e)
	}
	if e := es[6]; e.Size != 2048 {
		t.Errorf("2K = %+v", e)
	}
	if e := es[4]; e.Downloadable {
		t.Errorf("-rf se leería como opción: %+v", e)
	}
	if es, trunc = ParseHTMLIndex([]byte(body), 2); len(es) != 2 || !trunc {
		t.Errorf("tope de entradas: %d %v", len(es), trunc)
	}
}

func FuzzParseList(f *testing.F) {
	f.Add("drwxr-xr-x 2 root root 4096 Nov  6 10:15 backups\n-rw-r--r-- 1 u g 5 Nov  6  2025 a b\n")
	f.Add("11-06-26  10:15AM       <DIR>          x\r\n")
	f.Add("lrwxrwxrwx 1 r r 9 Oct 20 2024 l -> t\n")
	f.Add("\x00\xff\u202e Jan 99 99:99")
	f.Fuzz(func(t *testing.T, s string) {
		for _, e := range ParseList(s, now) {
			checkEntry(t, e)
		}
		for _, e := range ParseMLSD(s) {
			checkEntry(t, e)
		}
	})
}

func FuzzParseHTMLIndex(f *testing.F) {
	f.Add(`<a href="a.bin">a</a> 2026-11-06 10:15 1K`)
	f.Add(`<a href='x/'>x</a><a href=y>`)
	f.Add("<a href=\"\x00\u202e\">")
	f.Add(strings.Repeat("<a href=", 50))
	f.Fuzz(func(t *testing.T, s string) {
		es, _ := ParseHTMLIndex([]byte(s), 50)
		if len(es) > 50 {
			t.Fatalf("%d entradas con tope 50", len(es))
		}
		for _, e := range es {
			checkEntry(t, e)
		}
	})
}

// checkEntry: lo que el cliente nunca debe entregar a la vista, venga lo que venga del servidor.
func checkEntry(t *testing.T, e Entry) {
	t.Helper()
	if e.Name == "" || e.Name == "." || e.Name == ".." || strings.ContainsAny(e.Name, `/\`) {
		t.Fatalf("nombre inválido %q", e.Name)
	}
	for _, r := range e.Name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			t.Fatalf("nombre %q con carácter peligroso %U", e.Name, r)
		}
	}
	if e.Size < -1 {
		t.Fatalf("tamaño %d", e.Size)
	}
	switch e.Type {
	case "file", "dir", "link", "other":
	default:
		t.Fatalf("tipo %q", e.Type)
	}
}
