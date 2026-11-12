package transfer

import (
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Entry es una entrada de un listado remoto. Todo lo que trae viene del servidor y no es de
// fiar: el nombre ya está saneado para mostrarlo; Unsafe avisa que el original no lo estaba.
type Entry struct {
	Name         string
	Type         string    // file, dir, link u other
	Size         int64     // bytes; -1 si el servidor no lo dice
	ModTime      time.Time // cero si no la dice
	Perms        string    // «rwxr-xr-x», «0644» o los permisos de MLSD; vacío si no los hay
	Downloadable bool      // archivo con un nombre que Get puede pedir (juego de caracteres de la ruta remota)
	Unsafe       bool      // el nombre original traía control, formato invisible o UTF-8 inválido
}

// SanitizeName deja un nombre del servidor listo para mostrar: los caracteres de control, los de
// formato Unicode (U+202E, ancho cero, BOM) y los bytes que no son UTF-8 se cambian por «?».
// unsafe dice si hubo que cambiar algo.
func SanitizeName(raw string) (name string, unsafe bool) {
	if !utf8.ValidString(raw) {
		raw, unsafe = strings.ToValidUTF8(raw, "?"), true
	}
	out := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			unsafe = true
			return '?'
		}
		return r
	}, raw)
	return out, unsafe
}

// remoteOK dice si Get podría pedir este nombre (mismo juego de caracteres que remotePath).
func remoteOK(name string) bool {
	if name == "" || strings.HasPrefix(name, "-") {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-:@+,=~", c)) {
			return false
		}
	}
	return true
}

// entry arma una Entry con el nombre saneado; ok=false si el nombre no sirve (vacío, «.», «..» o con ruta).
func entry(rawName, typ string) (Entry, bool) {
	if rawName == "" || rawName == "." || rawName == ".." || strings.ContainsAny(rawName, `/\`) {
		return Entry{}, false
	}
	name, unsafe := SanitizeName(rawName)
	return Entry{Name: name, Type: typ, Size: -1, Unsafe: unsafe, Downloadable: typ == "file" && !unsafe && remoteOK(rawName)}, true
}

// ---- LIST (Unix y DOS) ----

var (
	unixPermRe = regexp.MustCompile(`^[-dlcbpsD][rwxsStTl-]{9}[+@.]?$`)
	dosRe      = regexp.MustCompile(`(?i)^(\d{2})-(\d{2})-(\d{2}|\d{4})\s+(\d{1,2}):(\d{2})\s*([AP]M)?\s+(<DIR>|\d+)\s+(\S.*)$`)
	fieldRe    = regexp.MustCompile(`\S+`)
	hhmmRe     = regexp.MustCompile(`^\d{1,2}:\d{2}$`)
	yearRe     = regexp.MustCompile(`^\d{4}$`)
	isoDateRe  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	months     = map[string]time.Month{"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}
)

// ParseList lee la salida de LIST de un servidor FTP: formato de ls -l de Unix (con o sin columna
// de grupo, fecha «Mon DD HH:MM», «Mon DD YYYY» o ISO) y el de IIS en modo DOS. Una línea que no
// reconoce se salta; no falla. now fija el año de las fechas sin año.
func ParseList(text string, now time.Time) []Entry {
	var out []Entry
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if e, ok := parseDOS(ln); ok {
			out = append(out, e)
		} else if e, ok := parseUnix(ln, now); ok {
			out = append(out, e)
		}
	}
	return out
}

func parseDOS(ln string) (Entry, bool) {
	m := dosRe.FindStringSubmatch(strings.TrimSpace(ln))
	if m == nil {
		return Entry{}, false
	}
	typ, size := "file", int64(-1)
	if !strings.EqualFold(m[7], "<DIR>") {
		n, err := strconv.ParseInt(m[7], 10, 64)
		if err != nil {
			return Entry{}, false
		}
		size = n
	} else {
		typ = "dir"
	}
	e, ok := entry(m[8], typ)
	if !ok {
		return Entry{}, false
	}
	e.Size = size
	mo, d, y, h, mi := atoiS(m[1]), atoiS(m[2]), atoiS(m[3]), atoiS(m[4]), atoiS(m[5])
	if len(m[3]) == 2 {
		if y >= 70 {
			y += 1900
		} else {
			y += 2000
		}
	}
	if p := strings.ToUpper(m[6]); p == "PM" && h < 12 {
		h += 12
	} else if p == "AM" && h == 12 {
		h = 0
	}
	if mo >= 1 && mo <= 12 && d >= 1 && d <= 31 && h < 24 && mi < 60 {
		e.ModTime = time.Date(y, time.Month(mo), d, h, mi, 0, 0, time.UTC)
	}
	return e, true
}

func atoiS(s string) int { n, _ := strconv.Atoi(s); return n }

func parseUnix(ln string, now time.Time) (Entry, bool) {
	idx := fieldRe.FindAllStringIndex(ln, -1)
	if len(idx) < 7 {
		return Entry{}, false
	}
	f := func(i int) string { return ln[idx[i][0]:idx[i][1]] }
	if !unixPermRe.MatchString(f(0)) {
		return Entry{}, false
	}
	// la fecha empieza en la primera posición donde cabe «Mes DD HH:MM|AAAA» o «AAAA-MM-DD HH:MM», con el tamaño antes
	for i := 3; i+1 < len(idx); i++ {
		var mod time.Time
		last := i + 1
		if _, isMonth := months[strings.ToLower(f(i))]; isMonth && i+2 < len(idx) && atoiS(f(i+1)) >= 1 && atoiS(f(i+1)) <= 31 && (hhmmRe.MatchString(f(i+2)) || yearRe.MatchString(f(i+2))) {
			mod, last = unixDate(f(i), f(i+1), f(i+2), now), i+2
		} else if isoDateRe.MatchString(f(i)) && hhmmRe.MatchString(f(i+1)) {
			mod, _ = time.Parse("2006-01-02 15:04", f(i)+" "+f(i+1))
		} else {
			continue
		}
		size, err := strconv.ParseInt(f(i-1), 10, 64)
		if err != nil || size < 0 || idx[last][1] >= len(ln) {
			continue
		}
		name := strings.TrimLeft(ln[idx[last][1]:], " \t")
		typ := map[byte]string{'-': "file", 'd': "dir", 'l': "link"}[f(0)[0]]
		if typ == "" {
			typ = "other"
		}
		if typ == "link" {
			name, _, _ = strings.Cut(name, " -> ")
		}
		e, ok := entry(name, typ)
		if !ok {
			return Entry{}, false
		}
		e.Size, e.ModTime, e.Perms = size, mod, f(0)[1:10]
		return e, true
	}
	return Entry{}, false
}

// unixDate lee «Nov 6 10:15» (sin año: el actual, o el anterior si caería más de un día en el futuro) o «Nov 6 2025».
func unixDate(mon, day, third string, now time.Time) time.Time {
	m, d := months[strings.ToLower(mon)], atoiS(day)
	if yearRe.MatchString(third) {
		return time.Date(atoiS(third), m, d, 0, 0, 0, 0, time.UTC)
	}
	hm := strings.SplitN(third, ":", 2)
	t := time.Date(now.Year(), m, d, atoiS(hm[0]), atoiS(hm[1]), 0, 0, time.UTC)
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t
}

// ---- MLSD (RFC 3659) ----

// ParseMLSD lee la respuesta de MLSD: «hecho=valor;hecho=valor; nombre». Salta «cdir» y «pdir».
func ParseMLSD(text string) []Entry {
	var out []Entry
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimRight(ln, "\r")
		facts, name, ok := strings.Cut(ln, " ")
		if !ok || !strings.Contains(facts, "=") {
			continue
		}
		kv := map[string]string{}
		for _, p := range strings.Split(facts, ";") {
			if k, v, ok := strings.Cut(p, "="); ok {
				kv[strings.ToLower(k)] = v
			}
		}
		typ := ""
		switch t := strings.ToLower(kv["type"]); {
		case t == "file":
			typ = "file"
		case t == "dir":
			typ = "dir"
		case t == "cdir" || t == "pdir":
			continue
		case strings.HasPrefix(t, "os.unix=slink"), strings.HasPrefix(t, "os.unix=symlink"):
			typ = "link"
		default:
			typ = "other"
		}
		e, ok := entry(name, typ)
		if !ok {
			continue
		}
		if n, err := strconv.ParseInt(firstNonEmpty(kv["size"], kv["sizd"]), 10, 64); err == nil && n >= 0 {
			e.Size = n
		}
		if m := kv["modify"]; len(m) >= 14 {
			e.ModTime, _ = time.Parse("20060102150405", m[:14])
		}
		e.Perms = firstNonEmpty(kv["unix.mode"], kv["perm"])
		out = append(out, e)
	}
	return out
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}

// ---- índice HTML simple ----

var (
	anchorRe  = regexp.MustCompile(`(?is)<a\s[^>]*?href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))[^>]*>`)
	idxDateRe = regexp.MustCompile(`(\d{4}-\d{2}-\d{2}|\d{2}-[A-Za-z]{3}-\d{4})\s+(\d{2}:\d{2})\s+(\d+(?:\.\d+)?[KkMmGg]?|-)`)
)

// ParseHTMLIndex lee un índice de directorio HTML (Apache, nginx, python -m http.server): solo los
// enlaces relativos a la misma carpeta (un segmento, sin «..», sin esquema ni «?»). Tamaño y fecha
// salen del texto que sigue al enlace en la misma línea, si el formato es el de Apache o nginx.
// Devuelve a lo más max entradas; truncated dice que había más.
func ParseHTMLIndex(body []byte, max int) (out []Entry, truncated bool) {
	text := string(body)
	locs := anchorRe.FindAllStringSubmatchIndex(text, -1)
	seen := map[string]bool{}
	for i, loc := range locs {
		href := ""
		for g := 1; g <= 3; g++ {
			if loc[2*g] >= 0 {
				href = text[loc[2*g]:loc[2*g+1]]
			}
		}
		raw := hrefName(html.UnescapeString(href))
		if raw == "" {
			continue
		}
		isDir := strings.HasSuffix(raw, "/")
		name := strings.TrimSuffix(raw, "/")
		typ := "file"
		if isDir {
			typ = "dir"
		}
		e, ok := entry(name, typ)
		if !ok || e.Unsafe || seen[e.Name] {
			continue
		}
		seen[e.Name] = true
		if len(out) >= max {
			return out, true
		}
		end := len(text)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		tail := text[loc[1]:end]
		if nl := strings.IndexByte(tail, '\n'); nl >= 0 {
			tail = tail[:nl]
		}
		fillFromIndexText(&e, tail)
		out = append(out, e)
	}
	return out, false
}

// hrefName devuelve el nombre (con «/» final si es carpeta) de un href relativo a la misma carpeta, o "".
func hrefName(h string) string {
	h = strings.TrimSpace(h)
	if h == "" || strings.HasPrefix(h, "/") || strings.HasPrefix(h, "?") || strings.HasPrefix(h, "#") || strings.HasPrefix(h, "../") || h == ".." {
		return ""
	}
	h = strings.TrimPrefix(h, "./")
	if i := strings.IndexAny(h, "?#"); i >= 0 {
		h = h[:i]
	}
	if c := strings.IndexByte(h, ':'); c >= 0 && (strings.IndexByte(h, '/') < 0 || c < strings.IndexByte(h, '/')) {
		return "" // tiene esquema (http:, mailto:, javascript:)
	}
	n, err := url.PathUnescape(h)
	if err != nil {
		return ""
	}
	if strings.Contains(strings.TrimSuffix(n, "/"), "/") {
		return "" // subcarpetas: no es de esta carpeta
	}
	return n
}

func fillFromIndexText(e *Entry, tail string) {
	m := idxDateRe.FindStringSubmatch(tail)
	if m == nil {
		return
	}
	for _, layout := range []string{"2006-01-02 15:04", "02-Jan-2006 15:04"} {
		if t, err := time.Parse(layout, m[1]+" "+m[2]); err == nil {
			e.ModTime = t
			break
		}
	}
	if m[3] == "-" {
		return
	}
	mult := float64(1)
	num := m[3]
	switch num[len(num)-1] {
	case 'k', 'K':
		mult, num = 1<<10, num[:len(num)-1]
	case 'm', 'M':
		mult, num = 1<<20, num[:len(num)-1]
	case 'g', 'G':
		mult, num = 1<<30, num[:len(num)-1]
	}
	if v, err := strconv.ParseFloat(num, 64); err == nil && v >= 0 && v*mult < 1<<62 {
		e.Size = int64(v * mult)
	}
}
