package devices

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Libreta de hosts (fase 29b): los equipos que el usuario agrega a mano son la fuente «manual» del inventario.
// Una credencial se guarda solo como la referencia (id) a la bóveda; nunca un secreto.

const (
	SrcManual = "manual" // host de la libreta

	DefaultPort = 22
	TelnetPort  = 23 // fase 48: puerto por omisión de un host con protocolo telnet
	MaxHosts    = 5000

	MaxHostName = 64
	MaxFolder   = 48
	MaxHostTags = 10
	MaxNotes    = 2000
	MaxLabel    = 128

	// MaxImportHosts es el tope de hosts (filas) de un archivo de import, JSON o CSV.
	MaxImportHosts = 1000
)

var (
	hostTagRe  = regexp.MustCompile(`^[a-z0-9-]{1,24}$`)
	folderRe   = regexp.MustCompile(`^[A-Za-z0-9 _.-]{1,48}$`)
	dnsLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	credIDRe   = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// HostPlatforms es la lista cerrada de plataformas; vacía = sin definir.
var HostPlatforms = []string{"ios", "ios-xe", "nx-os", "asa", "ftd", "ise", "iosxr", "wlc", "linux", "windows"}

// MaxStartup es el tope de la orden de inicio, en puntos de código.
const MaxStartup = 256

// IsGeneric dice si la plataforma es de un host que no es de red (linux, windows): solo se abre en el terminal SSH.
func IsGeneric(platform string) bool { return platform == "linux" || platform == "windows" }

// Host es un host de la libreta. CredentialID es el id de la bóveda, vacío si no tiene.
type Host struct {
	ID, Name, Address string
	Port              int
	Platform, Folder  string
	Tags              []string
	CredentialID      string
	Notes             string
	StartupCommand    string // orden que el terminal manda al conectar (fase 44); solo linux y windows
	Protocol          string // fase 48: "ssh" (por omisión) o "telnet"; solo la terminal interactiva lo usa
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// NewID da un ID de host: 16 bytes aleatorios en hex.
func NewID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// NameKey es la clave con la que se comparan los nombres (sin importar mayúsculas): pasar por mayúsculas
// primero junta «ς» y «σ», que ToLower solo no junta.
func NameKey(n string) string { return strings.ToLower(strings.ToUpper(n)) }

// Key identifica un host por dirección y puerto (la dirección ya canónica, ver Clean).
func Key(h Host) string { return h.Address + ":" + strconv.Itoa(h.Port) }

// hasControl: con allowNL (notas) solo los controles que no son salto ni tab; sin él (nombre de host, etiqueta de credencial)
// también los separadores de línea y de párrafo y los caracteres que disfrazan lo que se ve (hiddenRune).
func hasControl(s string, allowNL bool) bool {
	for _, r := range s {
		if unicode.IsControl(r) && !(allowNL && (r == '\n' || r == '\t')) {
			return true
		}
		if !allowNL && (hiddenRune(r) || unicode.In(r, unicode.Zl, unicode.Zp)) {
			return true
		}
	}
	return false
}

// hiddenRune: control de dirección del texto (bidi: U+202A-202E, U+2066-2069, U+200E, U+200F, U+061C), ancho cero (U+200B, U+2060,
// U+FEFF), operadores matemáticos invisibles (U+2061-2064) y las etiquetas (U+E0000-E007F, que esconden texto «tag» invisible). No cuenta el resto de \p{Cf}: U+200D y U+200C (necesarios en persa, hindi y emoji) ni el guion blando U+00AD.
func hiddenRune(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r >= 0x2061 && r <= 0x2064, r >= 0xE0000 && r <= 0xE007F:
		return true
	}
	return r == 0x200E || r == 0x200F || r == 0x061C || r == 0x200B || r == 0x2060 || r == 0xFEFF
}

// FieldError es un campo inválido de un host: Field es el nombre del campo en el archivo de import (name, address…).
// Msg es el texto en es; Err es el mismo con código del catálogo. Es un i18n.Coded: reason y metadata son los de Err,
// más metadata.field con el campo (regla 9b).
type FieldError struct {
	Field, Msg string
	Err        error
}

func (e *FieldError) Error() string { return e.Msg }
func (e *FieldError) Unwrap() error { return e.Err }

func (e *FieldError) coded() (i18n.Coded, bool) {
	var c i18n.Coded
	return c, e.Err != nil && errors.As(e.Err, &c)
}

func (e *FieldError) Reason() string {
	if c, ok := e.coded(); ok {
		return c.Reason()
	}
	return ""
}

func (e *FieldError) Metadata() map[string]string {
	m := map[string]string{}
	if c, ok := e.coded(); ok {
		for k, v := range c.Metadata() {
			m[k] = v
		}
	}
	m["field"] = e.Field
	return m
}

func (e *FieldError) Localize(loc string) string {
	if c, ok := e.coded(); ok {
		return c.Localize(loc)
	}
	return e.Msg
}

func fe(field, code string, args ...any) *FieldError {
	err := i18n.New(code, i18n.A(args...))
	return &FieldError{Field: field, Msg: err.Error(), Err: err}
}

// canonAddr valida una dirección (IP o nombre DNS, sin esquema, usuario, puerto ni ruta) y la deja canónica.
func canonAddr(a string) (string, error) {
	if a == "" || len(a) > 253 {
		return "", i18n.New("hostfield.addr_len", nil)
	}
	if ip, err := netip.ParseAddr(a); err == nil {
		if ip.Zone() != "" {
			return "", i18n.New("hostfield.addr_zone", nil)
		}
		return ip.Unmap().String(), nil
	}
	a = strings.ToLower(a)
	labels := strings.Split(a, ".")
	for _, l := range labels {
		if !dnsLabelRe.MatchString(l) {
			return "", i18n.New("hostfield.addr_dns", i18n.A("addr", a))
		}
	}
	if _, err := strconv.Atoi(labels[len(labels)-1]); err == nil { // «10.0.0.256»: parece IP, no es nombre
		return "", i18n.New("hostfield.addr_ip", i18n.A("addr", a))
	}
	return a, nil
}

// Clean valida un host y lo deja canónico (dirección en minúsculas o IP normalizada, puerto por defecto).
func Clean(h Host) (Host, error) {
	if n := utf8.RuneCountInString(h.Name); n < 1 || n > MaxHostName || h.Name != strings.TrimSpace(h.Name) || hasControl(h.Name, false) {
		return h, fe("name", "hostfield.name")
	}
	var err error
	if h.Address, err = canonAddr(h.Address); err != nil {
		return h, &FieldError{Field: "address", Msg: err.Error(), Err: err}
	}
	if h.Protocol = strings.ToLower(strings.TrimSpace(h.Protocol)); h.Protocol == "" { // «Telnet » de un CSV hecho a mano vale
		h.Protocol = "ssh"
	}
	if h.Protocol != "ssh" && h.Protocol != "telnet" {
		return h, fe("protocol", "hostfield.protocol")
	}
	if h.Port == 0 && h.Protocol == "telnet" {
		h.Port = TelnetPort
	} else if h.Port == 0 {
		h.Port = DefaultPort
	}
	if h.Port < 1 || h.Port > 65535 {
		return h, fe("port", "hostfield.port")
	}
	if h.Platform != "" && !slices.Contains(HostPlatforms, h.Platform) {
		return h, fe("platform", "hostfield.platform", "platform", h.Platform, "list", strings.Join(HostPlatforms, ", "))
	}
	if h.Folder != "" && (!folderRe.MatchString(h.Folder) || h.Folder != strings.TrimSpace(h.Folder)) {
		return h, fe("folder", "hostfield.folder")
	}
	if len(h.Tags) > MaxHostTags {
		return h, fe("tags", "hostfield.tags_max", "max", MaxHostTags)
	}
	seen := map[string]bool{}
	for _, t := range h.Tags {
		if !hostTagRe.MatchString(t) || seen[t] {
			return h, fe("tags", "hostfield.tag_bad", "tag", t)
		}
		seen[t] = true
	}
	if utf8.RuneCountInString(h.Notes) > MaxNotes || hasControl(h.Notes, true) {
		return h, fe("notes", "hostfield.notes", "max", MaxNotes)
	}
	if h.CredentialID != "" && !credIDRe.MatchString(h.CredentialID) {
		return h, fe("credential_id", "hostfield.credential_id")
	}
	if h.StartupCommand != "" {
		if n := utf8.RuneCountInString(h.StartupCommand); n > MaxStartup || h.StartupCommand != strings.TrimSpace(h.StartupCommand) || badStartupRune(h.StartupCommand) {
			return h, fe("startup_command", "hostfield.startup_command", "max", MaxStartup)
		}
		if !IsGeneric(h.Platform) {
			return h, fe("startup_command", "hostfield.startup_platform")
		}
		if h.Protocol == "telnet" {
			return h, fe("startup_command", "hostfield.startup_telnet")
		}
	}
	return h, nil
}

// badStartupRune: control (\p{Cc}: tab, saltos, NUL, DEL, C1), formato (\p{Cf}: bidi, U+200B-200F, U+FEFF) o separador de
// línea y de párrafo (\p{Zl}, \p{Zp}: U+2028/U+2029), que un textarea muestra como salto: la orden es una sola línea.
// Con un U+202E la orden se vería distinta de la que corre.
func badStartupRune(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return true
		}
	}
	return false
}
