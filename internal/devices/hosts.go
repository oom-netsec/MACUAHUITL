package devices

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Libreta de hosts (fase 29b): los equipos que el usuario agrega a mano son la fuente «manual» del inventario.
// Una credencial se guarda solo como la referencia (id) a la bóveda; nunca un secreto.

const (
	SrcManual = "manual" // host de la libreta

	DefaultPort = 22
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
var HostPlatforms = []string{"ios", "ios-xe", "nx-os", "asa", "iosxr", "wlc"}

// Host es un host de la libreta. CredentialID es el id de la bóveda, vacío si no tiene.
type Host struct {
	ID, Name, Address string
	Port              int
	Platform, Folder  string
	Tags              []string
	CredentialID      string
	Notes             string
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

func hasControl(s string, allowNL bool) bool {
	for _, r := range s {
		if unicode.IsControl(r) && !(allowNL && (r == '\n' || r == '\t')) {
			return true
		}
	}
	return false
}

// FieldError es un campo inválido de un host: Field es el nombre del campo en el archivo de import (name, address…).
type FieldError struct{ Field, Reason string }

func (e *FieldError) Error() string { return e.Reason }

func fe(field, format string, a ...any) *FieldError {
	return &FieldError{field, fmt.Sprintf(format, a...)}
}

// canonAddr valida una dirección (IP o nombre DNS, sin esquema, usuario, puerto ni ruta) y la deja canónica.
func canonAddr(a string) (string, error) {
	if a == "" || len(a) > 253 {
		return "", errors.New("la dirección va de 1 a 253 caracteres")
	}
	if ip, err := netip.ParseAddr(a); err == nil {
		if ip.Zone() != "" {
			return "", errors.New("la dirección no admite zona (%)")
		}
		return ip.Unmap().String(), nil
	}
	a = strings.ToLower(a)
	labels := strings.Split(a, ".")
	for _, l := range labels {
		if !dnsLabelRe.MatchString(l) {
			return "", fmt.Errorf("dirección %q: use una IP o un nombre DNS (letras, números y guiones), sin espacios, @, esquema, puerto ni ruta", a)
		}
	}
	if _, err := strconv.Atoi(labels[len(labels)-1]); err == nil { // «10.0.0.256»: parece IP, no es nombre
		return "", fmt.Errorf("dirección %q: parece una IP inválida", a)
	}
	return a, nil
}

// Clean valida un host y lo deja canónico (dirección en minúsculas o IP normalizada, puerto por defecto).
func Clean(h Host) (Host, error) {
	if n := utf8.RuneCountInString(h.Name); n < 1 || n > MaxHostName || h.Name != strings.TrimSpace(h.Name) || hasControl(h.Name, false) {
		return h, fe("name", "el nombre va de 1 a 64 caracteres, sin espacios en los extremos ni caracteres de control")
	}
	var err error
	if h.Address, err = canonAddr(h.Address); err != nil {
		return h, fe("address", "%s", err)
	}
	if h.Port == 0 {
		h.Port = DefaultPort
	}
	if h.Port < 1 || h.Port > 65535 {
		return h, fe("port", "el puerto va de 1 a 65535")
	}
	if h.Platform != "" && !slices.Contains(HostPlatforms, h.Platform) {
		return h, fe("platform", "plataforma %q fuera de la lista (%s)", h.Platform, strings.Join(HostPlatforms, ", "))
	}
	if h.Folder != "" && (!folderRe.MatchString(h.Folder) || h.Folder != strings.TrimSpace(h.Folder)) {
		return h, fe("folder", "la carpeta es de un solo nivel: 1 a 48 caracteres entre letras, números, espacio, _, . y -")
	}
	if len(h.Tags) > MaxHostTags {
		return h, fe("tags", "máximo %d etiquetas", MaxHostTags)
	}
	seen := map[string]bool{}
	for _, t := range h.Tags {
		if !hostTagRe.MatchString(t) || seen[t] {
			return h, fe("tags", "etiqueta %q inválida o repetida: 1 a 24 caracteres entre a-z, 0-9 y -", t)
		}
		seen[t] = true
	}
	if utf8.RuneCountInString(h.Notes) > MaxNotes || hasControl(h.Notes, true) {
		return h, fe("notes", "las notas pasan de %d caracteres o traen caracteres de control", MaxNotes)
	}
	if h.CredentialID != "" && !credIDRe.MatchString(h.CredentialID) {
		return h, fe("credential_id", "no es un id de la bóveda")
	}
	return h, nil
}
