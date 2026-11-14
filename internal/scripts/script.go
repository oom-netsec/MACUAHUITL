// Package scripts es la bóveda de scripts: comandos del usuario más una biblioteca predefinida,
// con favoritos aparte y export/import a un archivo (plan de la fase 28c).
//
// Un script nunca se aplica a un equipo desde aquí (ADR 0007): solo se expone ReadOnly para que
// Patrol decida si puede correrlo; la terminal inserta el texto sin Enter.
//
// No hace: persistir (lo hace el servicio), hablar con la red ni ejecutar comandos.
package scripts

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
)

const (
	OrigenBiblioteca = "biblioteca"
	OrigenUsuario    = "usuario"

	MaxName        = 64
	MaxDescription = 512
	MaxCommands    = 200
	MaxCommandLen  = 512
	MaxTags        = 10
)

// Techs y Platforms son listas cerradas.
var (
	Techs     = []string{"l2", "l3", "gestion", "seguridad", "qos", "etherchannel", "wireless", "diagnostico", "otro"}
	Platforms = []string{"ios", "ios-xe", "nx-os", "asa", "cualquiera"}
)

var (
	tagRe         = regexp.MustCompile(`^[a-z0-9-]{1,24}$`)
	userID        = regexp.MustCompile(`^[0-9a-f]{32}$`)
	libID         = regexp.MustCompile(`^lib-[a-z0-9-]{1,60}$`)
	errName error = i18n.New("scripts.err.name", nil)
)

// Script es una lista de comandos con nombre. El JSON es también el formato del archivo de export.
type Script struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Tech        string    `json:"tech"`
	Platform    string    `json:"platform"`
	Description string    `json:"description"`
	Commands    []string  `json:"commands"`
	Tags        []string  `json:"tags"`
	Origin      string    `json:"origin"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// NewID da un ID de usuario: 16 bytes aleatorios en hex.
func NewID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// IsLib dice si el ID es de la biblioteca (solo lectura).
func IsLib(id string) bool { return strings.HasPrefix(id, "lib-") }

func in(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func hasControl(s string, allowNL bool) bool {
	for _, r := range s {
		// Cf: formato (bidi, U+202E…) que cambia cómo se ve el texto sin cambiar lo que dice (trojan source).
		if (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) && !(allowNL && r == '\n') {
			return true
		}
	}
	return false
}

// Validate aplica las reglas de la fase: nombres, listas cerradas, topes y comandos en ASCII imprimible
// (IOS con 7 bits rompe lo demás).
func (s Script) Validate() error {
	if n := utf8.RuneCountInString(s.Name); n < 1 || n > MaxName || s.Name != strings.TrimSpace(s.Name) || hasControl(s.Name, false) {
		return errName
	}
	switch s.Origin {
	case OrigenBiblioteca:
		if !libID.MatchString(s.ID) {
			return i18n.New("scripts.err.lib_id", i18n.A("id", s.ID))
		}
	case OrigenUsuario:
		if !userID.MatchString(s.ID) {
			return i18n.New("scripts.err.user_id", i18n.A("id", s.ID))
		}
	default:
		return i18n.New("scripts.err.origin", i18n.A("origin", s.Origin))
	}
	if !in(Techs, s.Tech) {
		return i18n.New("scripts.err.tech", i18n.A("tech", s.Tech, "list", strings.Join(Techs, ", ")))
	}
	if !in(Platforms, s.Platform) {
		return i18n.New("scripts.err.platform", i18n.A("platform", s.Platform, "list", strings.Join(Platforms, ", ")))
	}
	if utf8.RuneCountInString(s.Description) > MaxDescription || hasControl(s.Description, true) {
		return i18n.New("scripts.err.description", i18n.A("max", MaxDescription))
	}
	if len(s.Commands) < 1 || len(s.Commands) > MaxCommands {
		return i18n.New("scripts.err.commands", i18n.A("max", MaxCommands))
	}
	for i, c := range s.Commands {
		if strings.TrimSpace(c) == "" || len(c) > MaxCommandLen {
			return i18n.New("scripts.err.command_empty", i18n.A("n", i+1, "max", MaxCommandLen))
		}
		for _, r := range c {
			if r < 0x20 || r > 0x7e {
				return i18n.New("scripts.err.command_ascii", i18n.A("n", i+1))
			}
		}
	}
	if len(s.Tags) > MaxTags {
		return i18n.New("scripts.err.tags_max", i18n.A("max", MaxTags))
	}
	seen := map[string]bool{}
	for _, t := range s.Tags {
		if !tagRe.MatchString(t) {
			return i18n.New("scripts.err.tag_bad", i18n.A("tag", t))
		}
		if seen[t] {
			return i18n.New("scripts.err.tag_dup", i18n.A("tag", t))
		}
		seen[t] = true
	}
	return nil
}

// Runnable devuelve los comandos que de verdad se escribirían en un equipo: sin las líneas de comentario.
// Una línea es comentario solo si empieza con «!» en la columna 0. Patrol debe usar esta misma regla.
func Runnable(cmds []string) []string {
	var out []string
	for _, c := range cmds {
		if !strings.HasPrefix(c, "!") {
			out = append(out, c)
		}
	}
	return out
}

// ReadOnly dice si todos los comandos pasan playbook.CheckDenied y ninguno trae «;».
// shortcut: CheckDenied solo modela IOS/IOS-XE, así que en nx-os, asa y cualquiera nunca es read_only;
// cuando CheckDenied tenga reglas por plataforma, medir «cualquiera» contra todas las concretas.
func (s Script) ReadOnly() bool {
	if s.Platform != "ios" && s.Platform != "ios-xe" {
		return false
	}
	cmds := Runnable(s.Commands)
	for _, c := range cmds {
		if strings.Contains(c, ";") || playbook.CheckDenied(s.Platform, c) != nil {
			return false
		}
	}
	return len(cmds) > 0
}

// NameKey es la clave con la que se comparan los nombres en todo el paquete y el servicio (sin importar
// mayúsculas): pasar por mayúsculas primero junta «ς» y «σ», que ToLower solo no junta.
func NameKey(n string) string { return strings.ToLower(strings.ToUpper(n)) }

// Same dice si dos scripts tienen el mismo contenido (ignora ID, origen y fechas).
func Same(a, b Script) bool {
	return a.Name == b.Name && a.Tech == b.Tech && a.Platform == b.Platform && a.Description == b.Description &&
		strings.Join(a.Commands, "\n") == strings.Join(b.Commands, "\n") && strings.Join(a.Tags, ",") == strings.Join(b.Tags, ",")
}
