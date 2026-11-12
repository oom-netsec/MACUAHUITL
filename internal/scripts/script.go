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
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
	tagRe   = regexp.MustCompile(`^[a-z0-9-]{1,24}$`)
	userID  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	libID   = regexp.MustCompile(`^lib-[a-z0-9-]{1,60}$`)
	errName = errors.New("el nombre va de 1 a 64 caracteres, sin espacios en los extremos ni caracteres de control")
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
		if unicode.IsControl(r) && !(allowNL && r == '\n') {
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
			return fmt.Errorf("id %q inválido para un script de la biblioteca", s.ID)
		}
	case OrigenUsuario:
		if !userID.MatchString(s.ID) {
			return fmt.Errorf("id %q inválido: son 32 caracteres hexadecimales", s.ID)
		}
	default:
		return fmt.Errorf("origen %q desconocido", s.Origin)
	}
	if !in(Techs, s.Tech) {
		return fmt.Errorf("tecnología %q fuera de la lista (%s)", s.Tech, strings.Join(Techs, ", "))
	}
	if !in(Platforms, s.Platform) {
		return fmt.Errorf("plataforma %q fuera de la lista (%s)", s.Platform, strings.Join(Platforms, ", "))
	}
	if utf8.RuneCountInString(s.Description) > MaxDescription || hasControl(s.Description, true) {
		return fmt.Errorf("la descripción pasa de %d caracteres o trae caracteres de control", MaxDescription)
	}
	if len(s.Commands) < 1 || len(s.Commands) > MaxCommands {
		return fmt.Errorf("el script lleva de 1 a %d comandos", MaxCommands)
	}
	for i, c := range s.Commands {
		if strings.TrimSpace(c) == "" || len(c) > MaxCommandLen {
			return fmt.Errorf("comando %d: vacío o de más de %d caracteres", i+1, MaxCommandLen)
		}
		for _, r := range c {
			if r < 0x20 || r > 0x7e {
				return fmt.Errorf("comando %d: solo ASCII imprimible, sin tabuladores ni caracteres de control", i+1)
			}
		}
	}
	if len(s.Tags) > MaxTags {
		return fmt.Errorf("máximo %d etiquetas", MaxTags)
	}
	seen := map[string]bool{}
	for _, t := range s.Tags {
		if !tagRe.MatchString(t) {
			return fmt.Errorf("etiqueta %q inválida: minúsculas, dígitos y guion, de 1 a 24", t)
		}
		if seen[t] {
			return fmt.Errorf("etiqueta %q repetida", t)
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
