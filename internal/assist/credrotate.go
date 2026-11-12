package assist

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/mask"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// ErrRotateRefused: la rotación no es segura en este equipo o para este usuario.
var ErrRotateRefused = errors.New("assist: no se puede rotar esa credencial")

const (
	credUsersCmd = "show running-config | include ^username"
	hidden       = "<oculto>"
)

var (
	userRe      = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)
	secretRe    = regexp.MustCompile(`^[A-Za-z0-9._~@%^&*()+=:,-]{8,64}$`)
	hashRe      = regexp.MustCompile(`^[\x21-\x7e]{4,200}$`)
	xeVersionRe = regexp.MustCompile(`Cisco IOS XE Software, Version (\d+)\.`)
	// secretTail es todo lo que sigue a secret o password hasta el final de la línea (una clave puede traer espacios).
	secretTail = regexp.MustCompile(`(?i)\b(secret|password)[ \t]+[^\r\n]*`)
)

// Scrub reemplaza en s cada uno de secrets y, con generic, lo que sigue a secret/password.
func Scrub(s string, secrets []string, generic bool) string {
	for _, x := range secrets {
		if x != "" {
			s = strings.ReplaceAll(s, x, hidden)
		}
	}
	if generic {
		// Primero las reglas de enmascarado por plataforma (comunidades SNMP, llaves TACACS/RADIUS, claves OSPF/NTP...), luego lo que sigue a secret/password.
		s, _ = mask.Apply("ios-xe", s)
		s = secretTail.ReplaceAllString(s, "$1 "+hidden)
	}
	return s
}

// Redact devuelve una copia del plan apta para mostrarse o enviarse a un cliente: sin Secrets ni Baseline y con las líneas
// ya filtradas. El plan original (con los secretos) nunca sale del núcleo.
func Redact(p Plan, fn Function) Plan {
	out := p
	out.Devices = nil
	for _, d := range p.Devices {
		c := d
		c.Apply, c.Rollback = scrubAll(d.Apply, d.Secrets, fn.Scrub), scrubAll(d.Rollback, d.Secrets, fn.Scrub)
		c.Expect = nil
		for _, e := range d.Expect { // lo esperado también cita la línea aplicada (p. ej. la community SNMP)
			e.Line = Scrub(e.Line, d.Secrets, fn.Scrub)
			c.Expect = append(c.Expect, e)
		}
		c.Secrets, c.Baseline = nil, nil
		out.Devices = append(out.Devices, c)
	}
	return out
}

func scrubAll(lines, secrets []string, generic bool) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = Scrub(l, secrets, generic)
	}
	return out
}

func checkSecret(s string) error {
	if !secretRe.MatchString(s) {
		return errors.New("el secreto nuevo mide de 8 a 64 caracteres y solo lleva letras, números y ._~@%^&*()+=:,-")
	}
	return nil
}

// ValidateSecret dice si s sirve como secreto nuevo (la misma regla de CredRotatePlan, para rechazar antes de conectar).
func ValidateSecret(s string) error { return checkSecret(s) }

// ValidUser dice si user es un nombre de usuario local que la rotación acepta.
func ValidUser(user string) bool { return userRe.MatchString(user) }

// GenerateSecret da un secreto aleatorio de 24 caracteres alfanuméricos.
func GenerateSecret() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	b := make([]byte, 24)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b[i] = alphabet[n.Int64()]
	}
	return string(b), nil
}

// parseCredLine revisa `username U [privilege N] [algorithm-type scrypt|sha256] secret S` (plano) o
// `username U [privilege N] secret T HASH` (hash=true, T en 5, 8, 9) y devuelve el usuario.
func parseCredLine(line string) (user string, hash bool, err error) {
	f := strings.Fields(line)
	if len(f) < 4 || !strings.EqualFold(f[0], "username") {
		return "", false, errors.New("no reconocida")
	}
	user = f[1]
	if !userRe.MatchString(user) {
		return "", false, errors.New("nombre de usuario inválido")
	}
	i := 2
	if strings.EqualFold(f[i], "privilege") {
		if i+1 >= len(f) {
			return "", false, errors.New("falta el nivel")
		}
		n, e := strconv.Atoi(f[i+1])
		if e != nil || n < 0 || n > 15 || ntoa(n) != f[i+1] {
			return "", false, errors.New("nivel de privilegio fuera de 0-15")
		}
		i += 2
	}
	alg := ""
	if i < len(f) && strings.EqualFold(f[i], "algorithm-type") {
		if i+1 >= len(f) || (f[i+1] != "scrypt" && f[i+1] != "sha256") {
			return "", false, errors.New("algorithm-type scrypt o sha256")
		}
		alg, i = f[i+1], i+2
	}
	if i >= len(f) || !strings.EqualFold(f[i], "secret") {
		return "", false, errors.New("solo `secret` (nunca password, nopassword ni opciones extra)")
	}
	switch rest := f[i+1:]; len(rest) {
	case 1:
		return user, false, checkSecret(rest[0])
	case 2:
		if alg != "" || (rest[0] != "5" && rest[0] != "8" && rest[0] != "9") || !hashRe.MatchString(rest[1]) || strings.Contains(rest[1], "?") {
			return "", false, errors.New("la reversa lleva `secret 5|8|9 HASH` sin algorithm-type")
		}
		return user, true, nil
	}
	return "", false, errors.New("sobran argumentos")
}

// CredRotate rota la contraseña de un usuario local: `username U secret S` y, para la reversa, el hash previo.
var CredRotate = Function{
	Name:    "credrotate",
	Allowed: []string{"username"},
	Scrub:   true,
	Check: func(line string) error {
		_, _, err := parseCredLine(line)
		return err
	},
	CheckDevice: func(d DevicePlan) error {
		if len(d.Apply) != 1 || len(d.Rollback) != 1 {
			return errors.New("la rotación es una línea de apply y una de reversa")
		}
		u1, h1, e1 := parseCredLine(d.Apply[0])
		u2, h2, e2 := parseCredLine(d.Rollback[0])
		switch {
		case e1 != nil || e2 != nil:
			return errors.New("líneas de usuario inválidas")
		case u1 != u2:
			return errors.New("el apply y la reversa deben ser del mismo usuario")
		case h1 || !h2:
			return errors.New("el apply lleva el secreto nuevo y la reversa el hash previo")
		case !d.VerifyLogin:
			return errors.New("la rotación exige verificar la credencial nueva con una sesión nueva")
		case len(d.Secrets) == 0:
			return errors.New("faltan los secretos que deben ocultarse")
		}
		return nil
	},
}

// CredRotateChange: rotar a User el secreto NewSecret. ConnectedUser es el usuario de la sesión que ejecuta el cambio.
type CredRotateChange struct{ User, NewSecret, ConnectedUser string }

// CredRotatePre: los usuarios locales del running-config y la versión (de ahí sale el algoritmo).
func CredRotatePre(user string) ([]string, error) {
	if !userRe.MatchString(user) {
		return nil, fmt.Errorf("usuario %q inválido (letras, números, . _ -; hasta 32)", user)
	}
	return []string{credUsersCmd, "show version"}, nil
}

// credAlgorithm decide en Pre qué algoritmo usar: el que ya tiene el usuario si es 8 o 9 (el equipo lo acepta); si no, tipo 9
// (scrypt) en IOS-XE 16 o posterior y, en cualquier otro caso, el que el equipo use por omisión.
func credAlgorithm(oldType, version string) string {
	switch {
	case oldType == "9":
		return "scrypt"
	case oldType == "8":
		return "sha256"
	}
	if m := xeVersionRe.FindStringSubmatch(version); m != nil {
		if n, _ := strconv.Atoi(m[1]); n >= 16 {
			return "scrypt"
		}
	}
	return ""
}

// CredRotatePlan arma el plan de rotación. Nunca rota al usuario de la sesión que ejecuta (si la credencial nueva fallara no habría
// por dónde revertir) ni a uno que no existe, que usa password o que no tiene contraseña. La reversa lleva el hash previo tal como está
// en el running-config; el hash y el secreto nuevo van en Secrets para que nada los muestre.
func CredRotatePlan(device string, c CredRotateChange, outs map[string]string) (DevicePlan, error) {
	pre, err := CredRotatePre(c.User)
	if err != nil {
		return DevicePlan{}, err
	}
	if err := checkSecret(c.NewSecret); err != nil {
		return DevicePlan{}, err
	}
	if c.ConnectedUser == "" || strings.EqualFold(c.ConnectedUser, c.User) {
		return DevicePlan{}, fmt.Errorf("%w: el usuario %q es el de la sesión que ejecuta el cambio; conéctate con otra credencial para poder revertir", ErrRotateRefused, c.User)
	}
	text, ok := outs[credUsersCmd]
	if !ok {
		return DevicePlan{}, fmt.Errorf("falta la salida de %q", credUsersCmd)
	}
	var found []iosxe.UserLine
	for _, u := range iosxe.ParseUsernames(text) {
		if u.Name == c.User {
			found = append(found, u)
		}
	}
	if len(found) != 1 {
		return DevicePlan{}, fmt.Errorf("%w: %s tiene %d líneas username para %q (se necesita exactamente una; crear usuarios no es rotar)", ErrRotateRefused, device, len(found), c.User)
	}
	u := found[0]
	if u.NoPassword || u.Kind != "secret" || (u.Type != "5" && u.Type != "8" && u.Type != "9") || u.Hash == "" {
		return DevicePlan{}, fmt.Errorf("%w: %q no usa `secret` con hash 5, 8 o 9 (con password la reversa no dejaría el equipo igual)", ErrRotateRefused, c.User)
	}
	if len(u.Extra) > 0 {
		return DevicePlan{}, fmt.Errorf("%w: la línea de %q trae atributos que la reversa no repetiría (view, autocommand, algorithm-type u otros): no se rota", ErrRotateRefused, c.User)
	}
	alg := credAlgorithm(u.Type, outs["show version"])
	priv := ""
	if u.Privilege != "" {
		priv = " privilege " + u.Privilege
	}
	apply := "username " + c.User + priv
	want := "*"
	switch alg {
	case "scrypt":
		want = "9"
	case "sha256":
		want = "8"
	}
	if alg != "" {
		apply += " algorithm-type " + alg
	}
	dp := DevicePlan{Device: device, Pre: pre, Baseline: map[string]string{credUsersCmd: text}, VerifyLogin: true,
		Apply:    []string{apply + " secret " + c.NewSecret},
		Rollback: []string{"username " + c.User + priv + " secret " + u.Type + " " + u.Hash},
		Post:     []string{credUsersCmd},
		Expect:   []Expect{{Command: credUsersCmd, Line: c.User + " " + want, Present: true, Column: "user-secret"}},
		Secrets:  []string{c.NewSecret, u.Hash}}
	if err := Validate(Plan{Function: CredRotate.Name, WriteMemory: true, Devices: []DevicePlan{dp}}, CredRotate); err != nil {
		return DevicePlan{}, err
	}
	return dp, nil
}
