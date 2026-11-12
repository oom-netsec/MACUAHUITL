package assist

import (
	"errors"
	"strings"
	"testing"
)

const (
	oldHash9 = "$9$Zq2k8Rw9$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	newSec   = "Nuev0-Secreto.2026"
)

func usersOut(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

func rotOuts(users, version string) map[string]string {
	return map[string]string{credUsersCmd: users, "show version": version}
}

const xe17 = "Cisco IOS XE Software, Version 17.03.04a\nCisco IOS Software [Amsterdam], Catalyst L3 Switch Software\n"
const ios15 = "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)\n"

func TestCredRotatePlanUsesPreviousHashAndHidesNothingFromTheCore(t *testing.T) {
	outs := rotOuts(usersOut("username admin privilege 15 secret 9 $9$otro$xyz", "username tech privilege 15 secret 9 "+oldHash9), xe17)
	dp, err := CredRotatePlan("SW1", CredRotateChange{User: "tech", NewSecret: newSec, ConnectedUser: "admin"}, outs)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(dp.Apply, "|"); got != "username tech privilege 15 algorithm-type scrypt secret "+newSec {
		t.Errorf("Apply = %s", got)
	}
	if got := strings.Join(dp.Rollback, "|"); got != "username tech privilege 15 secret 9 "+oldHash9 {
		t.Errorf("Rollback = %s", got)
	}
	if !dp.VerifyLogin {
		t.Error("la rotación exige verificar la credencial nueva con una sesión nueva")
	}
	has := func(s string) bool {
		for _, x := range dp.Secrets {
			if x == s {
				return true
			}
		}
		return false
	}
	if !has(newSec) || !has(oldHash9) {
		t.Errorf("Secrets debe traer el secreto nuevo y el hash previo: %v", dp.Secrets)
	}
	if err := Validate(Plan{Function: CredRotate.Name, WriteMemory: true, Devices: []DevicePlan{dp}}, CredRotate); err != nil {
		t.Fatal(err)
	}
}

func TestCredRotateAlgorithmDecidedInPre(t *testing.T) {
	line := func(user, ver string) string {
		dp, err := CredRotatePlan("SW1", CredRotateChange{User: "tech", NewSecret: newSec, ConnectedUser: "admin"}, rotOuts(usersOut(user), ver))
		if err != nil {
			t.Fatal(err)
		}
		return dp.Apply[0]
	}
	for name, c := range map[string][3]string{
		"tipo 9 se conserva":                       {"username tech secret 9 $9$a$b", ios15, "username tech algorithm-type scrypt secret " + newSec},
		"tipo 8 se conserva":                       {"username tech secret 8 $8$a$b", ios15, "username tech algorithm-type sha256 secret " + newSec},
		"tipo 5 en IOS-XE moderno sube a tipo 9":   {"username tech secret 5 $1$a$b", xe17, "username tech algorithm-type scrypt secret " + newSec},
		"tipo 5 en IOS clásico se queda como está": {"username tech secret 5 $1$a$b", ios15, "username tech secret " + newSec},
		"sin versión legible se queda como está":   {"username tech privilege 1 secret 5 $1$a$b", "", "username tech privilege 1 secret " + newSec},
	} {
		if got := line(c[0], c[1]); got != c[2] {
			t.Errorf("%s: %q, se esperaba %q", name, got, c[2])
		}
	}
}

func TestCredRotateRefusals(t *testing.T) {
	ok := usersOut("username admin privilege 15 secret 9 $9$x$y", "username tech privilege 15 secret 9 "+oldHash9)
	try := func(user, connected, secret string, outs map[string]string) error {
		_, err := CredRotatePlan("SW1", CredRotateChange{User: user, NewSecret: secret, ConnectedUser: connected}, outs)
		return err
	}
	if err := try("tech", "admin", newSec, rotOuts(ok, xe17)); err != nil {
		t.Fatal(err)
	}
	if err := try("admin", "admin", newSec, rotOuts(ok, xe17)); !errors.Is(err, ErrRotateRefused) {
		t.Errorf("rotar al usuario con el que se está conectado: %v", err)
	}
	if err := try("ADMIN", "admin", newSec, rotOuts(ok, xe17)); !errors.Is(err, ErrRotateRefused) {
		t.Errorf("mayúsculas: %v", err)
	}
	if err := try("nadie", "admin", newSec, rotOuts(ok, xe17)); !errors.Is(err, ErrRotateRefused) {
		t.Errorf("usuario que no existe (eso sería crearlo): %v", err)
	}
	legacy := usersOut("username tech password 7 0822455D0A16")
	if err := try("tech", "admin", newSec, rotOuts(legacy, xe17)); !errors.Is(err, ErrRotateRefused) {
		t.Errorf("usuario con password: la reversa no quedaría igual: %v", err)
	}
	if err := try("tech", "admin", newSec, rotOuts(usersOut("username tech nopassword"), xe17)); !errors.Is(err, ErrRotateRefused) {
		t.Errorf("nopassword: %v", err)
	}
	// Dos líneas del mismo usuario (secret y password a la vez) es una configuración ambigua.
	if err := try("tech", "admin", newSec, rotOuts(usersOut("username tech secret 9 $9$a$b", "username tech password 7 0822455D0A16"), xe17)); !errors.Is(err, ErrRotateRefused) {
		t.Errorf("usuario repetido: %v", err)
	}
	// Sin la salida de los usuarios no se planea.
	if err := try("tech", "admin", newSec, map[string]string{}); err == nil {
		t.Error("sin captura")
	}
	// Quien se conecta no se conoce: no se puede garantizar que no sea el rotado.
	if _, err := CredRotatePlan("SW1", CredRotateChange{User: "tech", NewSecret: newSec}, rotOuts(ok, xe17)); !errors.Is(err, ErrRotateRefused) {
		t.Errorf("sin usuario conectado: %v", err)
	}
}

func TestCredRotateValidatesUserAndSecret(t *testing.T) {
	outs := rotOuts(usersOut("username tech secret 9 "+oldHash9), xe17)
	for _, s := range []string{"", "corta", "con espacio 123", "tiene?signo1", "ñandúñandú1", "comilla\"larga1", "barra\\larga123", "pipe|largo123", "dolar$largo123", "tab\tlargo1234", strings.Repeat("a", 65), "a\rlargo12345", "bang!largo123"} {
		if _, err := CredRotatePlan("SW1", CredRotateChange{User: "tech", NewSecret: s, ConnectedUser: "admin"}, outs); err == nil {
			t.Errorf("secreto %q aceptado", s)
		}
	}
	for _, u := range []string{"", "con espacio", "a;b", "ñ", "t?", strings.Repeat("u", 33)} {
		if _, err := CredRotatePre(u); err == nil {
			t.Errorf("usuario %q aceptado", u)
		}
	}
}

func TestGenerateSecretIsValidAndRandom(t *testing.T) {
	a, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GenerateSecret()
	if a == b || len(a) < 20 {
		t.Errorf("a=%q b=%q", a, b)
	}
	if err := checkSecret(a); err != nil {
		t.Errorf("el secreto generado no pasa la validación: %v", err)
	}
}

func TestCredRotateClosedListRejectsOtherUsersAndForms(t *testing.T) {
	plan := func(apply, rollback []string) error {
		dp := DevicePlan{Device: "SW1", Pre: []string{credUsersCmd}, Apply: apply, Rollback: rollback, Post: []string{credUsersCmd},
			Expect: []Expect{{Command: credUsersCmd, Line: "tech 9", Column: "user-secret", Present: true}}, VerifyLogin: true, Secrets: []string{newSec}}
		return Validate(Plan{Function: CredRotate.Name, WriteMemory: true, Devices: []DevicePlan{dp}}, CredRotate)
	}
	ap := "username tech privilege 15 algorithm-type scrypt secret " + newSec
	rb := "username tech privilege 15 secret 9 " + oldHash9
	if err := plan([]string{ap}, []string{rb}); err != nil {
		t.Fatal(err)
	}
	bad := map[string][2][]string{
		"otro usuario en la reversa": {{ap}, {"username admin privilege 15 secret 9 " + oldHash9}},
		"dos usuarios":               {{ap, "username admin secret " + newSec}, {rb}},
		"no username":                {{"no username tech"}, {rb}},
		"password en el apply":       {{"username tech password " + newSec}, {rb}},
		"secreto corto":              {{"username tech secret corto"}, {rb}},
		"apply con hash":             {{rb}, {rb}},
		"reversa con secreto plano":  {{ap}, {ap}},
		"reversa con tipo inválido":  {{ap}, {"username tech secret 4 " + oldHash9}},
		"nopassword":                 {{"username tech nopassword"}, {rb}},
		"autocommand":                {{ap + " autocommand show version"}, {rb}},
		"usuario con espacios":       {{"username  secret " + newSec}, {rb}},
		"tipo desconocido":           {{"username tech algorithm-type md4 secret " + newSec}, {rb}},
		"reversa vacía":              {{ap}, nil},
		"aaa":                        {{"aaa new-model"}, {rb}},
		"enable secret":              {{"enable secret " + newSec}, {rb}},
		"privilegio no numérico":     {{"username tech privilege abc secret " + newSec}, {rb}},
		"privilegio fuera de 0-15":   {{"username tech privilege 16 secret " + newSec}, {rb}},
	}
	for name, p := range bad {
		if err := plan(p[0], p[1]); !errors.Is(err, ErrInvalidPlan) {
			t.Errorf("%s: se aceptó (%v)", name, err)
		}
	}
}

// El mensaje de rechazo viaja al cliente: no puede llevar el secreto ni el hash.
func TestValidateErrorNeverLeaksSecretOrHash(t *testing.T) {
	dp := DevicePlan{Device: "SW1", Pre: []string{credUsersCmd}, Apply: []string{"username tech secret " + newSec, "username otro secret " + newSec}, Rollback: []string{"username tech secret 4 " + oldHash9},
		Post: []string{credUsersCmd}, Expect: []Expect{{Command: credUsersCmd, Line: "tech *", Column: "user-secret", Present: true}}, VerifyLogin: true, Secrets: []string{newSec, oldHash9}}
	err := Validate(Plan{Function: CredRotate.Name, WriteMemory: true, Devices: []DevicePlan{dp}}, CredRotate)
	if !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("debía rechazar: %v", err)
	}
	for _, s := range []string{newSec, oldHash9} {
		if strings.Contains(err.Error(), s) {
			t.Errorf("el error filtra %q: %v", s, err)
		}
	}
	// Aunque la lista de secretos no venga completa, el filtro de IOS quita lo que sigue a secret/password.
	dp.Secrets = nil
	err = Validate(Plan{Function: CredRotate.Name, WriteMemory: true, Devices: []DevicePlan{dp}}, CredRotate)
	if err == nil || strings.Contains(err.Error(), newSec) || strings.Contains(err.Error(), oldHash9) {
		t.Errorf("sin lista de secretos: %v", err)
	}
}

func TestEvalExpectUserSecret(t *testing.T) {
	out := usersOut("username tech privilege 15 secret 9 $9$a$b", "username admin secret 5 $1$x$y")
	ex := func(line string, present bool) []Expect {
		return []Expect{{Command: credUsersCmd, Line: line, Present: present, Column: "user-secret"}}
	}
	m := map[string]string{credUsersCmd: out}
	if f := EvalExpect(ex("tech 9", true), m); len(f) != 0 {
		t.Errorf("tech tipo 9: %v", f)
	}
	if f := EvalExpect(ex("tech *", true), m); len(f) != 0 {
		t.Errorf("tech cualquier tipo: %v", f)
	}
	if f := EvalExpect(ex("tech 8", true), m); len(f) == 0 {
		t.Error("tech no es tipo 8")
	}
	if f := EvalExpect(ex("nadie *", true), m); len(f) == 0 {
		t.Error("el usuario no existe")
	}
	if f := EvalExpect(ex("tech 9", true), map[string]string{credUsersCmd: "username tech password 7 0822455D0A16\n"}); len(f) == 0 {
		t.Error("password no es secret")
	}
	for _, f := range EvalExpect(ex("nadie *", true), m) {
		if strings.Contains(f, "$9$") {
			t.Errorf("el fallo muestra un hash: %s", f)
		}
	}
}

// El filtro genérico oculta hasta el final de la línea: una contraseña con espacios no deja cola visible.
func TestScrubHidesTheWholeLineAfterSecretOrPassword(t *testing.T) {
	for in, tail := range map[string]string{
		"username bob password 0 hola mundo":             "mundo",
		"username bob privilege 15 secret 9 $9$ab cd ef": "ef",
		"username bob SECRET 5 $1$x y z":                 "z",
		"username bob password hola mundo":               "mundo",
	} {
		if got := Scrub(in, nil, true); strings.Contains(got, tail) || !strings.Contains(got, hidden) {
			t.Errorf("%q -> %q", in, got)
		}
	}
	// Solo la línea afectada; lo anterior y las otras líneas quedan.
	got := Scrub("username bob privilege 15 secret 9 H1\nline vty 0 4", nil, true)
	if got != "username bob privilege 15 secret "+hidden+"\nline vty 0 4" {
		t.Errorf("%q", got)
	}
}

// La reversa solo repite `privilege N` y el hash: cualquier otro atributo de la línea se perdería al revertir.
func TestCredRotateRefusesUsersWithAttributesTheRollbackWouldDrop(t *testing.T) {
	for _, line := range []string{
		"username tech privilege 15 view ops secret 9 " + oldHash9,
		"username tech privilege 15 secret 9 " + oldHash9 + " autocommand show version",
		"username tech privilege 15 algorithm-type scrypt secret 9 " + oldHash9,
		"username tech secret 9 " + oldHash9 + " view ops",
	} {
		_, err := CredRotatePlan("SW1", CredRotateChange{User: "tech", NewSecret: newSec, ConnectedUser: "admin"}, rotOuts(usersOut(line), xe17))
		if !errors.Is(err, ErrRotateRefused) {
			t.Errorf("%q: %v", line, err)
		}
		if err != nil && strings.Contains(err.Error(), oldHash9) {
			t.Errorf("el error muestra el hash: %v", err)
		}
	}
}
