// Package assist es el motor del modo de cambio asistido (ADR 0007): el plan de un cambio
// (pre-check, líneas, reversa, post-check y lo que se espera ver), su validación contra una
// lista cerrada por función y la máquina de estados que lo ejecuta con confirmación por paso.
//
// No hace: hablar con equipos (lo hace un Executor que pone el servicio), guardar en NVRAM salvo
// el paso explícito write memory, ni decidir qué se cambia (cada función arma su plan).
package assist

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/iosconf"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
)

// ErrInvalidPlan envuelve todo rechazo de Validate.
var ErrInvalidPlan = errors.New("assist: plan inválido")

// Expect es una condición sobre la salida de un comando de Post: que una línea aparezca
// (Present) o no. Prefix compara el comienzo de la línea, no la línea completa.
type Expect struct {
	Command string
	Line    string
	Present bool
	Prefix  bool
	// Column "status" evalúa la columna Status de `show interfaces X status` (no el texto de la línea):
	// Line es un estado (inactive, err-disabled) y Present dice si debe ser ese.
	Column string
}

// DevicePlan es todo lo que se hará en un equipo, definido antes de tocarlo.
type DevicePlan struct {
	Device   string
	Pre      []string // comandos de lectura
	Apply    []string // líneas de configuración
	Rollback []string // líneas de configuración; obligatoria y no vacía
	Post     []string // comandos de lectura
	Expect   []Expect // se evalúan sobre la salida de Post
	// Baseline guarda la salida de ciertos comandos de Pre al planear. Si el equipo ya no la
	// devuelve igual al aplicar, el plan caducó y la ejecución se detiene antes de cambiar nada.
	Baseline map[string]string
	// Secrets son textos que jamás pueden salir del núcleo (ni en la auditoría, ni en eventos, ni en errores, ni en el plan que
	// ve el cliente): las líneas de Apply y Rollback los llevan, pero todo lo demás los ve reemplazados.
	Secrets []string
	// Notes son avisos para el ingeniero (p. ej. que el enlace rebota); no se ejecutan ni se verifican.
	Notes []string
	// VerifyLogin: tras aplicar y pasar el post-check, el ejecutor abre una sesión nueva con la credencial nueva (Verifier).
	VerifyLogin bool
}

// Plan es un cambio completo de una función sobre uno o más equipos.
type Plan struct {
	Function string
	// WriteMemory agrega un paso final write memory por equipo, con su confirmación. Apagado por defecto.
	WriteMemory bool
	Devices     []DevicePlan
}

// Function declara qué líneas de configuración acepta una función del modo asistido.
type Function struct {
	Name string
	// Allowed son prefijos exactos: la línea es el prefijo o empieza con él y un espacio.
	Allowed []string
	// Check revisa los argumentos de una línea ya aceptada por prefijo; puede ser nil.
	Check func(line string) error
	// CheckDevice revisa el plan de un equipo completo (que la reversa sea la inversa exacta del apply); puede ser nil.
	CheckDevice func(d DevicePlan) error
	// Scrub quita de todo lo que sale del motor lo que IOS imprime tras secret/password, además de DevicePlan.Secrets.
	Scrub bool
	// AllowNo: las líneas de Allowed también se aceptan con un `no` delante (quitar lo que se agregó).
	AllowNo bool
}

// Lo que ninguna función puede enviar aunque su lista lo permita. Cada palabra se compara
// como abreviatura (IOS ejecuta cualquier prefijo único: "rel" es reload). do, end, exit,
// configure, write y copy sacan de la configuración o ejecutan fuera de ella.
var denied = [][]string{
	{"reload"}, {"write", "erase"}, {"erase"}, {"format"}, {"delete"}, {"boot"},
	{"crypto", "key", "zeroize"}, {"no", "username"}, {"no", "aaa"}, {"tclsh"}, {"event", "manager"},
	{"do"}, {"end"}, {"exit"}, {"configure"}, {"write"}, {"copy"}, {"archive"},
}

func abbrev(tok, word string) bool { return playbook.Abbrev(tok, word) }

func isDenied(line string) bool {
	f := strings.Fields(strings.ToLower(line))
	for _, d := range denied {
		if len(f) < len(d) {
			continue
		}
		match := true
		for i, w := range d {
			// "no" va completo: "n" no es "no" para IOS ni para esta lista.
			if i == 0 && w == "no" && f[0] != "no" || !abbrev(f[i], w) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func (fn Function) allows(line string) bool {
	l := strings.Join(strings.Fields(strings.ToLower(line)), " ")
	if fn.AllowNo {
		l = strings.TrimPrefix(l, "no ")
	}
	for _, p := range fn.Allowed {
		if l == p || strings.HasPrefix(l, p+" ") {
			return true
		}
	}
	return false
}

// asciiOnly rechaza toda runa fuera de 0x20-0x7e. IOS con exec-character-bits 7 quita el bit alto:
// en UTF-8 "Í" (C3 8D) llega como 'C' + CR y "Ê" (C3 8A) como LF, y una línea colaría otro comando.
func asciiOnly(s string) error {
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return fmt.Errorf("%q: tiene caracteres fuera de ASCII imprimible (0x20-0x7e)", s)
		}
	}
	return nil
}

// configLine revisa una línea de Apply o Rollback.
func (fn Function) configLine(line string) error {
	if err := asciiOnly(line); err != nil {
		return err
	}
	if strings.Contains(line, "?") {
		return fmt.Errorf("%q: '?' abre la ayuda de IOS sin Enter", line)
	}
	if strings.TrimSpace(line) == "" {
		return errors.New("línea en blanco")
	}
	if isDenied(line) {
		return fmt.Errorf("%q: comando prohibido en modo asistido", line)
	}
	if !fn.allows(line) {
		return fmt.Errorf("%q: fuera de la lista cerrada de %s", line, fn.Name)
	}
	if fn.Check != nil {
		if err := fn.Check(strings.TrimSpace(line)); err != nil {
			return fmt.Errorf("%q: %v", line, err)
		}
	}
	return nil
}

// Validate aplica las reglas 2 y 3 del ADR 0007: plan completo (con reversa) y solo líneas de
// la lista cerrada de la función. Reúne todos los problemas en un solo error.
func Validate(p Plan, fn Function) error {
	var bad []string
	add := func(dev, format string, a ...any) { bad = append(bad, dev+": "+fmt.Sprintf(format, a...)) }
	if p.Function != fn.Name {
		add("plan", "es de la función %q, no de %q", p.Function, fn.Name)
	}
	if len(p.Devices) == 0 {
		add("plan", "sin equipos")
	}
	for _, d := range p.Devices {
		name := d.Device
		if name == "" {
			add("equipo", "sin nombre")
		}
		for _, part := range []struct {
			n string
			l int
		}{{"Pre", len(d.Pre)}, {"Apply", len(d.Apply)}, {"Rollback (la reversa es obligatoria)", len(d.Rollback)},
			{"Post", len(d.Post)}, {"Expect", len(d.Expect)}} {
			if part.l == 0 {
				add(name, "falta %s", part.n)
			}
		}
		for _, c := range append(append([]string(nil), d.Pre...), d.Post...) {
			if err := asciiOnly(c); err != nil {
				add(name, "Pre/Post %v", err)
			} else if strings.TrimSpace(c) == "" {
				add(name, "comando de lectura en blanco")
			} else if err := playbook.CheckDenied("ios-xe", c); err != nil {
				add(name, "%v", err)
			}
		}
		if d.VerifyLogin && !p.WriteMemory {
			add(name, "una rotación de credenciales exige write memory: sin él el equipo vuelve al hash anterior al reiniciar y la bóveda queda con el nuevo")
		}
		for _, l := range d.Apply {
			if err := fn.configLine(l); err != nil {
				add(name, "Apply %v", err)
			}
		}
		for _, l := range d.Rollback {
			if err := fn.configLine(l); err != nil {
				add(name, "Rollback %v", err)
			}
		}
		if fn.CheckDevice != nil {
			if err := fn.CheckDevice(d); err != nil {
				add(name, "%v", err)
			}
		}
		post := map[string]bool{}
		for _, c := range d.Post {
			post[c] = true
		}
		for _, e := range d.Expect {
			if !post[e.Command] || strings.TrimSpace(e.Line) == "" {
				add(name, "Expect %q no corresponde a un comando de Post", e.Command)
			}
		}
	}
	if len(bad) == 0 {
		return nil
	}
	// El error viaja al cliente y puede citar líneas de Apply o Rollback: ahí van los secretos.
	var secrets []string
	for _, d := range p.Devices {
		secrets = append(secrets, d.Secrets...)
	}
	return fmt.Errorf("%w: %s", ErrInvalidPlan, Scrub(strings.Join(bad, "; "), secrets, fn.Scrub))
}

// EvalExpect devuelve cada condición que no se cumple, con la salida de cada comando de Post.
func EvalExpect(ex []Expect, outputs map[string]string) []string {
	var fails []string
	parsed := map[string]*iosconf.Node{}
	states := map[string]cfgState{}
	for _, e := range ex {
		text, ran := outputs[e.Command]
		if e.Column == "section-hash" && ran {
			// La sección entera del running (Line es «sección␟hash», o solo el hash para la global) contra la simulada.
			st, ok := states[e.Command]
			if !ok {
				st = stateOf(parseCfg(text))
				states[e.Command] = st
			}
			parts := strings.Split(e.Line, expectSep)
			path := parts[:len(parts)-1]
			if (sectionHash(st.lists[pathKey(path)]) == parts[len(parts)-1]) != e.Present {
				where := "global"
				if len(path) > 0 {
					where = strings.Join(path, " > ")
				}
				fails = append(fails, fmt.Sprintf("en %q la sección %q no quedó como se esperaba tras aplicar (alguna otra línea cambió o falta)", e.Command, where))
			}
			continue
		}
		if e.Column == "section-line" && ran {
			// Una línea dentro de su sección del running-config (Line es «sección␟línea»).
			root, ok := parsed[e.Command]
			if !ok {
				root = parseCfg(text)
				parsed[e.Command] = root
			}
			shown := strings.ReplaceAll(e.Line, expectSep, " > ")
			if found := sectionHas(root, strings.Split(e.Line, expectSep)); found != e.Present && e.Present {
				fails = append(fails, fmt.Sprintf("en %q debía aparecer %q", e.Command, shown))
			} else if found != e.Present {
				fails = append(fails, fmt.Sprintf("en %q no debía aparecer %q", e.Command, shown))
			}
			continue
		}
		if e.Column == "status" && ran {
			rows, _ := iosxe.ParseIfStatus(text)
			switch {
			case len(rows) == 0:
				fails = append(fails, fmt.Sprintf("en %q no se pudo leer el estado del puerto", e.Command))
			case (rows[0].Status == e.Line) != e.Present && e.Present:
				fails = append(fails, fmt.Sprintf("en %q el estado debía ser %q y es %q", e.Command, e.Line, rows[0].Status))
			case (rows[0].Status == e.Line) != e.Present:
				fails = append(fails, fmt.Sprintf("en %q el puerto quedó %q", e.Command, rows[0].Status))
			}
			continue
		}
		if m, ok := columnMatch(e, text); ran && e.Column != "" {
			switch {
			case !ok:
				fails = append(fails, fmt.Sprintf("en %q no se pudo leer %s", e.Command, e.Column))
			case m != e.Present && e.Present:
				fails = append(fails, fmt.Sprintf("en %q debía cumplirse %s %q", e.Command, e.Column, e.Line))
			case m != e.Present:
				fails = append(fails, fmt.Sprintf("en %q no debía cumplirse %s %q", e.Command, e.Column, e.Line))
			}
			continue
		}
		found := false
		for _, l := range strings.Split(text, "\n") {
			l = strings.TrimSpace(l)
			if l == e.Line || e.Prefix && strings.HasPrefix(l, e.Line) {
				found = true
				break
			}
		}
		switch {
		case !ran:
			fails = append(fails, fmt.Sprintf("%q no corrió", e.Command))
		case found != e.Present && e.Present:
			fails = append(fails, fmt.Sprintf("en %q debía aparecer %q", e.Command, e.Line))
		case found != e.Present:
			fails = append(fails, fmt.Sprintf("en %q no debía aparecer %q", e.Command, e.Line))
		}
	}
	return fails
}

var vlanNotFoundRe = regexp.MustCompile(`VLAN id (\d+) not found in current VLAN database`)

// columnMatch evalúa las condiciones que no son una línea de texto: vlan ("ID NOMBRE" activa en show vlan), trunk-allowed (la VLAN
// está permitida en el trunk), static-route, logging-host y snmp-user (fase 28d, l3ColumnMatch) y user-secret ("USUARIO TIPO", TIPO 5, 8, 9 o * para cualquier hash). ok=false si la salida no se pudo leer.
// Nunca cita hashes: un fallo dice usuario y tipo, no la línea.
func columnMatch(e Expect, text string) (match, ok bool) {
	switch e.Column {
	case "vlan", "vlan-id":
		id, name, _ := strings.Cut(e.Line, " ")
		rows, ok := iosxe.ParseVlanBrief(text)
		// Una VLAN que no existe se contesta «VLAN id N not found...»: vale como ausente solo si N es la de la condición.
		if m := vlanNotFoundRe.FindStringSubmatch(text); !ok && m != nil {
			return false, m[1] == id
		}
		for _, r := range rows {
			if ntoa(r.ID) == id && (e.Column == "vlan-id" || r.Name == name && r.Status == "active") {
				return true, ok
			}
		}
		return false, ok
	case "trunk-allowed":
		cur, ok := iosxe.ParseInterfaceConfig(text)
		n, err := strconv.Atoi(e.Line)
		if !ok || err != nil {
			return false, false
		}
		set, all := iosxe.TrunkAllowedSet(cur.TrunkAllowed)
		return all || set[n], true
	case "static-route", "logging-host", "snmp-user":
		return l3ColumnMatch(e, text)
	case "user-secret":
		user, typ, _ := strings.Cut(e.Line, " ")
		for _, u := range iosxe.ParseUsernames(text) {
			if u.Name == user && u.Kind == "secret" && (typ == "*" && (u.Type == "5" || u.Type == "8" || u.Type == "9") || u.Type == typ) {
				return true, true
			}
		}
		return false, true
	}
	return false, e.Column == "status"
}

// sectionHas dice si la última línea de path está entre las hijas de la sección que forman las anteriores.
func sectionHas(root *iosconf.Node, path []string) bool {
	n := root
	for _, p := range path[:len(path)-1] {
		var next *iosconf.Node
		for _, c := range n.Children {
			if c.Line == p {
				next = c
				break
			}
		}
		if next == nil {
			return false
		}
		n = next
	}
	for _, c := range n.Children {
		if c.Line == path[len(path)-1] {
			return true
		}
	}
	return false
}
