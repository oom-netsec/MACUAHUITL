package assist

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/iosconf"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// Restaurar por diff (fase 16c): lleva el running-config del equipo al de un respaldo cambiando solo las líneas que difieren, dentro de su
// sección. La reversa es el diff inverso calculado del running capturado en Pre. La lista cerrada (restore_rules.go) decide qué se aplica;
// CheckDevice simula el apply y la reversa sobre la línea base y exige que cada línea sea de la lista cerrada y que la reversa cierre el círculo.

// ErrRestoreRefused: el respaldo no se puede restaurar (enmascarado, de otro equipo, con cambios peligrosos).
var ErrRestoreRefused = errors.New("assist: no se puede restaurar ese respaldo")

// ErrNoDifference: el equipo ya coincide con el respaldo.
var ErrNoDifference = errors.New("assist: el equipo ya coincide con el respaldo")

const (
	// RestoreDiff es el nombre de la función; cada plan lleva su propia Function (con la gestión, las VLAN activas y el tope).
	RestoreDiff = "restore-diff"
	// DefaultRestoreLines es el tope de líneas de cambio por plan si la petición no dice otro.
	DefaultRestoreLines = 200
	// MaxRestoreLines es el tope máximo que se puede pedir.
	MaxRestoreLines = 1000
	runningCmd      = "show running-config"
	// expectSep separa la sección y la línea en Expect.Line.
	expectSep = "\x1f"
)

// Refusal es algo que el diff tocaría y la función no restaura: se lista para hacerlo a mano (ya sin secretos).
type Refusal struct{ Path, Line, Why string }

// RestoreChange son los datos de una restauración por diff.
type RestoreChange struct {
	Backup          string // texto del respaldo
	BackupMasked    bool
	BackupSerial    string // número de serie guardado en la ficha: debe ser el del equipo
	BackupTruncated bool   // la ficha dice que el respaldo se recortó
	Management      string // interfaz de gestión que indica el ingeniero (obligatoria si la sesión no la identifica sola)
	MaxLines        int    // 0 = DefaultRestoreLines
	Partial         bool   // aplicar solo lo permitido y dejar lo rechazado para hacerlo a mano
}

// RestorePlan es el plan de un equipo, la función que lo valida (lleva la gestión y el tope) y lo rechazado.
type RestorePlan struct {
	Device  DevicePlan
	Fn      Function
	Refused []Refusal
}

// RestoreDiffPre: lo que se lee para planear: el running, la serie, la sesión actual (show users + show tcp brief) y las VLAN.
func RestoreDiffPre() []string {
	return []string{runningCmd, "show version", "show users", "show tcp brief", "show vlan brief"}
}

// ---- texto del running ----

// stripHeaders quita las cabeceras que IOS imprime y que no son configuración.
func stripHeaders(text string) string {
	var keep []string
	for _, l := range strings.Split(text, "\n") {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "Using ") && strings.Contains(t, " out of ") || strings.HasPrefix(t, "Building configuration") {
			continue
		}
		keep = append(keep, l)
	}
	return strings.Join(keep, "\n")
}

// parseCfg lee un running-config. `ip domain name` (IOS-XE) e `ip domain-name` (IOS 15.2) son el mismo comando: se lee siempre como el segundo,
// en el equipo y en el respaldo, para que el diff, el plan y el post-check hablen de lo mismo.
func parseCfg(text string) *iosconf.Node {
	root := iosconf.Parse(stripHeaders(text))
	for _, n := range root.Children {
		if r, ok := strings.CutPrefix(n.Line, "ip domain name "); ok {
			n.Line = "ip domain-name " + r
		} else if r, ok := strings.CutPrefix(n.Line, "no ip domain name "); ok {
			n.Line = "no ip domain-name " + r
		}
	}
	return root
}

// completeBackup: un respaldo completo termina en `end`.
func completeBackup(text string) bool {
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(text, "\r\n", "\n")), "\n")
	return strings.TrimSpace(lines[len(lines)-1]) == "end"
}

// ---- diff ----

type op struct {
	path []string
	line string
	add  bool
}

func pathKey(p []string) string { return strings.Join(p, expectSep) }

type differ struct {
	ops  []op
	refs []Refusal
}

func (d *differ) refuse(path []string, line, why string) {
	hs := make([]string, len(path))
	for i, h := range path {
		hs[i] = redact(h)
	}
	r := Refusal{Path: strings.Join(hs, " > "), Line: redact(line), Why: why}
	if !slices.Contains(d.refs, r) { // quitar la llave vieja y poner la nueva son la misma cosa a mano
		d.refs = append(d.refs, r)
	}
}

func isHeaderNode(n *iosconf.Node) bool { return len(n.Children) > 0 || sectionLike(n.Line) }

// diffNode compara las líneas hijas de cur y want (la sección en path) y recorre las secciones comunes en el orden del respaldo.
func (d *differ) diffNode(path []string, cur, want *iosconf.Node) {
	var curLeaves, wantLeaves []*iosconf.Node
	curSec, wantSec := map[string]*iosconf.Node{}, map[string]*iosconf.Node{}
	var order []string
	for _, c := range cur.Children {
		if isHeaderNode(c) {
			curSec[c.Line] = c
		} else {
			curLeaves = append(curLeaves, c)
		}
	}
	for _, c := range want.Children {
		if isHeaderNode(c) {
			if _, dup := wantSec[c.Line]; !dup {
				order = append(order, c.Line)
			}
			wantSec[c.Line] = c
		} else {
			wantLeaves = append(wantLeaves, c)
		}
	}
	d.leaves(path, curLeaves, wantLeaves)
	why := func(l, base string) string {
		if f := forbiddenWhy(tokens(l)); f != "" {
			return base + "; " + f
		}
		return base
	}
	for _, l := range order {
		cs, ok := curSec[l]
		if !ok {
			d.refuse(path, l, why(l, "sección nueva en el respaldo: para revertirla habría que borrarla completa; créala a mano"))
			continue
		}
		d.diffNode(append(slices.Clone(path), l), cs, wantSec[l])
	}
	var gone []string
	for l := range curSec {
		if _, ok := wantSec[l]; !ok {
			gone = append(gone, l)
		}
	}
	sort.Strings(gone)
	for _, l := range gone {
		d.refuse(path, l, why(l, "sección que el respaldo no tiene: habría que borrarla completa; hazlo a mano"))
	}
}

// leaves compara las líneas sueltas de una sección como multiconjuntos.
func (d *differ) leaves(path []string, cur, want []*iosconf.Node) {
	here := slices.Clone(path)
	wantBody := map[string]string{}
	left := map[string]int{}
	for _, n := range want {
		wantBody[n.Line] = n.Body
		left[n.Line]++
	}
	have := map[string]int{}
	for _, n := range cur {
		have[n.Line]++
		if b, ok := wantBody[n.Line]; ok && n.Body != b {
			d.refuse(path, n.Line, "el texto (banner o macro) es distinto: no se inversa con certeza")
		}
		if left[n.Line] > 0 {
			left[n.Line]--
		} else {
			d.ops = append(d.ops, op{path: here, line: n.Line})
		}
	}
	for _, n := range want {
		if have[n.Line] > 0 {
			have[n.Line]--
		} else {
			d.ops = append(d.ops, op{path: here, line: n.Line, add: true})
		}
	}
}

// ---- líneas de un solo valor, inversa y render ----

// famsAt son las familias de la lista cerrada de una sección.
func famsAt(path []string) []fam {
	switch {
	case len(path) == 0:
		return globalFams
	case len(path) == 1 && strings.HasPrefix(path[0], "interface "):
		return ifaceFams
	case len(path) == 1 && strings.HasPrefix(path[0], "vlan "):
		return vlanFams
	}
	return nil
}

func famOf(path []string, line string) (fam, bool) {
	body := unNo(tokens(line))
	for _, f := range famsAt(path) {
		if hasPrefix(body, f.w) {
			return f, true
		}
	}
	return fam{}, false
}

// single devuelve la clave de una línea de un comando que IOS guarda una sola vez (fam.one, o fam.keyN con su dirección): la línea nueva con la
// misma clave la sustituye y un `no` en medio la borraría; vacío si el comando admite varias líneas con otra clave (logging host A y B).
// ip domain-name e ip domain name comparten clave.
func single(path []string, line string) string {
	f, ok := famOf(path, line)
	if !ok || !f.one && f.keyN == 0 {
		return ""
	}
	body := unNo(tokens(line))
	if len(body) < len(f.w)+f.keyN {
		return ""
	}
	k := strings.Join(body[:len(f.w)+f.keyN], " ")
	if k == "ip domain name" {
		return "ip domain-name"
	}
	return k
}

// paired dice si otra línea del diff, en la misma sección, hace de contraparte de o: la sustituye (mismo comando de un solo valor) o es su
// inversa. Solo las líneas sin pareja pasan por un `no` al aplicar o al revertir.
func paired(ops []op, o op) bool {
	k := single(o.path, o.line)
	for _, a := range ops {
		if a.add != o.add && pathKey(a.path) == pathKey(o.path) && (inverse(a.line) == o.line || k != "" && k == single(a.path, a.line)) {
			return true
		}
	}
	return false
}

func inverse(l string) string {
	if r, ok := strings.CutPrefix(l, "no "); ok {
		return r
	}
	return "no " + l
}

type group struct {
	path     []string
	rem, add []op
}

func groupOps(ops []op) []group {
	var gs []group
	idx := map[string]int{}
	for _, o := range ops {
		k := pathKey(o.path)
		i, ok := idx[k]
		if !ok {
			i = len(gs)
			idx[k] = i
			gs = append(gs, group{path: o.path})
		}
		if o.add {
			gs[i].add = append(gs[i].add, o)
		} else {
			gs[i].rem = append(gs[i].rem, o)
		}
	}
	// La raíz primero: los comandos globales no dependen de ninguna sección.
	sort.SliceStable(gs, func(i, j int) bool { return len(gs[i].path) == 0 && len(gs[j].path) > 0 })
	return gs
}

// render da las líneas de configuración (con los encabezados de sección), cuántas son cambios y lo que se espera ver en el running por línea.
// Orden dentro de una sección: `shutdown` primero, luego lo que se agrega, luego lo que se quita y `no shutdown` al final; así un comando de
// un solo valor manda solo la línea nueva y, cuando hay que agregar y quitar, nunca queda el equipo sin el valor viejo ni el nuevo.
func render(ops []op) (lines []string, changes int, expect []Expect) {
	seen := map[string]bool{}
	want := func(path []string, line string, present bool) {
		k := fmt.Sprintf("%s%s%s|%t", pathKey(path), expectSep, line, present)
		if !seen[k] {
			seen[k] = true
			expect = append(expect, Expect{Command: runningCmd, Line: strings.Join(append(slices.Clone(path), line), expectSep), Present: present, Column: "section-line"})
		}
	}
	for _, g := range groupOps(ops) {
		var add, rem []string
		for _, a := range g.add {
			add = append(add, a.line)
			if neg, ok := strings.CutPrefix(a.line, "no "); ok {
				want(g.path, neg, false)
			}
			want(g.path, a.line, true)
		}
		for _, r := range g.rem {
			want(g.path, r.line, false)
			if !paired(ops, r) {
				rem = append(rem, inverse(r.line))
			}
		}
		var front, mid, tail []string
		for _, l := range append(add, rem...) {
			switch l {
			case "shutdown":
				front = append(front, l)
			case "no shutdown":
				tail = append(tail, l)
			default:
				mid = append(mid, l)
			}
		}
		body := append(append(front, mid...), tail...)
		if len(body) == 0 {
			continue
		}
		lines = append(lines, g.path...)
		lines = append(lines, body...)
		changes += len(body)
	}
	return lines, changes, expect
}

func flip(ops []op) []op {
	out := make([]op, len(ops))
	for i, o := range ops {
		o.add = !o.add
		out[i] = o
	}
	return out
}

// ---- simulación del plan completo ----

type cfgState struct {
	lists map[string][]string // sección (ruta) -> líneas sueltas; "" es la raíz
	heads map[string]bool     // rutas que son secciones
}

func stateOf(root *iosconf.Node) cfgState {
	st := cfgState{lists: map[string][]string{"": nil}, heads: map[string]bool{}}
	var walk func(n *iosconf.Node, path []string)
	walk = func(n *iosconf.Node, path []string) {
		for _, c := range n.Children {
			if isHeaderNode(c) {
				p := append(slices.Clone(path), c.Line)
				st.heads[pathKey(p)] = true
				if _, ok := st.lists[pathKey(p)]; !ok {
					st.lists[pathKey(p)] = nil
				}
				walk(c, p)
			} else {
				st.lists[pathKey(path)] = append(st.lists[pathKey(path)], c.Line)
			}
		}
	}
	walk(root, nil)
	return st
}

func (s cfgState) clone() cfgState {
	c := cfgState{lists: map[string][]string{}, heads: s.heads}
	for k, v := range s.lists {
		c.lists[k] = slices.Clone(v)
	}
	return c
}

// volatile: lo que cambia solo entre dos lecturas del running-config.
func volatile(l string) bool {
	return strings.HasPrefix(l, "ntp clock-period") || strings.HasPrefix(l, "Using ") && strings.Contains(l, " out of ")
}

// sectionHash es la forma comparable de una sección (sin orden): el post-check compara la sección entera del running contra la simulada,
// no solo las líneas del diff. Va como hash para que el plan, los eventos y la bitácora no lleven el resto de la sección (secretos incluidos).
func sectionHash(lines []string) string {
	ls := slices.DeleteFunc(slices.Clone(lines), volatile)
	sort.Strings(ls)
	sum := sha256.Sum256([]byte(strings.Join(ls, "\n")))
	return hex.EncodeToString(sum[:])
}

// canon es la forma comparable del estado completo.
func (s cfgState) canon() string {
	keys := make([]string, 0, len(s.lists))
	for k := range s.lists {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		if h := sectionHash(s.lists[k]); len(s.lists[k]) > 0 {
			fmt.Fprintf(&b, "[%s]%s\n", k, h)
		}
	}
	return b.String()
}

type touch struct {
	path []string
	line string
}

// simulate aplica líneas de configuración a un estado como lo hace IOS: encabezados de sección, `no X` quita X (o guarda `no X` si
// no estaba) y una línea de un solo valor sustituye a la anterior y `no X ...` quita el comando entero.
func simulate(st cfgState, lines []string) (cfgState, []touch, error) {
	st = st.clone()
	var ctx []string
	var touched []touch
	for _, line := range lines {
		matched := false
		for i := len(ctx); i >= 0; i-- {
			if p := append(slices.Clone(ctx[:i]), line); st.heads[pathKey(p)] {
				ctx, matched = p, true
				break
			}
		}
		if matched {
			continue
		}
		if sectionLike(line) {
			return st, touched, fmt.Errorf("%q abre o borra una sección que el equipo no tiene tal cual", line)
		}
		touched = append(touched, touch{path: slices.Clone(ctx), line: line})
		k := pathKey(ctx)
		cur := st.lists[k]
		neg := strings.HasPrefix(line, "no ")
		body := strings.TrimPrefix(line, "no ")
		if sk := single(ctx, body); sk != "" {
			cur = slices.DeleteFunc(cur, func(l string) bool { return single(ctx, l) == sk })
			if f, _ := famOf(ctx, body); !neg || f.keepNo { // IOS conserva la forma `no X` de los keepNo en el running
				cur = append(cur, line)
			}
		} else if i := slices.Index(cur, inverse(line)); i >= 0 {
			cur = slices.Delete(cur, i, i+1) // `no X` quita X; X anula un `no X`
		} else if !slices.Contains(cur, line) {
			cur = append(cur, line)
		}
		st.lists[k] = cur
	}
	return st, touched, nil
}

// sectionExpects son las comparaciones de sección completa del post-check: una por sección tocada (la global incluida).
func sectionExpects(st cfgState, touched []touch) []Expect {
	var out []Expect
	seen := map[string]bool{}
	for _, t := range touched {
		k := pathKey(t.path)
		if seen[k] {
			continue
		}
		seen[k] = true
		line := sectionHash(st.lists[k])
		if k != "" {
			line = k + expectSep + line
		}
		out = append(out, Expect{Command: runningCmd, Line: line, Present: true, Column: "section-hash"})
	}
	return out
}

// restoreCheck es el CheckDevice de la función: cada línea tocada debe estar en la lista cerrada (viendo la interfaz en el estado base, en
// el de después del Apply y en el de después de la reversa), el plan debe caber en el tope, la reversa debe devolver la línea base exacta
// y el post-check debe comparar cada sección tocada completa.
func restoreCheck(rc *rctx) func(DevicePlan) error {
	return func(d DevicePlan) error {
		run, ok := d.Baseline[runningCmd]
		if !ok || strings.TrimSpace(run) == "" {
			return errors.New("falta la línea base (el running-config capturado)")
		}
		base := stateOf(parseCfg(run))
		after, t1, err := simulate(base, d.Apply)
		if err != nil {
			return fmt.Errorf("en el Apply: %v", err)
		}
		back, t2, err := simulate(after, d.Rollback)
		if err != nil {
			return fmt.Errorf("en la reversa: %v", err)
		}
		sides := []cfgState{base, after, back}
		for _, t := range append(slices.Clone(t1), t2...) {
			if why := rc.refuse(t.path, t.line, sides); why != "" {
				return fmt.Errorf("%q (en %q): %s", redact(t.line), redact(strings.Join(t.path, " > ")), why)
			}
		}
		if len(t1) > rc.max || len(t2) > rc.max {
			return fmt.Errorf("más de %d líneas de cambio (tope del plan)", rc.max)
		}
		if after.canon() == base.canon() {
			for i, l := range d.Apply {
				if i > 0 && slices.Contains(d.Apply[:i], l) {
					return fmt.Errorf("el Apply no cambia nada: repite la línea %q y la segunda copia no cambia nada", redact(l))
				}
			}
			return errors.New("el Apply no cambia nada")
		}
		if back.canon() != base.canon() {
			return errors.New("la reversa no es la inversa exacta del Apply: no devuelve el equipo a la línea base")
		}
		for _, e := range sectionExpects(after, t1) {
			if !slices.Contains(d.Expect, e) {
				return fmt.Errorf("el post-check no compara la sección %q completa contra el estado esperado", strings.Join(t1[0].path, " > "))
			}
		}
		return nil
	}
}

func restoreFn(rc *rctx) Function {
	return Function{Name: RestoreDiff, Allowed: engineAllowed(), AllowNo: true, Scrub: true, CheckDevice: restoreCheck(rc)}
}

// ---- el plan ----

// headerName es el nombre que una sección rechazada le pone a lo que otras líneas pueden nombrar (VLAN, interfaz, ACL, route-map, VRF).
func headerName(h string) string {
	f := strings.Fields(h)
	switch {
	case len(f) > 3 && f[1] == "access-list":
		return strings.ToLower(f[len(f)-1])
	case len(f) > 1:
		return strings.ToLower(f[1])
	}
	return ""
}

// RestoreDiffPlan arma el plan que lleva el running-config actual (outs["show running-config"]) al del respaldo. Un respaldo enmascarado,
// recortado, de otro equipo o con cambios que la lista cerrada no admite se rechaza (ErrRestoreRefused) y lo rechazado va en
// RestorePlan.Refused; con Partial se aplica solo lo permitido.
func RestoreDiffPlan(device string, c RestoreChange, outs map[string]string) (RestorePlan, error) {
	refuseAll := func(format string, a ...any) (RestorePlan, error) {
		return RestorePlan{}, fmt.Errorf("%w: "+format, append([]any{ErrRestoreRefused}, a...)...)
	}
	if c.BackupMasked || maskRe.MatchString(c.Backup) {
		return refuseAll("el respaldo se tomó con secretos enmascarados (o trae marcas de enmascarado): restaurarlo borraría contraseñas y llaves; toma un respaldo sin enmascarar")
	}
	if c.BackupTruncated {
		return refuseAll("el respaldo está marcado como recortado: no es la configuración completa")
	}
	if strings.TrimSpace(c.Backup) == "" || !completeBackup(c.Backup) {
		return refuseAll("el respaldo no termina en end: está cortado o incompleto")
	}
	max := c.MaxLines
	if max < 0 || max > MaxRestoreLines {
		return refuseAll("el tope de líneas va de 1 a %d", MaxRestoreLines)
	}
	if max == 0 {
		max = DefaultRestoreLines
	}
	run, ok := outs[runningCmd]
	if !ok || strings.TrimSpace(run) == "" {
		return refuseAll("falta el running-config del equipo")
	}
	curRoot, wantRoot := parseCfg(run), parseCfg(c.Backup)
	if len(wantRoot.Children) == 0 {
		return refuseAll("el respaldo está vacío")
	}
	hn := func(r *iosconf.Node) string {
		for _, n := range r.Find(`hostname .+`) {
			return strings.TrimSpace(strings.TrimPrefix(n.Line, "hostname "))
		}
		return ""
	}
	if a, b := hn(curRoot), hn(wantRoot); a == "" || b == "" || a != b {
		return refuseAll("el respaldo es del equipo %q y este es %q (sin hostname en alguno no se puede comprobar que sea el mismo equipo)", b, a)
	}
	ver, _ := iosxe.ParseVersion(outs["show version"])
	if c.BackupSerial == "" || ver.Serial == "" || !strings.EqualFold(c.BackupSerial, ver.Serial) {
		return refuseAll("el número de serie del respaldo (%q) no coincide con el del equipo (%q): el hostname no basta para saber que es el mismo equipo; sin serie en la ficha o en show version no se restaura", c.BackupSerial, ver.Serial)
	}
	mgI, mgV, err := managementOf(curRoot, outs, c.Management)
	if err != nil {
		return RestorePlan{}, err
	}
	rc := &rctx{mgIfaces: mgI, mgVlans: mgV, live: map[string]bool{}, ifs: map[string]bool{}, max: max}
	rows, _ := iosxe.ParseVlanBrief(outs["show vlan brief"])
	for _, r := range rows {
		if r.Status == "active" {
			rc.live[ntoa(r.ID)] = true
		}
	}
	for _, n := range curRoot.Children {
		if k, ok := ifaceKey(n.Line); ok {
			rc.ifs[k] = true
		}
	}
	curSt, wantSt := stateOf(curRoot), stateOf(wantRoot)
	d := &differ{}
	d.diffNode(nil, curRoot, wantRoot)
	// Primero lo que la lista cerrada rechaza; con ello se sabe qué nombres están rechazados (una VLAN, una interfaz, una ACL, un route-map).
	var kept []op
	names := map[string]bool{}
	for _, r := range d.refs {
		if n := headerName(r.Line); n != "" {
			names[n] = true
		}
	}
	sides := []cfgState{curSt, wantSt}
	for _, o := range d.ops {
		why := rc.refuse(o.path, o.line, sides)
		if why == "" && !paired(d.ops, o) {
			// Sin pareja, la línea se manda al aplicar o al revertir con `no`: esa forma también debe ser de la lista cerrada y exacta en IOS.
			if why = rc.refuse(o.path, inverse(o.line), sides); why == "" {
				if f, ok := famOf(o.path, o.line); ok && f.keepNo {
					why = "IOS conserva la forma `no` en el running en lugar de quitar la línea: no se puede aplicar ni revertir con certeza; hazlo a mano"
				}
			}
		}
		if why != "" {
			d.refuse(o.path, o.line, why)
			continue
		}
		kept = append(kept, o)
	}
	// Con --parcial, una línea permitida que nombra algo rechazado también se rechaza.
	var keep []op
	for _, o := range kept {
		f := tokens(o.line)
		named := ""
		if len(f) > 0 && unNo(f)[0] != "description" && unNo(f)[0] != "name" {
			for _, w := range f {
				if names[w] {
					named = w
				}
			}
		}
		if named != "" {
			d.refuse(o.path, o.line, fmt.Sprintf("nombra %q, que se rechaza", named))
			continue
		}
		keep = append(keep, o)
	}
	rp := RestorePlan{Refused: d.refs}
	if len(d.refs) > 0 && !c.Partial {
		return rp, fmt.Errorf("%w: el diff toca %d cosas que no se restauran con seguridad (lista abajo); hazlas a mano o pide el plan parcial", ErrRestoreRefused, len(d.refs))
	}
	if len(keep) == 0 {
		return rp, ErrNoDifference
	}
	apply, n, expect := render(keep)
	rollback, _, _ := render(flip(keep))
	if n > max {
		return rp, fmt.Errorf("%w: el plan tiene %d líneas de cambio y el tope es %d", ErrRestoreRefused, n, max)
	}
	after, touched, err := simulate(curSt, apply)
	if err != nil {
		return rp, fmt.Errorf("%w: %v", ErrRestoreRefused, err)
	}
	expect = append(expect, sectionExpects(after, touched)...)
	rp.Fn = restoreFn(rc)
	rp.Device = DevicePlan{Device: device, Pre: RestoreDiffPre(), Apply: apply, Rollback: rollback, Post: []string{runningCmd},
		Expect: expect, Baseline: map[string]string{runningCmd: run}}
	if err := Validate(Plan{Function: RestoreDiff, Devices: []DevicePlan{rp.Device}}, rp.Fn); err != nil {
		return rp, err
	}
	return rp, nil
}

// RestoreEgressPre son las lecturas extra del camino de regreso: por dónde sale el tráfico hacia el origen de la sesión (show ip cef y, de
// respaldo, show ip route; con la VRF de la interfaz que lleva la sesión, o en IPv6 si el origen lo es). Se piden siempre que se conozca el
// origen (un router trae `ip routing` activo y no lo imprime), salvo con `no ip routing` y un origen IPv4. Dependen de lo leído en RestoreDiffPre.
func RestoreEgressPre(outs map[string]string) []string {
	run, ok := outs[runningCmd]
	if !ok {
		return nil
	}
	root := parseCfg(run)
	if o, has := sessionOrigin(outs["show users"]); !has || hasGlobal(root, "no ip routing") && !o.Is6() {
		return nil
	}
	cmds, _ := egressReads(root, outs)
	return cmds
}
