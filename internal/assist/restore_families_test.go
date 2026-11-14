package assist

import (
	"errors"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"slices"
	"strings"
	"testing"
)

// Semántica en IOS de cada familia de la lista cerrada, escrita aparte del código:
//   - one:        un solo valor; la línea nueva sustituye a la anterior y `no X ...` quita el comando entero (no solo esa línea).
//   - one-keepno: como one, pero IOS conserva la forma `no X` en el running en lugar de quitar la línea: una línea que desaparece sin
//     sustituto no se puede expresar y se rechaza.
//   - multi:      una línea por valor; `no X valor` quita solo esa línea.
//   - keyed:      una línea por dirección (ntp server, logging host, ip name-server): IOS guarda una sola por dirección, así que
//     `ntp server X prefer` reemplaza a `ntp server X` sin `no`, y `no ntp server X` quita la asociación entera.
//   - flag:       sin valor; la línea está o no está.
type famCase struct {
	section, kind, a, b string
	strip               []string // otras escrituras del mismo comando que se limpian del fixture
}

var iosFamilies = map[string]famCase{
	"|hostname":                       {"", "one", "", "", nil}, // el hostname debe ser el mismo en los dos lados: nunca hay diff
	"|logging host":                   {"", "keyed", "logging host 10.0.0.8", "logging host 10.0.0.7", nil},
	"|logging buffered":               {"", "one-keepno", "logging buffered 8192", "logging buffered 16384 informational", nil},
	"|logging trap":                   {"", "one-keepno", "logging trap warnings", "logging trap errors", nil},
	"|logging facility":               {"", "one", "logging facility local6", "logging facility local5", nil},
	"|logging source-interface":       {"", "one", "logging source-interface Vlan99", "logging source-interface Vlan10", nil},
	"|ntp server":                     {"", "keyed", "ntp server 10.0.0.1", "ntp server 10.0.0.2", nil},
	"|snmp-server location":           {"", "one", "snmp-server location Lab", "snmp-server location Otro", nil},
	"|snmp-server contact":            {"", "one", "snmp-server contact NOC", "snmp-server contact Otro", nil},
	"|ip domain-name":                 {"", "one", "ip domain-name a.local", "ip domain-name b.local", []string{"ip domain name"}},
	"|ip domain name":                 {"", "one", "ip domain name a.local", "ip domain-name b.local", []string{"ip domain-name"}},
	"|ip name-server":                 {"", "keyed", "ip name-server 1.1.1.1", "ip name-server 2.2.2.2", nil},
	"|clock timezone":                 {"", "one", "clock timezone CST -6", "clock timezone EST -5", nil},
	"|clock summer-time":              {"", "one", "clock summer-time CDT recurring", "clock summer-time CST recurring", nil},
	"|service timestamps debug":       {"", "one-keepno", "service timestamps debug datetime msec", "service timestamps debug datetime msec localtime", nil},
	"|service timestamps log":         {"", "one-keepno", "service timestamps log datetime msec", "service timestamps log datetime msec localtime", nil},
	"|spanning-tree portfast default": {"", "flag", "spanning-tree portfast default", "spanning-tree portfast default", nil},
	"|errdisable recovery cause":      {"", "multi", "errdisable recovery cause bpduguard", "errdisable recovery cause udld", nil},
	"|errdisable recovery interval":   {"", "one", "errdisable recovery interval 300", "errdisable recovery interval 600", nil},
	"i|description":                   {"interface GigabitEthernet1/0/4", "one", "description uno", "description dos", nil},
	"i|switchport access vlan":        {"interface GigabitEthernet1/0/4", "one", "switchport access vlan 10", "switchport access vlan 20", nil},
	"i|switchport voice vlan":         {"interface GigabitEthernet1/0/4", "one", "switchport voice vlan 10", "switchport voice vlan 20", nil},
	"i|shutdown":                      {"interface GigabitEthernet1/0/4", "flag", "shutdown", "shutdown", nil},
	"i|spanning-tree portfast":        {"interface GigabitEthernet1/0/4", "one", "spanning-tree portfast", "spanning-tree portfast disable", nil},
	"i|spanning-tree bpduguard":       {"interface GigabitEthernet1/0/4", "one", "spanning-tree bpduguard enable", "spanning-tree bpduguard disable", nil},
	"i|storm-control broadcast":       {"interface GigabitEthernet1/0/4", "one", "storm-control broadcast level 50", "storm-control broadcast level 60", nil},
	"i|storm-control multicast":       {"interface GigabitEthernet1/0/4", "one", "storm-control multicast level 50", "storm-control multicast level 60", nil},
	"i|storm-control unicast":         {"interface GigabitEthernet1/0/4", "one", "storm-control unicast level 50", "storm-control unicast level 60", nil},
	"i|storm-control action":          {"interface GigabitEthernet1/0/4", "multi", "storm-control action shutdown", "storm-control action trap", nil},
	"v|name":                          {"vlan 10", "one", "name UNO", "name DOS", nil},
}

func famTableKey(section string, f fam) string {
	p := map[string]string{"": "", "interface": "i", "vlan": "v"}[section]
	return p + "|" + strings.Join(f.w, " ")
}

func allFamilies() map[string]fam {
	out := map[string]fam{}
	for sec, fs := range map[string][]fam{"": globalFams, "interface": ifaceFams, "vlan": vlanFams} {
		for _, f := range fs {
			out[famTableKey(sec, f)] = f
		}
	}
	return out
}

// Cada familia de la lista cerrada está clasificada aquí, y el código coincide con la clasificación.
func TestRestoreEveryFamilyIsClassifiedAndMatchesItsIOSSemantics(t *testing.T) {
	fams := allFamilies()
	for k, f := range fams {
		c, ok := iosFamilies[k]
		if !ok {
			t.Errorf("la familia %q no está clasificada (un solo valor o varias líneas)", k)
			continue
		}
		if (f.keyN > 0) != (c.kind == "keyed") {
			t.Errorf("%s: el código dice keyN=%d y la semántica de IOS es %s", k, f.keyN, c.kind)
		}
		if f.one != strings.HasPrefix(c.kind, "one") || f.keepNo != (c.kind == "one-keepno") {
			t.Errorf("%s: el código dice one=%v keepNo=%v y la semántica de IOS es %s", k, f.one, f.keepNo, c.kind)
		}
	}
	for k := range iosFamilies {
		if _, ok := fams[k]; !ok {
			t.Errorf("la clasificación %q no corresponde a ninguna familia", k)
		}
	}
}

// withLine deja en la sección el comando con esa línea (o sin él si line es vacío), quitando antes cualquier otra escritura del mismo comando.
func withLine(cfg string, c famCase, prefix string, line string) string {
	strip := append([]string{prefix}, c.strip...)
	drop := func(l string) bool {
		f := unNo(tokens(l))
		for _, s := range strip {
			if hasPrefix(f, tokens(s)) {
				return true
			}
		}
		return false
	}
	lines := strings.Split(cfg, "\n")
	var out []string
	in := false
	inserted := false
	for _, l := range lines {
		top := !strings.HasPrefix(l, " ") && l != "!"
		switch {
		case c.section == "" && top && drop(l):
			continue
		case c.section == "" && l == "hostname SW1":
			out = append(out, l)
			if line != "" {
				out, inserted = append(out, line), true
			}
			continue
		case c.section != "" && l == c.section:
			in = true
		case in && strings.HasPrefix(l, " ") && drop(strings.TrimSpace(l)):
			continue
		case in && !strings.HasPrefix(l, " "):
			in = false
			if line != "" && !inserted {
				out, inserted = append(out, " "+line), true
			}
		}
		out = append(out, l)
	}
	if line != "" && !inserted {
		panic("no se pudo poner " + line)
	}
	return strings.Join(out, "\n")
}

// iosModel aplica las líneas de un plan como lo hace IOS según la clasificación de arriba (no usa fam.one ni simulate).
func iosModel(t *testing.T, st cfgState, lines []string) cfgState {
	t.Helper()
	st = st.clone()
	var ctx []string
	sectionOf := func() string {
		switch {
		case len(ctx) == 0:
			return ""
		case strings.HasPrefix(ctx[0], "interface "):
			return "i"
		case strings.HasPrefix(ctx[0], "vlan "):
			return "v"
		}
		return "?"
	}
	for _, l := range lines {
		if st.heads[pathKey([]string{l})] {
			ctx = []string{l}
			continue
		}
		neg := strings.HasPrefix(l, "no ")
		body := tokens(strings.TrimPrefix(l, "no "))
		var key string
		var fc famCase
		for k, c := range iosFamilies {
			if !strings.HasPrefix(k, sectionOf()+"|") {
				continue
			}
			kw := tokens(strings.TrimPrefix(k, sectionOf()+"|"))
			if hasPrefix(body, kw) && len(kw) > len(strings.Fields(key)) {
				key, fc = strings.Join(kw, " "), c
			}
		}
		if key == "" {
			t.Fatalf("el plan manda %q que no es de ninguna familia", l)
		}
		k := pathKey(ctx)
		cur := st.lists[k]
		same := func(x string) bool { return hasPrefix(unNo(tokens(x)), tokens(key)) }
		lineIsKey := func(x string) bool {
			if same(x) {
				return true
			}
			for _, s := range fc.strip {
				if hasPrefix(unNo(tokens(x)), tokens(s)) {
					return true
				}
			}
			return false
		}
		switch fc.kind {
		case "one", "one-keepno":
			cur = slices.DeleteFunc(cur, lineIsKey)
			if !neg || fc.kind == "one-keepno" {
				cur = append(cur, l)
			}
		case "multi":
			if neg {
				i := slices.Index(cur, strings.TrimPrefix(l, "no "))
				if i < 0 {
					t.Fatalf("`%s` quita una línea que no existe (IOS lo ignora o falla)", l)
				}
				cur = slices.Delete(cur, i, i+1)
			} else if !slices.Contains(cur, l) {
				cur = append(cur, l)
			}
		case "keyed":
			// Una línea por dirección: la clave es el comando y su primer argumento; la nueva reemplaza, `no` quita la asociación.
			sameAddr := func(x string) bool {
				g := unNo(tokens(x))
				return len(g) > len(tokens(key)) && hasPrefix(g, tokens(key)) && g[len(tokens(key))] == body[len(tokens(key))]
			}
			if !slices.ContainsFunc(cur, sameAddr) && neg {
				t.Fatalf("`%s` quita una asociación que no existe (IOS lo ignora o falla)", l)
			}
			cur = slices.DeleteFunc(cur, sameAddr)
			if !neg {
				cur = append(cur, l)
			}
		case "flag":
			if neg {
				cur = slices.DeleteFunc(cur, func(x string) bool { return x == strings.TrimPrefix(l, "no ") })
			} else if !slices.Contains(cur, l) {
				cur = append(cur, l)
			}
		}
		st.lists[k] = cur
	}
	return st
}

// Para cada familia, sustituir, agregar y quitar: el plan solo usa formas cuya semántica en IOS lleva el running al respaldo, la reversa
// regresa, y el modelo de IOS coincide con simulate (que es lo que valida CheckDevice).
func TestRestoreEveryFamilySubstituteAddRemoveRoundTripsUnderIOSSemantics(t *testing.T) {
	for k, c := range iosFamilies {
		if c.a == "" {
			continue // hostname
		}
		prefix := strings.TrimLeft(k[strings.Index(k, "|")+1:], "")
		type scen struct{ name, run, back string }
		var scens []scen
		if c.kind != "flag" {
			scens = append(scens, scen{"sustituir", c.a, c.b})
		}
		scens = append(scens, scen{"agregar", "", c.b}, scen{"quitar", c.a, ""})
		for _, s := range scens {
			t.Run(k+"/"+s.name, func(t *testing.T) {
				run := withLine(reviewRunning, c, prefix, s.run)
				back := withLine(reviewRunning, c, prefix, s.back)
				p, err := RestoreDiffPlan("SW1", RestoreChange{Backup: back, BackupSerial: "FOC0001A0AA"}, reviewOuts(run))
				if s.name != "sustituir" && c.kind == "one-keepno" {
					// IOS conserva la forma `no`: ni quitar la línea ni revertir su alta se puede expresar con certeza.
					if !errors.Is(err, ErrRestoreRefused) || len(p.Refused) == 0 {
						t.Fatalf("debía rechazarse y listarse: err=%v apply=%q", err, p.Device.Apply)
					}
					return
				}
				if err != nil {
					t.Fatalf("debía armarse: %v %v", err, p.Refused)
				}
				base, want := stateOf(parseCfg(run)), stateOf(parseCfg(back))
				after := iosModel(t, base, p.Device.Apply)
				if after.canon() != want.canon() {
					t.Errorf("según IOS el Apply %q no deja el running como el respaldo", p.Device.Apply)
				}
				if sim, _, err := simulate(base, p.Device.Apply); err != nil || sim.canon() != after.canon() {
					t.Errorf("simulate no coincide con IOS para %q: %v", p.Device.Apply, err)
				}
				if rb := iosModel(t, after, p.Device.Rollback); rb.canon() != base.canon() {
					t.Errorf("según IOS la reversa %q no regresa al running", p.Device.Rollback)
				}
				// Un valor sustituido nunca pasa por un `no` del mismo comando (en IOS borraría el valor nuevo); varias líneas: agrega y luego quita.
				if s.name == "sustituir" && strings.HasPrefix(c.kind, "one") {
					for _, l := range append(slices.Clone(p.Device.Apply), p.Device.Rollback...) {
						if strings.HasPrefix(l, "no ") && hasPrefix(tokens(strings.TrimPrefix(l, "no ")), tokens(prefix)) {
							t.Errorf("la sustitución de un valor no pasa por %q", l)
						}
					}
				}
			})
		}
	}
}

func TestRestoreReviewerSingleValueCases(t *testing.T) {
	apply := func(t *testing.T, run, back string) []string {
		t.Helper()
		p, err := RestoreDiffPlan("SW1", RestoreChange{Backup: back, BackupSerial: "FOC0001A0AA"}, reviewOuts(run))
		if err != nil {
			t.Fatalf("%v %v", err, p.Refused)
		}
		return p.Device.Apply
	}
	g := func(lines ...string) string {
		return rep(reviewRunning, "hostname SW1\n", "hostname SW1\n"+strings.Join(lines, "\n")+"\n")
	}
	for name, tc := range map[string]struct{ run, back, want string }{
		"summer-time CDT a CST":     {g("clock summer-time CDT recurring"), g("clock summer-time CST recurring"), "clock summer-time CST recurring"},
		"timestamps con localtime":  {g("service timestamps log datetime msec"), g("service timestamps log datetime msec localtime"), "service timestamps log datetime msec localtime"},
		"errdisable interval":       {g("errdisable recovery interval 300"), g("errdisable recovery interval 600"), "errdisable recovery interval 600"},
		"domain-name 15.2 a IOS-XE": {g("ip domain name a.local"), g("ip domain-name b.local"), "ip domain-name b.local"},
	} {
		if got := apply(t, tc.run, tc.back); !slices.Equal(got, []string{tc.want}) {
			t.Errorf("%s: Apply = %q, quería solo %q", name, got, tc.want)
		}
	}
	// El mismo valor escrito de las dos formas no es una diferencia.
	if _, err := RestoreDiffPlan("SW1", RestoreChange{Backup: g("ip domain-name a.local"), BackupSerial: "FOC0001A0AA"}, reviewOuts(g("ip domain name a.local"))); !errors.Is(err, ErrNoDifference) {
		t.Errorf("ip domain name e ip domain-name son el mismo comando: %v", err)
	}
	// Dos servidores en una línea: IOS los junta en una sola línea, y quitar uno no es quitar la línea; se rechaza.
	p, err := RestoreDiffPlan("SW1", RestoreChange{Backup: g("ip name-server 1.1.1.1"), BackupSerial: "FOC0001A0AA"}, reviewOuts(g("ip name-server 1.1.1.1 2.2.2.2")))
	if !errors.Is(err, ErrRestoreRefused) || len(p.Refused) == 0 {
		t.Errorf("name-server con varios en una línea se rechaza: %v %v", err, p.Refused)
	}
	// storm-control action shutdown y trap pueden estar juntas: agregar una no quita la otra.
	both := rep(reviewRunning, "interface GigabitEthernet1/0/4\n", "interface GigabitEthernet1/0/4\n storm-control action shutdown\n")
	back := rep(both, " storm-control action shutdown\n", " storm-control action shutdown\n storm-control action trap\n")
	if got := apply(t, both, back); !slices.Equal(got, []string{"interface GigabitEthernet1/0/4", "storm-control action trap"}) {
		t.Errorf("Apply = %q", got)
	}
}

// Las formas que IOS no entiende como se espera nunca están en la lista cerrada, ni siquiera en un plan armado a mano.
func TestRestoreClosedListRefusesNoFormsWithTheWrongIOSMeaning(t *testing.T) {
	rc := &rctx{live: map[string]bool{}, ifs: map[string]bool{}, max: 10}
	for _, l := range []string{"no logging buffered 8192", "no logging buffered 8192 informational", "no ip name-server 1.1.1.1 2.2.2.2", "ip name-server 1.1.1.1 2.2.2.2"} {
		if why := rc.refuse(nil, l, nil); why.Empty() {
			t.Errorf("%q debía rechazarse", l)
		}
	}
	for _, l := range []string{"no logging buffered", "logging buffered 8192", "ip name-server 1.1.1.1", "no ip name-server 1.1.1.1"} {
		if why := rc.refuse(nil, l, nil); !why.Empty() {
			t.Errorf("%q debía aceptarse: %s", l, why.In(i18n.Es))
		}
	}
}

// IOS guarda una sola línea por dirección de ntp server: `ntp server X prefer` reemplaza a `ntp server X`, y un `no ntp server X`
// posterior borraría la asociación nueva. El plan manda solo la línea nueva, en los dos sentidos y con otros servidores en medio.
func TestRestoreNTPServerWithPreferReplacesTheSameAddressWithoutNo(t *testing.T) {
	c := iosFamilies["|ntp server"]
	line := func(cfg string, lines ...string) string {
		return withLine(cfg, c, "ntp server", strings.Join(lines, "\n"))
	}
	for name, tc := range map[string]struct {
		run, back []string
		apply     []string
		rollback  []string
	}{
		"agregar prefer": {[]string{"ntp server 10.0.0.1"}, []string{"ntp server 10.0.0.1 prefer"}, []string{"ntp server 10.0.0.1 prefer"}, []string{"ntp server 10.0.0.1"}},
		"quitar prefer":  {[]string{"ntp server 10.0.0.1 prefer"}, []string{"ntp server 10.0.0.1"}, []string{"ntp server 10.0.0.1"}, []string{"ntp server 10.0.0.1 prefer"}},
		"prefer y otro quitado": {[]string{"ntp server 10.0.0.1", "ntp server 10.0.0.2"}, []string{"ntp server 10.0.0.1 prefer"},
			[]string{"ntp server 10.0.0.1 prefer", "no ntp server 10.0.0.2"}, []string{"ntp server 10.0.0.1", "ntp server 10.0.0.2"}},
	} {
		run, back := line(reviewRunning, tc.run...), line(reviewRunning, tc.back...)
		p, err := RestoreDiffPlan("SW1", RestoreChange{Backup: back, BackupSerial: "FOC0001A0AA"}, reviewOuts(run))
		if err != nil {
			t.Errorf("%s: debía armarse: %v %v", name, err, p.Refused)
			continue
		}
		if !slices.Equal(p.Device.Apply, tc.apply) {
			t.Errorf("%s: Apply = %q, quería %q", name, p.Device.Apply, tc.apply)
		}
		base, want := stateOf(parseCfg(run)), stateOf(parseCfg(back))
		after := iosModel(t, base, p.Device.Apply)
		if after.canon() != want.canon() {
			t.Errorf("%s: según IOS el Apply %q no deja el running como el respaldo", name, p.Device.Apply)
		}
		if rb := iosModel(t, after, p.Device.Rollback); rb.canon() != base.canon() {
			t.Errorf("%s: según IOS la reversa %q no regresa al running", name, p.Device.Rollback)
		}
		if sim, _, err := simulate(base, p.Device.Apply); err != nil || sim.canon() != after.canon() {
			t.Errorf("%s: simulate no coincide con IOS para %q: %v", name, p.Device.Apply, err)
		}
	}
	// Con key, source o version la línea sigue siendo la misma asociación, pero no es de la lista cerrada (key es un secreto).
	rc := &rctx{live: map[string]bool{}, ifs: map[string]bool{}, max: 10}
	for _, l := range []string{"ntp server 10.0.0.1 key 5", "ntp server 10.0.0.1 version 3", "ntp server 10.0.0.1 source Vlan99"} {
		if rc.refuse(nil, l, nil).Empty() {
			t.Errorf("%q debía rechazarse", l)
		}
	}
}
