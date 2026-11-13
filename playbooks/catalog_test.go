package playbooks_test

import (
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/playbooks"
)

// Archivos del catálogo por área (los playbooks anteriores no llevan estos prefijos; tac-baseline es anterior).
var catalogFile = regexp.MustCompile(`^(l1|l2|l3|svc|plat|vpn|tac)-`)

// Comandos que pueden imprimir secretos (el enmascarado solo corre si el comando lo declara).
var secretCmd = regexp.MustCompile(`^(show (run|start|tech|snmp comm|archive log)|more )`)

// Salidas sin acotar: tabla completa de rutas/BGP/CEF/MAC o todas las interfaces.
var bigCmd = regexp.MustCompile(`^show (ip route( vrf \*)?|ip bgp|ip cef|mac address-table|interfaces)$`)

// catalogFS junta el contenido embebido con el de packs/ios-xe y packs/ios (en cisco/<plataforma>), para que estas pruebas sigan
// cubriendo los playbooks que salieron del binario al paquete oficial.
func catalogFS(t testing.TB) fs.FS {
	t.Helper()
	m := fstest.MapFS{}
	add := func(root fs.FS, prefix string) {
		err := fs.WalkDir(root, ".", func(name string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := fs.ReadFile(root, name)
			m[path.Join(prefix, name)] = &fstest.MapFile{Data: b}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	add(playbooks.FS, "")
	add(os.DirFS("../packs/ios-xe/playbooks"), "cisco/ios-xe")
	add(os.DirFS("../packs/ios/playbooks"), "cisco/ios")
	return m
}

func TestCatalogo(t *testing.T) {
	pbs, err := playbook.Load(catalogFS(t)) // todo playbook carga; Load ya aplica CheckDenied
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]playbook.Playbook{}
	for _, p := range pbs {
		if _, dup := byID[p.ID]; dup {
			t.Errorf("id duplicado: %s", p.ID)
		}
		byID[p.ID] = p
		if (p.Platform == "ios-xe" || p.Platform == "ios") && !strings.Contains(p.Name, " · ") { // el selector de Patrol agrupa por el área antes del «·»
			t.Errorf("%s: name %q sin área (\"L2 · STP\")", p.ID, p.Name)
		}
		for _, c := range p.Commands {
			if secretCmd.MatchString(c.Text) && !c.MaySecrets {
				t.Errorf("%s: %q puede traer secretos y debe llevar may_contain_secrets", p.ID, c.Text)
			}
			if (p.Platform == "ios-xe" || p.Platform == "ios") && bigCmd.MatchString(c.Text) && c.Timeout <= 60*time.Second {
				t.Errorf("%s: %q es una salida grande y necesita timeout > 60s", p.ID, c.Text)
			}
		}
	}

	nuevos := 0
	err = fs.WalkDir(catalogFS(t), ".", func(name string, d fs.DirEntry, err error) error {
		base := strings.TrimSuffix(path.Base(name), ".yaml")
		if err != nil || d.IsDir() || path.Ext(name) != ".yaml" || !catalogFile.MatchString(base) || base == "tac-baseline" {
			return err
		}
		nuevos++
		raw, err := fs.ReadFile(catalogFS(t), name)
		if err != nil {
			return err
		}
		lines := strings.Split(string(raw), "\n")
		for i, want := range []string{"# Propósito", "# Cuándo", "# Fuente: https://www.cisco.com", "# Sin validar en laboratorio"} {
			ok := i < len(lines) && strings.HasPrefix(lines[i], want)
			if i == 3 && !ok { // o ya pasó por un equipo real: «# Validado en laboratorio: <modelo> con <versión> (<fecha>)…»
				ok = i < len(lines) && strings.HasPrefix(lines[i], "# Validado en laboratorio: ")
			}
			if !ok {
				t.Errorf("%s: la línea %d de la cabecera debe empezar con %q (o «# Validado en laboratorio: »)", name, i+1, want)
			}
		}
		p, ok := byID[path.Base(path.Dir(name))+"/"+base]
		if !ok {
			t.Errorf("%s: el id no coincide con el nombre del archivo", name)
			return nil
		}
		if n := len(p.Commands); n < 6 || n > 20 {
			t.Errorf("%s: %d comandos, deben ser 6-20", name, n)
		}
		if !strings.Contains(p.Name, " · ") {
			t.Errorf("%s: name %q sin prefijo de área con ' · '", name, p.Name)
		}
		for i, c := range p.Commands { // lo más pesado va al final: un timeout marca el equipo como fallido y salta el resto
			if c.Timeout >= 300*time.Second && i != len(p.Commands)-1 {
				t.Errorf("%s: %q (timeout %s) debe ser el último comando", name, c.Text, c.Timeout)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if nuevos == 0 {
		t.Fatal("no se encontró ningún archivo del catálogo")
	}
}

// dir bootflash: no existe en IOS clásico: los cuatro playbooks que lo piden lo marcan solo para ios-xe, y nada más lleva platforms.
func TestSoloBootflashLlevaPlatforms(t *testing.T) {
	pbs, err := playbook.Load(catalogFS(t))
	if err != nil {
		t.Fatal(err)
	}
	con := map[string]bool{}
	for _, p := range pbs {
		for _, c := range p.Commands {
			if c.Text == "dir bootflash:" && (len(c.Platforms) != 1 || c.Platforms[0] != "ios-xe") {
				t.Errorf("%s: %q debe llevar platforms: [ios-xe]: %v", p.ID, c.Text, c.Platforms)
			}
			if len(c.Platforms) > 0 {
				con[p.ID] = true
				if c.Text != "dir bootflash:" {
					t.Errorf("%s: %q lleva platforms sin evidencia", p.ID, c.Text)
				}
			}
		}
	}
	for _, id := range []string{"upgrade-check", "plat-flash-fs", "flota", "plat-reloads-crashinfo"} {
		if !con["ios-xe/"+id] {
			t.Errorf("ios-xe/%s no marca dir bootflash:", id)
		}
	}
}

// Todo playbook incrustado lleva su nombre en inglés, con la misma separación « · » que el español, para que la UI
// agrupe igual en los dos idiomas (cobertura, como la del catálogo de mensajes).
func TestNombresEnIngles(t *testing.T) {
	pbs, err := playbook.Load(catalogFS(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(pbs) == 0 {
		t.Fatal("sin playbooks")
	}
	for _, p := range pbs {
		if strings.TrimSpace(p.NameEn) == "" {
			t.Errorf("%s: falta name_en", p.ID)
			continue
		}
		if p.NameEn == p.Name && strings.ContainsAny(p.Name, "áéíóúñ") {
			t.Errorf("%s: name_en repite el nombre en español %q", p.ID, p.Name)
		}
		es, en := strings.Contains(p.Name, " · "), strings.Contains(p.NameEn, " · ")
		if es != en {
			t.Errorf("%s: el área antes de « · » debe estar en los dos nombres (%q, %q)", p.ID, p.Name, p.NameEn)
		}
	}
}

// Cada grupo en español (lo que va antes de « · ») corresponde a un único grupo en inglés y al revés: el selector
// agrupa igual en los dos idiomas.
func TestGruposUnoAUno(t *testing.T) {
	pbs, err := playbook.Load(catalogFS(t))
	if err != nil {
		t.Fatal(err)
	}
	group := func(n string) string { g, _, _ := strings.Cut(n, " · "); return g }
	esEn, enEs := map[string]string{}, map[string]string{}
	for _, p := range pbs {
		es, en := group(p.Name), group(p.NameEn)
		if prev, ok := esEn[es]; ok && prev != en {
			t.Errorf("el grupo %q tiene dos traducciones: %q y %q (%s)", es, prev, en, p.ID)
		}
		if prev, ok := enEs[en]; ok && prev != es {
			t.Errorf("el grupo %q viene de dos grupos en español: %q y %q (%s)", en, prev, es, p.ID)
		}
		esEn[es], enEs[en] = en, es
	}
}

// MovedToIOSXE es exactamente lo que hay en packs/ios-xe/playbooks, y el paquete no repite nada de la base.
func TestMovedToIOSXECoincideConElPaquete(t *testing.T) {
	ents, err := os.ReadDir("../packs/ios-xe/playbooks")
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, e := range ents {
		want = append(want, "ios-xe/"+strings.TrimSuffix(e.Name(), ".yaml"))
	}
	got := append([]string{}, playbooks.MovedToIOSXE...)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("MovedToIOSXE = %v\npackage    = %v", got, want)
	}
	base, err := playbook.Load(playbooks.FS)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range base {
		if slices.Contains(got, p.ID) {
			t.Errorf("%s está en la base y en el paquete", p.ID)
		}
	}
}
