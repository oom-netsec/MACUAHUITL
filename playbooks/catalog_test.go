package playbooks_test

import (
	"io/fs"
	"path"
	"regexp"
	"strings"
	"testing"
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

func TestCatalogo(t *testing.T) {
	pbs, err := playbook.Load(playbooks.FS) // todo playbook carga; Load ya aplica CheckDenied
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]playbook.Playbook{}
	for _, p := range pbs {
		if _, dup := byID[p.ID]; dup {
			t.Errorf("id duplicado: %s", p.ID)
		}
		byID[p.ID] = p
		if p.Platform == "ios-xe" && !strings.Contains(p.Name, " · ") { // el selector de Patrol agrupa por el área antes del «·»
			t.Errorf("%s: name %q sin área (\"L2 · STP\")", p.ID, p.Name)
		}
		for _, c := range p.Commands {
			if secretCmd.MatchString(c.Text) && !c.MaySecrets {
				t.Errorf("%s: %q puede traer secretos y debe llevar may_contain_secrets", p.ID, c.Text)
			}
			if p.Platform == "ios-xe" && bigCmd.MatchString(c.Text) && c.Timeout <= 60*time.Second {
				t.Errorf("%s: %q es una salida grande y necesita timeout > 60s", p.ID, c.Text)
			}
		}
	}

	nuevos := 0
	err = fs.WalkDir(playbooks.FS, ".", func(name string, d fs.DirEntry, err error) error {
		base := strings.TrimSuffix(path.Base(name), ".yaml")
		if err != nil || d.IsDir() || path.Ext(name) != ".yaml" || !catalogFile.MatchString(base) || base == "tac-baseline" {
			return err
		}
		nuevos++
		raw, err := fs.ReadFile(playbooks.FS, name)
		if err != nil {
			return err
		}
		lines := strings.Split(string(raw), "\n")
		for i, want := range []string{"# Propósito", "# Cuándo", "# Fuente: https://www.cisco.com", "# Sin validar en laboratorio"} {
			if i >= len(lines) || !strings.HasPrefix(lines[i], want) {
				t.Errorf("%s: la línea %d de la cabecera debe empezar con %q", name, i+1, want)
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
	pbs, err := playbook.Load(playbooks.FS)
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
