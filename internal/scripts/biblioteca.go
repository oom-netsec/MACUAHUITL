package scripts

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
)

//go:embed biblioteca/*.yaml
var bibliotecaFS embed.FS

// Los scripts de la biblioteca llevan esta fecha fija para que su contenido (y su export) sea reproducible.
var fechaBiblioteca = time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)

type cfgScript struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Tech        string   `yaml:"tech"`
	Platform    string   `yaml:"platform"`
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags"`
	Commands    []string `yaml:"commands"`
}

// Library arma la biblioteca predefinida (solo lectura): un script de diagnóstico por playbook de
// pb (los comandos son los del playbook, así que nunca se desincronizan) más los de configuración
// embebidos en biblioteca/*.yaml. Los IDs son estables: «lib-<id del playbook>» y «lib-<id>».
// shortcut: se deriva de los playbooks al cargar y no se genera una copia en yaml; si los playbooks
// dejan de ser la fuente, congelar la copia con un generador.
func Library(pb fs.FS) ([]Script, error) {
	pbs, err := playbook.Load(pb)
	if err != nil {
		return nil, err
	}
	var out []Script
	for _, p := range pbs {
		id := p.ID[strings.Index(p.ID, "/")+1:]
		if p.Platform != "ios-xe" { // los IDs de ios-xe no cambian; el resto lleva su plataforma para no chocar
			id = p.Platform + "-" + id
		}
		cmds := append([]string{}, p.Pre...)
		for _, c := range p.Commands {
			cmds = append(cmds, c.Text)
		}
		out = append(out, Script{ID: "lib-" + id, Name: p.Name, Tech: techDe(id), Platform: p.Platform,
			Description: "Diagnóstico de solo lectura del playbook " + p.ID + ".",
			Commands:    cmds, Tags: []string{}, Origin: OrigenBiblioteca, CreatedAt: fechaBiblioteca, UpdatedAt: fechaBiblioteca})
	}
	b, err := bibliotecaFS.ReadFile("biblioteca/configuracion.yaml")
	if err != nil {
		return nil, err
	}
	var cfgs []cfgScript
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cfgs); err != nil {
		return nil, fmt.Errorf("biblioteca/configuracion.yaml: %w", err)
	}
	for _, c := range cfgs {
		id := c.ID
		if c.Platform != "ios-xe" {
			id = c.Platform + "-" + id
		}
		out = append(out, Script{ID: "lib-" + id, Name: c.Name, Tech: c.Tech, Platform: c.Platform, Description: c.Description,
			Commands: c.Commands, Tags: nonNil(c.Tags), Origin: OrigenBiblioteca, CreatedAt: fechaBiblioteca, UpdatedAt: fechaBiblioteca})
	}
	ids, nombres := map[string]bool{}, map[string]bool{}
	for _, s := range out {
		if err := s.Validate(); err != nil {
			return nil, fmt.Errorf("biblioteca %s: %w", s.ID, err)
		}
		if k := NameKey(s.Name); ids[s.ID] || nombres[k] {
			return nil, fmt.Errorf("biblioteca %s (%q): ID o nombre repetido", s.ID, s.Name)
		}
		ids[s.ID], nombres[NameKey(s.Name)] = true, true
	}
	return out, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// techDe clasifica un playbook por el prefijo de su ID.
func techDe(id string) string {
	switch {
	case id == "l2-etherchannel":
		return "etherchannel"
	case id == "l2-dot1x-mab" || id == "l2-dhcp-snooping-dai-ipsg" || id == "svc-acl" || id == "svc-aaa" || id == "svc-copp" || strings.HasPrefix(id, "vpn-"):
		return "seguridad"
	case id == "svc-qos":
		return "qos"
	case strings.HasPrefix(id, "l2-"):
		return "l2"
	case strings.HasPrefix(id, "l3-"):
		return "l3"
	case strings.HasPrefix(id, "svc-"), strings.HasPrefix(id, "plat-"):
		return "gestion"
	}
	return "diagnostico"
}
