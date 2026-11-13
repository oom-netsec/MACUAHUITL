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
	ID            string   `yaml:"id"`
	Name          string   `yaml:"name"`
	Tech          string   `yaml:"tech"`
	Platform      string   `yaml:"platform"`
	Description   string   `yaml:"description"`
	NameEN        string   `yaml:"name_en"`
	DescriptionEN string   `yaml:"description_en"`
	Tags          []string `yaml:"tags"`
	Commands      []string `yaml:"commands"`
}

// Library arma la biblioteca predefinida (solo lectura): un script de diagnóstico por playbook de
// pb (los comandos son los del playbook, así que nunca se desincronizan) más los de configuración
// embebidos en biblioteca/*.yaml. Los IDs son estables: «lib-<id del playbook>» y «lib-<id>».
// shortcut: se deriva de los playbooks al cargar y no se genera una copia en yaml; si los playbooks
// dejan de ser la fuente, congelar la copia con un generador.
func Library(pb fs.FS) ([]Script, error) {
	out, _, err := LibraryWithEN(pb)
	return out, err
}

// Texto es el nombre y la descripción de un script de fábrica en inglés (name_en y description_en).
type Texto struct{ Name, Description string }

// LibraryWithEN es Library junto con el texto en inglés de cada script de fábrica, por ID. Los playbooks sin
// name_en no traen nombre en inglés: ese script queda con el español (In).
func LibraryWithEN(pb fs.FS) ([]Script, map[string]Texto, error) { return LibraryWith(pb, nil) }

// Contenido es lo que un paquete instalado suma a la biblioteca: un script derivado por playbook y los de scripts.json.
type Contenido struct {
	Playbooks []playbook.Playbook
	Scripts   []Script
}

// LibraryWith es LibraryWithEN más el contenido de los paquetes instalados, en el orden dado. Un ID o nombre que
// choque da error, igual que dentro de la biblioteca base (el instalador ya lo rechaza al instalar).
func LibraryWith(pb fs.FS, packs []Contenido) ([]Script, map[string]Texto, error) {
	pbs, err := playbook.Load(pb)
	if err != nil {
		return nil, nil, err
	}
	out, en := Derived(pbs), DerivedTexts(pbs)
	b, err := bibliotecaFS.ReadFile("biblioteca/configuracion.yaml")
	if err != nil {
		return nil, nil, err
	}
	var cfgs []cfgScript
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cfgs); err != nil {
		return nil, nil, fmt.Errorf("biblioteca/configuracion.yaml: %w", err)
	}
	for _, c := range cfgs {
		id := c.ID
		if c.Platform != "ios-xe" {
			id = c.Platform + "-" + id
		}
		out = append(out, Script{ID: "lib-" + id, Name: c.Name, Tech: c.Tech, Platform: c.Platform, Description: c.Description,
			Commands: c.Commands, Tags: nonNil(c.Tags), Origin: OrigenBiblioteca, CreatedAt: fechaBiblioteca, UpdatedAt: fechaBiblioteca})
		en["lib-"+id] = Texto{c.NameEN, c.DescriptionEN}
	}
	for _, c := range packs {
		out = append(append(out, Derived(c.Playbooks)...), c.Scripts...)
		for k, v := range DerivedTexts(c.Playbooks) {
			en[k] = v
		}
	}
	ids, nombres := map[string]bool{}, map[string]bool{}
	for _, s := range out {
		if err := s.Validate(); err != nil {
			return nil, nil, fmt.Errorf("biblioteca %s: %w", s.ID, err)
		}
		if k := NameKey(s.Name); ids[s.ID] || nombres[k] {
			return nil, nil, fmt.Errorf("biblioteca %s (%q): ID o nombre repetido", s.ID, s.Name)
		}
		ids[s.ID], nombres[NameKey(s.Name)] = true, true
	}
	return out, en, nil
}

// Derived arma el script de diagnóstico «lib-<id>» de cada playbook (los comandos son los del playbook), y solo esos:
// nunca los de configuración. Lo usan la biblioteca y los paquetes de contenido: un playbook movido a un paquete
// conserva su ID. Un playbook con datos (params) no se deriva: un script de biblioteca no tiene dónde pedirlos.
func Derived(pbs []playbook.Playbook) []Script {
	var out []Script
	for _, p := range pbs {
		if len(p.Params) > 0 {
			continue
		}
		id := derivedID(p)
		cmds := append([]string{}, p.Pre...)
		for _, c := range p.Commands {
			cmds = append(cmds, c.Text)
		}
		out = append(out, Script{ID: "lib-" + id, Name: p.Name, Tech: techDe(id), Platform: p.Platform,
			Description: "Diagnóstico de solo lectura del playbook " + p.ID + ".",
			Commands:    cmds, Tags: []string{}, Origin: OrigenBiblioteca, CreatedAt: fechaBiblioteca, UpdatedAt: fechaBiblioteca})
	}
	return out
}

// DerivedTexts es el texto en inglés de los scripts de Derived, por ID.
func DerivedTexts(pbs []playbook.Playbook) map[string]Texto {
	en := map[string]Texto{}
	for _, p := range pbs {
		if len(p.Params) > 0 {
			continue
		}
		en["lib-"+derivedID(p)] = Texto{p.NameEn, "Read-only diagnostic of playbook " + p.ID + "."}
	}
	return en
}

func derivedID(p playbook.Playbook) string {
	id := p.ID[strings.Index(p.ID, "/")+1:]
	if p.Platform != "ios-xe" { // los IDs de ios-xe no cambian; el resto lleva su plataforma para no chocar
		id = p.Platform + "-" + id
	}
	return id
}

// In da el script de fábrica en el idioma loc: con en, su nombre y descripción en inglés (los que falten quedan en
// español); lo demás (es, o un script del usuario) queda tal cual.
func (t Texto) In(loc string, s Script) Script {
	if loc != "en" || s.Origin != OrigenBiblioteca {
		return s
	}
	if t.Name != "" {
		s.Name = t.Name
	}
	if t.Description != "" {
		s.Description = t.Description
	}
	return s
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
