// Package playbook carga y valida playbooks YAML y filtra comandos que
// cambian configuración (spec §8).
//
// No hace: ejecutar comandos.
package playbook

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultTimeout = 60 * time.Second

type Command struct {
	Text       string
	Timeout    time.Duration
	MaySecrets bool
	// Platforms: solo corre en esas plataformas detectadas; vacío = en todas las compatibles.
	Platforms []string
}

// Applies dice si el comando corre en la plataforma detectada.
func (c Command) Applies(detected string) bool {
	return len(c.Platforms) == 0 || slices.Contains(c.Platforms, detected)
}

// Compatible: un IOS clásico usa los playbooks de IOS-XE; lo que no exista queda marcado inválido.
func Compatible(detected, pbPlatform string) bool {
	return detected == pbPlatform || (detected == "ios" && pbPlatform == "ios-xe")
}

// knownPlatforms son las plataformas que un playbook puede nombrar en platforms: (las de playbooks/cisco).
var knownPlatforms = []string{"ios", "ios-xe", "nx-os", "cat9k", "ftd", "ise", "sda", "wlc-9800", "wlc-aireos"}

// KnownPlatforms son las plataformas que un playbook puede nombrar.
func KnownPlatforms() []string { return slices.Clone(knownPlatforms) }

// KnownPlatform dice si s es una plataforma que un playbook puede nombrar.
func KnownPlatform(s string) bool { return slices.Contains(knownPlatforms, s) }

// Playbook tiene ID "<plataforma>/<id del archivo>" (p. ej. "ios-xe/tac-baseline"). NameEn es el nombre en inglés
// (name_en); los playbooks del usuario pueden omitirlo y NameFor cae al nombre en español.
type Playbook struct {
	ID, Platform, Name, NameEn string
	Pre                        []string
	Commands                   []Command
}

type fileCommand struct {
	Cmd        string   `yaml:"cmd"`
	Timeout    string   `yaml:"timeout"`
	MaySecrets bool     `yaml:"may_contain_secrets"`
	Platforms  []string `yaml:"platforms"`
}

type file struct {
	ID       string        `yaml:"id"`
	Platform string        `yaml:"platform"`
	Name     string        `yaml:"name"`
	NameEn   string        `yaml:"name_en"`
	Pre      []string      `yaml:"pre"`
	Commands []fileCommand `yaml:"commands"`
}

// Load lee todos los *.yaml de fsys. Un archivo inválido devuelve error con su nombre.
func Load(fsys fs.FS) ([]Playbook, error) {
	var out []Playbook
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path.Ext(name) != ".yaml" {
			return err
		}
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return fmt.Errorf("playbook %s: %w", name, err)
		}
		p, err := parse(b)
		if err != nil {
			return fmt.Errorf("playbook %s: %w", name, err)
		}
		out = append(out, p)
		return nil
	})
	return out, err
}

func parse(b []byte) (Playbook, error) {
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return Playbook{}, err
	}
	if f.ID == "" || f.Platform == "" || f.Name == "" {
		return Playbook{}, errors.New("id, platform y name son obligatorios")
	}
	if len(f.Commands) == 0 {
		return Playbook{}, errors.New("sin comandos")
	}
	p := Playbook{ID: f.Platform + "/" + f.ID, Platform: f.Platform, Name: f.Name, NameEn: f.NameEn, Pre: f.Pre}
	for _, c := range append(f.Pre, cmdTexts(f.Commands)...) {
		if err := CheckDenied(f.Platform, c); err != nil {
			return Playbook{}, err
		}
	}
	for _, c := range f.Commands {
		cmd := Command{Text: strings.TrimSpace(c.Cmd), Timeout: defaultTimeout, MaySecrets: c.MaySecrets, Platforms: c.Platforms}
		for _, pl := range c.Platforms {
			if !slices.Contains(knownPlatforms, pl) {
				return Playbook{}, fmt.Errorf("plataforma desconocida %q en platforms de %q", pl, cmd.Text)
			}
		}
		if cmd.Text == "" {
			return Playbook{}, errors.New("comando vacío")
		}
		if c.Timeout != "" {
			d, err := time.ParseDuration(c.Timeout)
			if err != nil || d <= 0 {
				return Playbook{}, fmt.Errorf("timeout %q inválido en %q", c.Timeout, cmd.Text)
			}
			cmd.Timeout = d
		}
		p.Commands = append(p.Commands, cmd)
	}
	return p, nil
}

func cmdTexts(cs []fileCommand) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.Cmd
	}
	return out
}

// NameFor da el nombre en el idioma loc ("en" usa name_en si lo hay; todo lo demás, el nombre en español).
func (p Playbook) NameFor(loc string) string {
	if loc == "en" && p.NameEn != "" {
		return p.NameEn
	}
	return p.Name
}

// Ephemeral convierte comandos pegados (uno por línea) en un playbook.
// Ignora líneas vacías y las que empiezan con "!".
func Ephemeral(platform, text string) (Playbook, error) {
	sum := sha256.Sum256([]byte(text))
	p := Playbook{ID: "custom-" + hex.EncodeToString(sum[:])[:12], Platform: platform, Name: "Comandos pegados"}
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(strings.TrimSuffix(ln, "\r")) // CRLF pegado; un \r interno lo rechaza CheckDenied
		if strings.ContainsRune(ln, '\r') {
			return Playbook{}, denied(ln, "retorno de carro dentro de la línea")
		}
		if ln == "" || strings.HasPrefix(ln, "!") {
			continue
		}
		if err := CheckDenied(platform, ln); err != nil {
			return Playbook{}, err
		}
		p.Commands = append(p.Commands, Command{Text: ln, Timeout: defaultTimeout, MaySecrets: true})
	}
	if len(p.Commands) == 0 {
		return Playbook{}, errors.New("playbook: no hay comandos")
	}
	return p, nil
}
