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
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const defaultTimeout = 60 * time.Second

type Command struct {
	Text       string
	Timeout    time.Duration
	MaySecrets bool
}

// Playbook tiene ID "<plataforma>/<id del archivo>" (p. ej. "ios-xe/tac-baseline").
type Playbook struct {
	ID, Platform, Name string
	Pre                []string
	Commands           []Command
}

type fileCommand struct {
	Cmd        string `yaml:"cmd"`
	Timeout    string `yaml:"timeout"`
	MaySecrets bool   `yaml:"may_contain_secrets"`
}

type file struct {
	ID       string        `yaml:"id"`
	Platform string        `yaml:"platform"`
	Name     string        `yaml:"name"`
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
	p := Playbook{ID: f.Platform + "/" + f.ID, Platform: f.Platform, Name: f.Name, Pre: f.Pre}
	for _, c := range append(f.Pre, cmdTexts(f.Commands)...) {
		if err := CheckDenied(f.Platform, c); err != nil {
			return Playbook{}, err
		}
	}
	for _, c := range f.Commands {
		cmd := Command{Text: strings.TrimSpace(c.Cmd), Timeout: defaultTimeout, MaySecrets: c.MaySecrets}
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
