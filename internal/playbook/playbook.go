// Package playbook carga y valida playbooks YAML y filtra comandos que
// cambian configuración (spec §8).
//
// No hace: ejecutar comandos.
package playbook

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"path"
	"slices"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

const defaultTimeout = 60 * time.Second

// MaxTimeout es el timeout más largo que acepta un playbook. Debe coincidir con maxRun de internal/platform/iosxe
// (el tope fijo por comando del driver); no se importa de allá para no acoplar los paquetes.
const MaxTimeout = 30 * time.Minute

type Command struct {
	Text       string
	Timeout    time.Duration // de inactividad: el driver lo reinicia mientras llega salida
	MaySecrets bool
	// Platforms: solo corre en esas plataformas detectadas; vacío = en todas las compatibles.
	Platforms []string
}

// Applies dice si el comando corre en la plataforma detectada; un 9800 es IOS-XE, así que corre los marcados ios-xe.
func (c Command) Applies(detected string) bool {
	return len(c.Platforms) == 0 || slices.Contains(c.Platforms, detected) ||
		(detected == "wlc-9800" && slices.Contains(c.Platforms, "ios-xe"))
}

// Compatible: un IOS clásico y un WLC 9800 (que es IOS-XE) usan también los playbooks de IOS-XE; lo que no exista queda marcado inválido.
func Compatible(detected, pbPlatform string) bool {
	return detected == pbPlatform || (pbPlatform == "ios-xe" && (detected == "ios" || detected == "wlc-9800"))
}

// PackUsuario es el Pack de los playbooks de <config>/playbooks (propios o importados): no es un ID de paquete válido
// (no lleva «editor/nombre»), así que no choca con ninguno, y solo se empareja con los de su propio origen.
const PackUsuario = "usuario"

func officialPack(p string) bool { return p == "" || strings.HasPrefix(p, "oom/") }

// Twin es el gemelo de id en la plataforma platform ("ios-xe/x" ↔ "ios/x"), o nil. No cruza paquetes de terceros:
// solo si ambos son del mismo paquete u origen, o ambos oficiales (base u oom/*). Si id ya no existe, se trata como oficial.
func Twin(pbs []Playbook, id, platform string) *Playbook {
	pl, rest, _ := strings.Cut(id, "/")
	if pl == platform || (pl != "ios" && pl != "ios-xe") || (platform != "ios" && platform != "ios-xe") {
		return nil
	}
	orig := ""
	for _, p := range pbs {
		if p.ID == id {
			orig = p.Pack
		}
	}
	for i, p := range pbs {
		if p.ID == platform+"/"+rest && (p.Pack == orig || officialPack(p.Pack) && officialPack(orig)) {
			return &pbs[i]
		}
	}
	return nil
}

// Visible son los playbooks compatibles con detected, sin repetir: en IOS clásico, ios/<x> tapa a ios-xe/<x>.
func Visible(detected string, pbs []Playbook) []Playbook {
	var out []Playbook
	for _, p := range pbs {
		if Compatible(detected, p.Platform) && (p.Platform == detected || Twin(pbs, p.ID, detected) == nil) {
			out = append(out, p)
		}
	}
	return out
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
	Pack                       string // ID del paquete que lo trae; vacío = contenido base; PackUsuario = <config>/playbooks (no se serializa)
	Pre                        []string
	Commands                   []Command
	// Params son los datos que el playbook pide (MAC, AP...); vacío = el playbook de siempre.
	Params []Param
}

type fileCommand struct {
	Cmd        string   `yaml:"cmd"`
	Timeout    string   `yaml:"timeout,omitempty"`
	MaySecrets bool     `yaml:"may_contain_secrets,omitempty"`
	Platforms  []string `yaml:"platforms,omitempty"`
}

type fileParam struct {
	Name string `yaml:"name"`
	Kind string `yaml:"kind"`
}

type file struct {
	ID       string        `yaml:"id"`
	Platform string        `yaml:"platform"`
	Name     string        `yaml:"name"`
	NameEn   string        `yaml:"name_en,omitempty"`
	Pre      []string      `yaml:"pre,omitempty"`
	Params   []fileParam   `yaml:"params,omitempty"`
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
			return i18n.Wrap("playbook.err.file", err, i18n.A("name", name))
		}
		p, err := parse(b)
		if err != nil {
			return i18n.Wrap("playbook.err.file", err, i18n.A("name", name))
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
		return Playbook{}, i18n.New("playbook.err.required", nil)
	}
	if len(f.Commands) == 0 {
		return Playbook{}, i18n.New("playbook.err.no_commands", nil)
	}
	for field, v := range map[string]string{"name": f.Name, "name_en": f.NameEn} {
		if hidden(v) {
			return Playbook{}, i18n.New("playbook.err.text", i18n.A("field", field))
		}
	}
	for _, c := range append(slices.Clone(f.Pre), cmdTexts(f.Commands)...) {
		if hidden(c) {
			return Playbook{}, i18n.New("playbook.err.text", i18n.A("field", "cmd"))
		}
	}
	p := Playbook{ID: f.Platform + "/" + f.ID, Platform: f.Platform, Name: f.Name, NameEn: f.NameEn, Pre: f.Pre}
	for _, q := range f.Params {
		p.Params = append(p.Params, Param(q))
	}
	if err := checkParams(p.Params, f.Pre, f.Commands); err != nil {
		return Playbook{}, err
	}
	for _, c := range append(f.Pre, cmdTexts(f.Commands)...) {
		if err := CheckDenied(f.Platform, c); err != nil {
			return Playbook{}, err
		}
	}
	for _, c := range f.Commands {
		cmd := Command{Text: strings.TrimSpace(c.Cmd), Timeout: defaultTimeout, MaySecrets: c.MaySecrets, Platforms: c.Platforms}
		for _, pl := range c.Platforms {
			if !slices.Contains(knownPlatforms, pl) {
				return Playbook{}, i18n.New("playbook.err.platform", i18n.A("platform", pl, "cmd", cmd.Text))
			}
		}
		if cmd.Text == "" {
			return Playbook{}, i18n.New("playbook.err.empty_command", nil)
		}
		if c.Timeout != "" {
			d, err := time.ParseDuration(c.Timeout)
			if err != nil || d <= 0 {
				return Playbook{}, i18n.New("playbook.err.timeout", i18n.A("timeout", c.Timeout, "cmd", cmd.Text))
			}
			if d > MaxTimeout {
				return Playbook{}, i18n.New("playbook.err.timeout_max", i18n.A("timeout", c.Timeout, "cmd", cmd.Text, "max", MaxTimeout.String()))
			}
			cmd.Timeout = d
		}
		p.Commands = append(p.Commands, cmd)
	}
	return p, nil
}

// hidden dice si s lleva caracteres de control o de formato (Cf: bidi U+202E…), que cambian cómo se ve el texto sin
// cambiar lo que dice (trojan source).
func hidden(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
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
			return Playbook{}, denied(ln, "playbook.why.cr_in_line")
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
		return Playbook{}, i18n.New("playbook.err.none", nil)
	}
	return p, nil
}

// Marshal escribe p como YAML de playbook (el id del archivo es lo que va después de «<plataforma>/»); Load lo lee de vuelta.
func Marshal(p Playbook) ([]byte, error) {
	f := file{ID: p.ID[strings.Index(p.ID, "/")+1:], Platform: p.Platform, Name: p.Name, NameEn: p.NameEn, Pre: p.Pre}
	for _, q := range p.Params {
		f.Params = append(f.Params, fileParam(q))
	}
	for _, c := range p.Commands {
		fc := fileCommand{Cmd: c.Text, MaySecrets: c.MaySecrets, Platforms: c.Platforms}
		if c.Timeout != defaultTimeout {
			fc.Timeout = c.Timeout.String()
		}
		f.Commands = append(f.Commands, fc)
	}
	return yaml.Marshal(f)
}
