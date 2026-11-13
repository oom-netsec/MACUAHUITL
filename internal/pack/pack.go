// Package pack lee, valida e instala paquetes de contenido (.mpack, ADR 0010): un zip con playbooks, scripts y
// un manifiesto, que puede llevar la firma Ed25519 oficial. El .mpack es dato no confiable.
//
// No hace: descargar paquetes (noegress), ejecutar nada del paquete ni firmar con la llave oficial; solo verifica.
package pack

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing/fstest"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/scripts"
)

// Installable son las plataformas con driver de Patrol y reglas propias de CheckDenied (ADR 0010).
var Installable = []string{"ios", "ios-xe"}

var (
	idRe      = regexp.MustCompile(`^([a-z0-9][a-z0-9-]{0,31})/([a-z0-9][a-z0-9-]{0,31})$`)
	semverRe  = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	licenseRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$`)
)

// Manifest es manifest.yaml.
type Manifest struct {
	ID            string   `yaml:"id"`
	Version       string   `yaml:"version"`
	MinCore       string   `yaml:"min_core"`
	Name          string   `yaml:"name"`
	NameEn        string   `yaml:"name_en"`
	Description   string   `yaml:"description"`
	DescriptionEn string   `yaml:"description_en"`
	Platforms     []string `yaml:"platforms"`
	Author        string   `yaml:"author"`
	License       string   `yaml:"license"`
}

// Editor es la parte de ID antes de «/».
func (m Manifest) Editor() string { e, _, _ := strings.Cut(m.ID, "/"); return e }

// Pack es un paquete ya validado.
type Pack struct {
	Manifest
	Official  bool // la firma válida con la llave oficial; nunca un campo guardado
	Playbooks []playbook.Playbook
	Scripts   []scripts.Script
	Readme    string
	SHA256    string // del archivo .mpack (vacío si salió de una carpeta)
	DevCore   bool   // el núcleo es «dev»: min_core se aceptó sin comparar
	files     map[string][]byte
}

// Origin es el origen para auditoría y listas.
func (p *Pack) Origin() string {
	if p.Official {
		return "official"
	}
	return "third-party"
}

func rej(reason string, kv ...any) error { return i18n.New("pack.err."+reason, i18n.A(kv...)) }

func rejWrap(reason string, cause error, kv ...any) error {
	return i18n.Wrap("pack.err."+reason, cause, i18n.A(kv...))
}

// Reason da el motivo de rechazo corto («signature.invalid») de un error de este paquete; vacío si no lo es.
func Reason(err error) string {
	var c i18n.Coded
	if errors.As(err, &c) {
		return strings.TrimPrefix(c.Reason(), "pack.err.")
	}
	return ""
}

// Verify hace los pasos 2 a 6 del ADR sobre un .mpack ya en memoria. keys son las llaves oficiales aceptadas.
func Verify(data []byte, coreVersion string, keys []ed25519.PublicKey) (*Pack, error) {
	files, err := unzip(data)
	if err != nil {
		return nil, err
	}
	p, err := check(files, coreVersion, keys, false)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(data)
	p.SHA256 = hex.EncodeToString(h[:])
	return p, nil
}

// Validate valida una carpeta fuente packs/<nombre>/ con las reglas del instalador, salvo la firma y la reserva
// del editor oom (la firma la pone el release). Para la prueba de CI de cada packs/*.
func Validate(dir, coreVersion string) (*Pack, error) {
	files, err := readDir(dir)
	if err != nil {
		return nil, err
	}
	return check(files, coreVersion, nil, true)
}

func check(files map[string][]byte, coreVersion string, keys []ed25519.PublicKey, source bool) (*Pack, error) {
	for _, n := range []string{fileManifest, fileReadme} {
		if _, ok := files[n]; !ok {
			return nil, rej("zip.missing", "name", n)
		}
	}
	p := &Pack{files: files}
	if sig, ok := files[fileSig]; ok {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
		if err != nil || !slices.ContainsFunc(keys, func(k ed25519.PublicKey) bool { return ed25519.Verify(k, Index(files), raw) }) {
			return nil, rej("signature.invalid")
		}
		p.Official = true
	}
	m, err := parseManifest(files[fileManifest])
	if err != nil {
		return nil, err
	}
	p.Manifest = m
	if m.Editor() == "oom" && !p.Official && !source {
		return nil, rej("editor.reserved", "editor", "oom")
	}
	if !utf8.Valid(files[fileReadme]) {
		return nil, rej("manifest.invalid", "field", "README.md")
	}
	p.Readme = string(files[fileReadme])
	if err := checkCore(m.MinCore, coreVersion, p); err != nil {
		return nil, err
	}
	if err := loadPlaybooks(p, files); err != nil {
		return nil, err
	}
	if raw, ok := files[fileScripts]; ok {
		ss, err := scripts.Parse(raw)
		if err != nil {
			return nil, rejWrap("script.invalid", err)
		}
		for _, s := range ss {
			if !slices.Contains(m.Platforms, s.Platform) && s.Platform != "cualquiera" {
				return nil, rejWrap("script.invalid", fmt.Errorf("script %s: plataforma %q fuera de platforms del manifiesto", s.ID, s.Platform))
			}
			if !p.Official && !strings.HasPrefix(s.ID, "lib-"+m.Editor()+"-") {
				return nil, rej("id.prefix", "id", s.ID, "want", "lib-"+m.Editor()+"-")
			}
		}
		p.Scripts = ss
	}
	return p, nil
}

func plain(s string, max int) bool {
	if s == "" || utf8.RuneCountInString(s) > max || s != strings.TrimSpace(s) {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) })
}

func parseManifest(b []byte) (Manifest, error) {
	var m Manifest
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return m, rejWrap("manifest.invalid", err, "field", "manifest.yaml")
	}
	bad := func(f string) (Manifest, error) { return m, rej("manifest.invalid", "field", f) }
	switch {
	case !idRe.MatchString(m.ID):
		return bad("id")
	case !semverRe.MatchString(m.Version):
		return bad("version")
	case !semverRe.MatchString(m.MinCore):
		return bad("min_core")
	case !plain(m.Name, 64):
		return bad("name")
	case !plain(m.NameEn, 64):
		return bad("name_en")
	case !plain(m.Description, 512):
		return bad("description")
	case !plain(m.DescriptionEn, 512):
		return bad("description_en")
	case !plain(m.Author, 64):
		return bad("author")
	case !licenseRe.MatchString(m.License):
		return bad("license")
	case len(m.Platforms) == 0 || len(m.Platforms) > 16:
		return bad("platforms")
	}
	for _, pl := range m.Platforms {
		if !playbook.KnownPlatform(pl) && !slices.Contains(scripts.Platforms, pl) {
			return bad("platforms")
		}
	}
	return m, nil
}

var coreRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

func semver(s string) (v [3]int, ok bool) {
	m := coreRe.FindStringSubmatch(s)
	if m == nil {
		return v, false
	}
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v, true
}

// CompareVersions compara dos X.Y.Z: -1, 0 o 1.
func CompareVersions(a, b string) int {
	x, _ := semver(a)
	y, _ := semver(b)
	return slices.Compare(x[:], y[:])
}

func checkCore(minCore, core string, p *Pack) error {
	if core == "dev" {
		p.DevCore = true
		return nil
	}
	if _, ok := semver(core); !ok || CompareVersions(minCore, core) > 0 {
		return rej("core.too_old", "min_core", minCore, "core", core)
	}
	return nil
}

func loadPlaybooks(p *Pack, files map[string][]byte) error {
	mem := fstest.MapFS{}
	for n, b := range files {
		if rest, ok := strings.CutPrefix(n, filePlay); ok {
			mem[rest] = &fstest.MapFile{Data: b}
		}
	}
	pbs, err := playbook.Load(fs.FS(mem))
	if err != nil {
		if errors.Is(err, playbook.ErrDenied) {
			return rejWrap("playbook.denied", err)
		}
		return rejWrap("playbook.invalid", err)
	}
	for _, pb := range pbs {
		if !slices.Contains(Installable, pb.Platform) || !slices.Contains(p.Platforms, pb.Platform) {
			return rej("playbook.platform", "id", pb.ID, "platform", pb.Platform)
		}
		if want := pb.Platform + "/" + p.Editor() + "-"; !p.Official && !strings.HasPrefix(pb.ID, want) {
			return rej("id.prefix", "id", pb.ID, "want", want)
		}
	}
	slices.SortFunc(pbs, func(a, b playbook.Playbook) int { return strings.Compare(a.ID, b.ID) })
	p.Playbooks = pbs
	return nil
}

func (p *Pack) String() string { return fmt.Sprintf("%s@%s", p.ID, p.Version) }
