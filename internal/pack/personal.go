package pack

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/scripts"
)

// ExportInput es lo que hace falta para armar un paquete personal (ADR 0010, fase 32b). Los textos vacíos toman su valor
// por omisión; name_en y description_en copian el español.
type ExportInput struct {
	ID                                                        string // <editor>/<nombre>
	Name, NameEn, Description, DescriptionEn, Author, License string
	Core                                                      string // versión del núcleo; «dev» o no semver = min_core 0.0.0
	Now                                                       time.Time
	Scripts                                                   []scripts.Script    // los del usuario que se exportan
	Playbooks                                                 []playbook.Playbook // los de <config>/playbooks; los que no sean exportables se omiten con aviso
}

// ExportResult es el paquete armado y lo que quedó fuera.
type ExportResult struct {
	Data      []byte
	Manifest  Manifest
	Omitted   []string // IDs de playbook que no se exportaron (plataforma, ID o nombre de archivo que no sirven)
	Playbooks int
	Scripts   int
}

const readmeList = 100 // tope de nombres en el README; el README pesa a lo más 64 KB

// Export arma el .mpack personal sin firma y lo pasa por Verify como paquete de terceros: si el instalador no lo
// aceptaría, no sale.
func Export(in ExportInput) (*ExportResult, error) {
	m := idRe.FindStringSubmatch(in.ID)
	if m == nil {
		return nil, rej("manifest.invalid", "field", "id")
	}
	editor := m[1]
	if reservedSegments[editor] {
		return nil, rej("editor.reserved", "editor", editor)
	}
	if !thirdPartyEditor.MatchString(editor) {
		return nil, rej("manifest.invalid", "field", "id")
	}
	files := map[string][]byte{}
	res := &ExportResult{}
	plats := map[string]bool{}
	names := map[string]bool{}

	var out []scripts.Script
	used := map[string]bool{}
	for _, s := range in.Scripts {
		if k := scripts.NameKey(s.Name); names[k] {
			return nil, rej("export.name_dup", "name", s.Name)
		} else {
			names[k] = true
		}
		id := exportScriptID(editor, s.ID, used)
		s.ID, s.Origin = id, scripts.OrigenBiblioteca
		out = append(out, s)
		plats[s.Platform] = true
	}
	res.Scripts = len(out)
	if len(out) > 0 {
		raw, err := scripts.Marshal(out, in.Now)
		if err != nil {
			return nil, rejWrap("read", err)
		}
		files[fileScripts] = raw
	}

	var pbs []playbook.Playbook
	for _, pb := range in.Playbooks {
		pb, ok := exportPlaybook(pb, editor, files, names)
		if !ok {
			res.Omitted = append(res.Omitted, pb.ID)
			continue
		}
		pbs = append(pbs, pb)
		plats[pb.Platform] = true
	}
	res.Playbooks = len(pbs)
	if res.Scripts+res.Playbooks == 0 {
		return nil, rej("export.empty")
	}

	man := Manifest{ID: in.ID, Version: in.Now.Format("2006.0102.1504"), MinCore: "0.0.0", Name: in.Name, NameEn: in.NameEn,
		Description: in.Description, DescriptionEn: in.DescriptionEn, Author: in.Author, License: in.License}
	if v, ok := semver(in.Core); ok && in.Core != "dev" {
		man.MinCore = fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2])
	}
	if man.Name == "" {
		man.Name = m[2]
	}
	if man.NameEn == "" {
		man.NameEn = man.Name
	}
	if man.Description == "" {
		man.Description = "Paquete personal exportado desde MACUAHUITL."
	}
	if man.DescriptionEn == "" {
		man.DescriptionEn = man.Description
	}
	if man.Author == "" {
		man.Author = editor
	}
	if man.License == "" {
		man.License = "NOASSERTION"
	}
	for p := range plats {
		man.Platforms = append(man.Platforms, p)
	}
	slices.Sort(man.Platforms)
	raw, err := yaml.Marshal(man)
	if err != nil {
		return nil, rejWrap("read", err)
	}
	files[fileManifest] = raw
	files[fileReadme] = []byte(exportReadme(man, out, pbs))
	zip, err := Zip(files)
	if err != nil {
		return nil, rejWrap("read", err)
	}
	if _, err := Verify(zip, in.Core, nil); err != nil {
		return nil, err
	}
	res.Data, res.Manifest = zip, man
	return res, nil
}

// exportScriptID es lib-<editor>-<12 hex del sha256 del ID original>; si dos dieran lo mismo, avanza por el hash.
func exportScriptID(editor, orig string, used map[string]bool) string {
	h := SHA256([]byte(orig))
	for i := 0; ; i++ {
		id := "lib-" + editor + "-" + h[i:i+12]
		if !used[id] {
			used[id] = true
			return id
		}
	}
}

// exportPlaybook le pone al playbook su ID con prefijo de editor y agrega su archivo a files. ok=false (y pb.ID con el ID
// original) si no se puede exportar: plataforma que no es instalable, ID que el instalador rechazaría, script derivado
// inválido o un archivo playbooks/<id>.yaml ya tomado.
func exportPlaybook(pb playbook.Playbook, editor string, files map[string][]byte, names map[string]bool) (playbook.Playbook, bool) {
	orig := pb
	if !slices.Contains(Installable, pb.Platform) {
		return orig, false
	}
	id := pb.ID[strings.Index(pb.ID, "/")+1:]
	if !strings.HasPrefix(id, editor+"-") {
		id = editor + "-" + id
	}
	file := filePlay + id + ".yaml"
	if _, dup := files[file]; dup || !pbIDRe.MatchString(id) || !playName.MatchString(id) {
		return orig, false
	}
	pb.ID, pb.Pack = pb.Platform+"/"+id, ""
	for _, s := range scripts.Derived([]playbook.Playbook{pb}) {
		if s.Validate() != nil || names[scripts.NameKey(s.Name)] {
			return orig, false
		}
		names[scripts.NameKey(s.Name)] = true
	}
	raw, err := playbook.Marshal(pb)
	if err != nil {
		return orig, false
	}
	files[file] = raw
	return pb, true
}

func exportReadme(m Manifest, ss []scripts.Script, pbs []playbook.Playbook) string {
	var b strings.Builder
	list := func(items []string) {
		for i, it := range items {
			if i == readmeList {
				fmt.Fprintf(&b, "- … (%d)\n", len(items)-i)
				break
			}
			b.WriteString("- " + it + "\n")
		}
	}
	var sn, pn []string
	for _, s := range ss {
		sn = append(sn, s.Name)
	}
	for _, p := range pbs {
		pn = append(pn, p.ID)
	}
	fmt.Fprintf(&b, "# %s\n\n%s\n\nVersión %s · paquete personal sin firma · licencia %s.\n\n", m.Name, m.Description, m.Version, m.License)
	b.WriteString("## Cómo se carga\n\n`mctl pack install <archivo.mpack> --allow-unsigned` lo instala de solo lectura; `mctl pack import <archivo.mpack>` lo copia a «Mis scripts» y a tus playbooks.\n\n")
	if len(sn) > 0 {
		b.WriteString("## Scripts\n\n")
		list(sn)
		b.WriteString("\n")
	}
	if len(pn) > 0 {
		b.WriteString("## Playbooks\n\n")
		list(pn)
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "---\n\n# %s (English)\n\n%s\n\nVersion %s · unsigned personal package · license %s.\n\n", m.NameEn, m.DescriptionEn, m.Version, m.License)
	b.WriteString("## How to load it\n\n`mctl pack install <file.mpack> --allow-unsigned` installs it read-only; `mctl pack import <file.mpack>` copies it into \"My scripts\" and your playbooks.\n")
	return b.String()
}
