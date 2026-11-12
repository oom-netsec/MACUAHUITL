// Package upgrade verifica, con salidas ya recolectadas, que un equipo IOS-XE
// está listo para cambiar de imagen: espacio, imagen y MD5, variable de boot,
// modo install o bundle, configuración guardada y redundancia SSO para ISSU.
//
// Solo lee texto: no copia imágenes, no cambia el boot ni recarga. Interpretación
// escrita sobre la documentación pública de Cisco, sin validar en laboratorio.
package upgrade

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/capture"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

type Status string

const (
	Pass          Status = "pass"
	Fail          Status = "fail"
	Unknown       Status = "unknown" // no determinable con lo recolectado
	NotApplicable Status = "na"
)

type Image struct {
	File string `json:"file"` // nombre en el sistema de archivos; "bootflash:" opcional
	Size int64  `json:"size"` // bytes; 0 = no se sabe
	MD5  string `json:"md5"`  // esperado, de la página de descarga
}

type Item struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
	// TitleTx y DetailTx son Title y Detail como texto de catálogo (es/en); no viajan en el JSON.
	TitleTx, DetailTx i18n.Text `json:"-"`
}

func (it *Item) title(key string, kv ...any) { i18n.Put(&it.Title, &it.TitleTx, key, kv...) }

func (it *Item) det(st Status, key string, kv ...any) {
	it.Status = st
	i18n.Put(&it.Detail, &it.DetailTx, key, kv...)
}

type Report struct {
	Hostname   string    `json:"hostname"`
	Version    string    `json:"version"`
	Mode       string    `json:"mode"` // install, bundle o ""
	FileSystem string    `json:"file_system"`
	Image      Image     `json:"image"`
	Items      []Item    `json:"items"`
	Commands   []string  `json:"commands"` // comandos de lectura sugeridos; la app no los ejecuta aquí
	Note       string    `json:"note"`
	NoteTx     i18n.Text `json:"-"`
}

var noteTx = i18n.Tx("upgrade.note")

var (
	md5Re    = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	fsPrefix = regexp.MustCompile(`^([A-Za-z0-9\-]+:)(.*)$`)
)

// Check arma la lista de verificación. outputs viene de capture.Split o de una captura de Patrol.
func Check(outputs map[string]string, img Image, verifyOut string) (Report, error) {
	if m := fsPrefix.FindStringSubmatch(img.File); m != nil {
		img.File = m[2]
		if img.File == "" {
			return Report{}, i18n.New("upgrade.err.no_name", nil)
		}
	}
	switch {
	case strings.TrimSpace(img.File) == "":
		return Report{}, i18n.New("upgrade.err.no_name", nil)
	case strings.ContainsAny(img.File, "/\\ \t"):
		return Report{}, i18n.New("upgrade.err.bad_name", nil)
	case img.MD5 != "" && !md5Re.MatchString(img.MD5):
		return Report{}, i18n.New("upgrade.err.bad_md5", nil)
	case img.Size < 0:
		return Report{}, i18n.New("upgrade.err.neg_size", nil)
	}
	img.MD5 = strings.ToLower(img.MD5)
	ver, _ := capture.Get(outputs, "show version")
	r := Report{Image: img, Note: noteTx.In(i18n.Es), NoteTx: noteTx, FileSystem: "flash:"}
	v, _ := iosxe.ParseVersion(ver)
	r.Hostname, r.Version = v.Host, v.Version
	sysImage := v.Image
	if p := fsPrefix.FindStringSubmatch(sysImage); p != nil {
		r.FileSystem = p[1]
	}
	switch {
	case v.InstallMode != "":
		r.Mode = v.InstallMode
	case strings.HasSuffix(sysImage, "packages.conf"):
		r.Mode = "install"
	case strings.HasSuffix(sysImage, ".bin"):
		r.Mode = "bundle"
	}
	dir, _ := capture.Get(outputs, "dir "+r.FileSystem, "dir flash:", "dir bootflash:")
	d, _ := iosxe.ParseDir(dir)
	present, size, listed := false, int64(0), len(d.Files) > 0
	for _, f := range d.Files {
		if f.Name == img.File {
			present, size = true, f.Size
		}
	}
	free := int64(-1)
	if d.Total > 0 || d.Free > 0 {
		free = d.Free
	}

	r.Items = append(r.Items, r.modeItem(ver))
	r.Items = append(r.Items, spaceItem(r.Mode, img, present, free))
	r.Items = append(r.Items, presentItem(r.FileSystem, img, dir != "", listed, present, size))
	md5 := md5Item(r.FileSystem, img, outputs, verifyOut)
	r.Items = append(r.Items, md5)
	if md5.Status != Pass && img.MD5 != "" {
		r.Commands = append(r.Commands, fmt.Sprintf("verify /md5 %s%s %s", r.FileSystem, img.File, img.MD5))
	}
	r.Items = append(r.Items, bootItem(r.Mode, img, outputs))
	r.Items = append(r.Items, installItem(r.Mode, outputs))
	r.Items = append(r.Items, savedItem(outputs))
	r.Items = append(r.Items, redundancyItem(outputs))
	r.Items = append(r.Items, registerItem(v.Register))
	return r, nil
}

func (r Report) modeItem(ver string) Item {
	it := Item{ID: "mode"}
	it.title("upgrade.title.mode")
	switch r.Mode {
	case "install":
		it.det(Pass, "upgrade.detail.mode_install")
	case "bundle":
		it.det(Pass, "upgrade.detail.mode_bundle")
	default:
		it.det(Unknown, "upgrade.detail.mode_unknown")
		if ver == "" {
			it.det(Unknown, "upgrade.detail.no_version")
		}
	}
	return it
}

func spaceItem(mode string, img Image, present bool, free int64) Item {
	it := Item{ID: "space"}
	it.title("upgrade.title.space")
	var need int64
	if !present {
		need += img.Size
	}
	if mode == "install" {
		need += img.Size // install add expande el .bin en paquetes de tamaño parecido
	}
	switch {
	case free < 0:
		it.det(Unknown, "upgrade.detail.space_no_dir")
	case img.Size == 0:
		it.det(Unknown, "upgrade.detail.space_no_size", "free", human(free))
	case free >= need:
		it.det(Pass, "upgrade.detail.space_ok", "free", human(free), "need", human(need))
	default:
		it.det(Fail, "upgrade.detail.space_fail", "free", human(free), "need", human(need))
	}
	return it
}

func presentItem(fs string, img Image, haveDir, listed, present bool, size int64) Item {
	it := Item{ID: "image-present"}
	it.title("upgrade.title.present", "fs", fs)
	switch {
	case !haveDir || !listed:
		it.det(Unknown, "upgrade.detail.present_no_dir", "fs", fs)
	case !present:
		it.det(Fail, "upgrade.detail.present_absent", "file", img.File, "fs", fs)
	case img.Size > 0 && size != img.Size:
		it.det(Fail, "upgrade.detail.present_size", "size", size, "want", img.Size)
	default:
		it.det(Pass, "upgrade.detail.present_ok", "file", img.File, "size", size)
	}
	return it
}

func md5Item(fs string, img Image, outputs map[string]string, verifyOut string) Item {
	it := Item{ID: "md5"}
	it.title("upgrade.title.md5")
	if verifyOut == "" {
		for k, v := range outputs {
			if strings.HasPrefix(k, "verify /md5") && strings.Contains(k, strings.ToLower(img.File)) {
				verifyOut = v
			}
		}
	}
	if img.MD5 == "" {
		it.det(Unknown, "upgrade.detail.md5_none")
		return it
	}
	got := ""
	if m, ok := iosxe.ParseVerifyMD5(verifyOut); ok && (m.Path == "" || strings.HasSuffix(m.Path, img.File)) {
		got = m.Sum
	}
	switch {
	case got == "":
		it.det(Unknown, "upgrade.detail.md5_paste", "fs", fs, "file", img.File, "md5", img.MD5)
	case got != img.MD5:
		it.det(Fail, "upgrade.detail.md5_bad", "got", got, "want", img.MD5)
	default:
		it.det(Pass, "upgrade.detail.md5_ok", "sum", got)
	}
	return it
}

// bootSystem lee las líneas "boot system" de la configuración cuando show boot no vino.
var bootSystem = regexp.MustCompile(`(?m)^boot system (?:switch \S+ )?(\S+)`)

func bootItem(mode string, img Image, outputs map[string]string) Item {
	it := Item{ID: "boot"}
	it.title("upgrade.title.boot")
	out, _ := capture.Get(outputs, "show boot", "show bootvar")
	run, _ := capture.Get(outputs, "show running-config | include boot", "show running-config")
	boot, _ := iosxe.ParseBoot(out)
	entries := boot.Entries
	if len(entries) == 0 {
		for _, m := range bootSystem.FindAllStringSubmatch(run, -1) {
			entries = append(entries, m[1])
		}
	}
	first := ""
	if len(entries) > 0 {
		first = entries[0]
	}
	switch {
	case boot.Manual:
		it.det(Fail, "upgrade.detail.boot_manual")
	case first == "":
		it.det(Unknown, "upgrade.detail.boot_empty")
	case mode == "install" && strings.HasSuffix(first, "packages.conf"):
		it.det(Pass, "upgrade.detail.boot_ok", "first", first)
	case mode == "install":
		it.det(Fail, "upgrade.detail.boot_install", "first", first)
	case mode == "bundle" && strings.HasSuffix(first, img.File):
		it.det(Pass, "upgrade.detail.boot_ok", "first", first)
	case mode == "bundle":
		it.det(Fail, "upgrade.detail.boot_bundle", "first", first)
	default:
		it.det(Unknown, "upgrade.detail.boot_nomode", "first", first)
	}
	return it
}

func installItem(mode string, outputs map[string]string) Item {
	it := Item{ID: "install-state"}
	it.title("upgrade.title.install")
	if mode == "bundle" {
		it.det(NotApplicable, "upgrade.detail.install_bundle")
		return it
	}
	out, _ := capture.Get(outputs, "show install summary")
	rows, _ := iosxe.ParseInstallSummary(out)
	if len(rows) == 0 {
		it.det(Unknown, "upgrade.detail.install_none")
		return it
	}
	var pending, inactive []string
	for _, r := range rows {
		switch r.State {
		case "U", "D":
			pending = append(pending, r.Type+" "+r.File+" ("+r.State+")")
		case "I":
			inactive = append(inactive, r.File)
		}
	}
	switch {
	case len(pending) > 0:
		it.det(Fail, "upgrade.detail.install_pending", "list", strings.Join(pending, ", "))
	case len(inactive) > 0:
		it.det(Pass, "upgrade.detail.install_inactive", "list", strings.Join(inactive, ", "))
	default:
		it.det(Pass, "upgrade.detail.install_ok")
	}
	return it
}

func savedItem(outputs map[string]string) Item {
	it := Item{ID: "config-saved"}
	it.title("upgrade.title.saved")
	out, _ := capture.Get(outputs, "show running-config | include configuration change|NVRAM config", "show running-config")
	h, _ := iosxe.ParseConfigHeader(out)
	switch {
	case h.NoChange:
		it.det(Pass, "upgrade.detail.saved_clean")
	case h.LastChange == "":
		it.det(Unknown, "upgrade.detail.saved_no_header")
	case h.Saved == "":
		it.det(Fail, "upgrade.detail.saved_unsaved", "change", strings.TrimSpace(h.LastChange))
	case h.LastChangeAt.IsZero() || h.SavedAt.IsZero():
		it.det(Unknown, "upgrade.detail.saved_dates")
	case h.SavedAt.Before(h.LastChangeAt):
		it.det(Fail, "upgrade.detail.saved_before", "change", strings.TrimSpace(h.LastChange), "saved", strings.TrimSpace(h.Saved))
	default:
		it.det(Pass, "upgrade.detail.saved_ok")
	}
	return it
}

// registerItem: 0x2102 (IOS-XE clásico) y 0x102 (valor de fábrica de Catalyst 9000) cargan la config guardada y arrancan de flash.
func registerItem(reg string) Item {
	it := Item{ID: "config-register"}
	it.title("upgrade.title.register")
	switch {
	case reg == "":
		it.det(Unknown, "upgrade.detail.reg_missing")
	case reg == "0x2102" || reg == "0x102":
		it.det(Pass, "upgrade.detail.reg_ok", "reg", reg)
	default:
		it.det(Fail, "upgrade.detail.reg_bad", "reg", reg)
	}
	return it
}

func redundancyItem(outputs map[string]string) Item {
	it := Item{ID: "redundancy"}
	it.title("upgrade.title.redundancy")
	out, _ := capture.Get(outputs, "show redundancy")
	red, ok := iosxe.ParseRedundancy(out)
	switch {
	case !ok:
		it.det(Unknown, "upgrade.detail.red_none")
	case strings.EqualFold(red.Mode, "non-redundant") || red.Simplex:
		it.det(NotApplicable, "upgrade.detail.red_single")
	case !strings.EqualFold(red.Mode, "sso"):
		it.det(Fail, "upgrade.detail.red_mode", "mode", red.Mode)
	case red.StandbyHot:
		it.det(Pass, "upgrade.detail.red_hot")
	default:
		it.det(Fail, "upgrade.detail.red_wait")
	}
	return it
}

func human(b int64) string {
	return fmt.Sprintf("%.2f GB", float64(b)/1e9)
}

// Text es el informe legible, en español.
func (r Report) Text() string { return r.TextIn(i18n.Es) }

// TextIn es el informe en el idioma pedido (con es, el de siempre); los títulos, detalles y la nota ya vienen
// en ese idioma si el informe pasó por i18n.Localize.
func (r Report) TextIn(loc string) string {
	var b strings.Builder
	m := func(key string, kv ...any) string { return i18n.Msg(loc, key, i18n.A(kv...)) }
	fmt.Fprintf(&b, "%s\n", m("upgrade.text.head", "host", or(r.Hostname, m("upgrade.text.host")), "version", or(r.Version, "?"), "mode", or(r.Mode, "?"), "image", r.FileSystem+r.Image.File))
	for _, i := range r.Items {
		fmt.Fprintf(&b, "  %-15s %s: %s\n", m("upgrade.status."+string(i.Status)), i.Title, i.Detail)
	}
	for _, c := range r.Commands {
		b.WriteString("  " + m("upgrade.text.command", "cmd", c) + "\n")
	}
	b.WriteString(r.Note + "\n")
	return b.String()
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
