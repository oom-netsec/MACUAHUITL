// Package upgrade verifica, con salidas ya recolectadas, que un equipo IOS-XE
// está listo para cambiar de imagen: espacio, imagen y MD5, variable de boot,
// modo install o bundle, configuración guardada y redundancia SSO para ISSU.
//
// Solo lee texto: no copia imágenes, no cambia el boot ni recarga. Interpretación
// escrita sobre la documentación pública de Cisco, sin validar en laboratorio.
package upgrade

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/capture"
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
}

type Report struct {
	Hostname   string   `json:"hostname"`
	Version    string   `json:"version"`
	Mode       string   `json:"mode"` // install, bundle o ""
	FileSystem string   `json:"file_system"`
	Image      Image    `json:"image"`
	Items      []Item   `json:"items"`
	Commands   []string `json:"commands"` // comandos de lectura sugeridos; la app no los ejecuta aquí
	Note       string   `json:"note"`
}

const note = "Solo verificación: la app no copia, no cambia el boot ni recarga. Interpretación según la documentación pública de Cisco; sin validar en laboratorio."

var (
	md5Re    = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	fsPrefix = regexp.MustCompile(`^([A-Za-z0-9\-]+:)(.*)$`)
)

// Check arma la lista de verificación. outputs viene de capture.Split o de una captura de Patrol.
func Check(outputs map[string]string, img Image, verifyOut string) (Report, error) {
	if m := fsPrefix.FindStringSubmatch(img.File); m != nil {
		img.File = m[2]
		if img.File == "" {
			return Report{}, errors.New("upgrade: falta el nombre de la imagen")
		}
	}
	switch {
	case strings.TrimSpace(img.File) == "":
		return Report{}, errors.New("upgrade: falta el nombre de la imagen")
	case strings.ContainsAny(img.File, "/\\ \t"):
		return Report{}, errors.New("upgrade: el nombre de la imagen no lleva carpetas ni espacios")
	case img.MD5 != "" && !md5Re.MatchString(img.MD5):
		return Report{}, errors.New("upgrade: el MD5 esperado son 32 caracteres hexadecimales")
	case img.Size < 0:
		return Report{}, errors.New("upgrade: tamaño negativo")
	}
	img.MD5 = strings.ToLower(img.MD5)
	ver, _ := capture.Get(outputs, "show version")
	r := Report{Image: img, Note: note, FileSystem: "flash:"}
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
	it := Item{ID: "mode", Title: "Modo de arranque (install o bundle)"}
	switch r.Mode {
	case "install":
		it.Status, it.Detail = Pass, "modo install: el upgrade va por install add/activate/commit y el boot apunta a packages.conf"
	case "bundle":
		it.Status, it.Detail = Pass, "modo bundle: arranca de un .bin; en Catalyst 9000 Cisco recomienda modo install"
	default:
		it.Status, it.Detail = Unknown, "no se pudo deducir de show version"
		if ver == "" {
			it.Detail = "falta show version"
		}
	}
	return it
}

func spaceItem(mode string, img Image, present bool, free int64) Item {
	it := Item{ID: "space", Title: "Espacio libre suficiente"}
	var need int64
	if !present {
		need += img.Size
	}
	if mode == "install" {
		need += img.Size // install add expande el .bin en paquetes de tamaño parecido
	}
	switch {
	case free < 0:
		it.Status, it.Detail = Unknown, "falta la salida de dir del sistema de archivos"
	case img.Size == 0:
		it.Status, it.Detail = Unknown, fmt.Sprintf("libre %s; indica el tamaño de la imagen para comparar", human(free))
	case free >= need:
		it.Status, it.Detail = Pass, fmt.Sprintf("libre %s, se necesitan ~%s", human(free), human(need))
	default:
		it.Status, it.Detail = Fail, fmt.Sprintf("libre %s, se necesitan ~%s; libera espacio antes (en modo install: install remove inactive)", human(free), human(need))
	}
	return it
}

func presentItem(fs string, img Image, haveDir, listed, present bool, size int64) Item {
	it := Item{ID: "image-present", Title: "La imagen está en " + fs}
	switch {
	case !haveDir || !listed:
		it.Status, it.Detail = Unknown, "falta la salida de dir "+fs
	case !present:
		it.Status, it.Detail = Fail, img.File+" no está en "+fs+"; cópiala antes de la ventana"
	case img.Size > 0 && size != img.Size:
		it.Status, it.Detail = Fail, fmt.Sprintf("mide %d bytes y se esperaban %d: copia incompleta o imagen equivocada", size, img.Size)
	default:
		it.Status, it.Detail = Pass, fmt.Sprintf("%s (%d bytes)", img.File, size)
	}
	return it
}

func md5Item(fs string, img Image, outputs map[string]string, verifyOut string) Item {
	it := Item{ID: "md5", Title: "MD5 de la imagen coincide"}
	if verifyOut == "" {
		for k, v := range outputs {
			if strings.HasPrefix(k, "verify /md5") && strings.Contains(k, strings.ToLower(img.File)) {
				verifyOut = v
			}
		}
	}
	if img.MD5 == "" {
		it.Status, it.Detail = Unknown, "indica el MD5 esperado (está en la página de descarga de Cisco)"
		return it
	}
	got := ""
	if m, ok := iosxe.ParseVerifyMD5(verifyOut); ok && (m.Path == "" || strings.HasSuffix(m.Path, img.File)) {
		got = m.Sum
	}
	switch {
	case got == "":
		it.Status, it.Detail = Unknown, fmt.Sprintf("pega la salida de: verify /md5 %s%s %s", fs, img.File, img.MD5)
	case got != img.MD5:
		it.Status, it.Detail = Fail, fmt.Sprintf("el equipo calculó %s y se esperaba %s: imagen corrupta, vuelve a copiarla", got, img.MD5)
	default:
		it.Status, it.Detail = Pass, got
	}
	return it
}

// bootSystem lee las líneas "boot system" de la configuración cuando show boot no vino.
var bootSystem = regexp.MustCompile(`(?m)^boot system (?:switch \S+ )?(\S+)`)

func bootItem(mode string, img Image, outputs map[string]string) Item {
	it := Item{ID: "boot", Title: "Variable de boot apunta a la imagen correcta"}
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
		it.Status, it.Detail = Fail, "MANUAL_BOOT = yes: tras recargar se queda en ROMMON"
	case first == "":
		it.Status, it.Detail = Unknown, "falta show boot / show bootvar o la variable está vacía"
	case mode == "install" && strings.HasSuffix(first, "packages.conf"):
		it.Status, it.Detail = Pass, first
	case mode == "install":
		it.Status, it.Detail = Fail, "apunta a "+first+"; en modo install debe apuntar a packages.conf"
	case mode == "bundle" && strings.HasSuffix(first, img.File):
		it.Status, it.Detail = Pass, first
	case mode == "bundle":
		it.Status, it.Detail = Fail, "apunta a "+first+"; en modo bundle cambia boot system a la imagen nueva y guarda antes de recargar"
	default:
		it.Status, it.Detail = Unknown, "apunta a "+first+", pero no se sabe el modo"
	}
	return it
}

func installItem(mode string, outputs map[string]string) Item {
	it := Item{ID: "install-state", Title: "Sin install pendiente (todo con commit)"}
	if mode == "bundle" {
		it.Status, it.Detail = NotApplicable, "modo bundle"
		return it
	}
	out, _ := capture.Get(outputs, "show install summary")
	rows, _ := iosxe.ParseInstallSummary(out)
	if len(rows) == 0 {
		it.Status, it.Detail = Unknown, "falta show install summary"
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
		it.Status, it.Detail = Fail, "operación sin commit: "+strings.Join(pending, ", ")+"; termina con install commit o install abort antes"
	case len(inactive) > 0:
		it.Status, it.Detail = Pass, "paquetes inactivos ocupan espacio: "+strings.Join(inactive, ", ")
	default:
		it.Status, it.Detail = Pass, "todo activado y con commit"
	}
	return it
}

func savedItem(outputs map[string]string) Item {
	it := Item{ID: "config-saved", Title: "Configuración guardada (running = startup)"}
	out, _ := capture.Get(outputs, "show running-config | include configuration change|NVRAM config", "show running-config")
	h, _ := iosxe.ParseConfigHeader(out)
	switch {
	case h.NoChange:
		it.Status, it.Detail = Pass, "sin cambios desde el último arranque"
	case h.LastChange == "":
		it.Status, it.Detail = Unknown, "falta la cabecera de show running-config (Last configuration change / NVRAM config)"
	case h.Saved == "":
		it.Status, it.Detail = Fail, "hay cambios ("+strings.TrimSpace(h.LastChange)+") y no consta que se haya guardado; usa write memory antes"
	case h.LastChangeAt.IsZero() || h.SavedAt.IsZero():
		it.Status, it.Detail = Unknown, "no se pudieron leer las fechas de la cabecera"
	case h.SavedAt.Before(h.LastChangeAt):
		it.Status, it.Detail = Fail, fmt.Sprintf("último cambio %s, guardado %s: hay cambios sin guardar", strings.TrimSpace(h.LastChange), strings.TrimSpace(h.Saved))
	default:
		it.Status, it.Detail = Pass, "guardada después del último cambio"
	}
	return it
}

// registerItem: 0x2102 (IOS-XE clásico) y 0x102 (valor de fábrica de Catalyst 9000) cargan la config guardada y arrancan de flash.
func registerItem(reg string) Item {
	it := Item{ID: "config-register", Title: "Configuration register de arranque normal"}
	switch {
	case reg == "":
		it.Status, it.Detail = Unknown, "falta la línea Configuration register de show version"
	case reg == "0x2102" || reg == "0x102":
		it.Status, it.Detail = Pass, "register "+reg
	default:
		it.Status, it.Detail = Fail, "register "+reg+": tras recargar puede ignorar la config guardada (0x2142) o quedar en ROMMON (0x0); corrígelo a 0x2102 antes"
	}
	return it
}

func redundancyItem(outputs map[string]string) Item {
	it := Item{ID: "redundancy", Title: "Redundancia SSO lista para ISSU"}
	out, _ := capture.Get(outputs, "show redundancy")
	red, ok := iosxe.ParseRedundancy(out)
	switch {
	case !ok:
		it.Status, it.Detail = Unknown, "falta show redundancy"
	case strings.EqualFold(red.Mode, "non-redundant") || red.Simplex:
		it.Status, it.Detail = NotApplicable, "equipo sin supervisor redundante: el upgrade recarga el equipo (sin ISSU)"
	case !strings.EqualFold(red.Mode, "sso"):
		it.Status, it.Detail = Fail, "modo "+red.Mode+"; ISSU requiere SSO"
	case red.StandbyHot:
		it.Status, it.Detail = Pass, "SSO con el par en STANDBY HOT"
	default:
		it.Status, it.Detail = Fail, "SSO pero el par no está en STANDBY HOT; espera a que sincronice"
	}
	return it
}

func human(b int64) string {
	return fmt.Sprintf("%.2f GB", float64(b)/1e9)
}

var statusText = map[Status]string{Pass: "OK", Fail: "FALLA", Unknown: "NO DETERMINABLE", NotApplicable: "NO APLICA"}

func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s · IOS-XE %s · modo %s · imagen destino %s%s\n", or(r.Hostname, "equipo"), or(r.Version, "?"), or(r.Mode, "?"), r.FileSystem, r.Image.File)
	for _, i := range r.Items {
		fmt.Fprintf(&b, "  %-15s %s: %s\n", statusText[i.Status], i.Title, i.Detail)
	}
	for _, c := range r.Commands {
		b.WriteString("  comando sugerido (lectura): " + c + "\n")
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
