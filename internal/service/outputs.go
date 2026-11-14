package service

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// Solo para pruebas: el código de producción no los asigna. Inyectables (los usan prefs, core y las pruebas de quien valide una carpeta del cliente): dueño de un archivo, uid del proceso y creación del temporal de la prueba de escritura.
var (
	FileOwner = sys.Owner
	ProcUID   = os.Getuid
	// AncestorInfo da el modo y el dueño de un ancestro de la carpeta (sin seguir enlaces).
	AncestorInfo = RealAncestorInfo
	CreateTemp   = os.CreateTemp
)

// safeShellPath son las rutas que se pueden poner en una orden de terminal sin citar: letras (también con acento),
// números y unos pocos signos; nada de espacios, comillas, $ ni caracteres de formato (bidi).
var safeShellPath = regexp.MustCompile(`^[\p{L}\p{M}\p{N}/._+,@%=:-]+$`)

// outputsErr arma el error del código prefs.outputs.<motivo> (el prefijo va dentro del texto de es y de en).
func outputsErr(code string, kv ...any) error { return i18n.New(code, i18n.A(kv...)) }

// resolve sigue los enlaces si puede; si la ruta no existe devuelve la limpia.
func resolve(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// CheckOutputs comprueba una carpeta de salidas (la de Ajustes o la que el cliente pasa en un RPC) y devuelve la ruta resuelta (sin enlaces). Vacía = la de
// fábrica y no se comprueba nada. El núcleo no cambia los permisos del usuario: si la carpeta es más abierta que
// 0700, la rechaza y sugiere la orden. Con probe prueba además la escritura (crea y borra un temporal); al arrancar
// se llama sin probe.
func CheckOutputs(dir string, st *CoreSettings, probe bool) (string, error) {
	if dir == "" {
		return "", nil
	}
	if !filepath.IsAbs(dir) {
		return "", outputsErr("prefs.outputs.relativa", "dir", dir)
	}
	if slices.Contains(strings.Split(dir, string(filepath.Separator)), "..") {
		return "", outputsErr("prefs.outputs.punto_punto", "dir", dir)
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", outputsErr("prefs.outputs.no_existe", "dir", dir)
		}
		return "", outputsErr("prefs.outputs.ilegible", "dir", dir, "err", err)
	}
	fi, err := os.Stat(real)
	if err != nil {
		return "", outputsErr("prefs.outputs.ilegible", "dir", real, "err", err)
	}
	if !fi.IsDir() {
		return "", outputsErr("prefs.outputs.no_directorio", "dir", real)
	}
	if real == "/" || (st.Home != "" && real == resolve(st.Home)) || real == resolve("/tmp") {
		return "", outputsErr("prefs.outputs.reservada", "dir", real)
	}
	reserved := slices.Clone(st.Inside)
	if st.Home != "" {
		reserved = append(reserved, filepath.Join(st.Home, ".ssh")) // y, de paso, un ancestro de HOME contiene a .ssh
	}
	for _, r := range reserved {
		if r == "" {
			continue
		}
		r = resolve(r)
		if inside(real, r) {
			return "", outputsErr("prefs.outputs.reservada_dentro", "dir", real, "res", r)
		}
		if inside(r, real) { // la elegida contiene una reservada: el núcleo escribiría entre sus propios datos
			return "", outputsErr("prefs.outputs.reservada_contiene", "dir", real, "res", r)
		}
	}
	if uid, ok := FileOwner(fi); !ok || uid != uint32(ProcUID()) {
		return "", outputsErr("prefs.outputs.otro_dueno", "dir", real)
	}
	if m := fi.Mode().Perm(); m != 0o700 {
		code := "prefs.outputs.permisos"
		if safeShellPath.MatchString(real) { // sin comillas ni metacaracteres: la orden se puede pegar tal cual
			code += "_orden"
		}
		return "", outputsErr(code, "dir", real, "mode", fmt.Sprintf("%04o", m))
	}
	// Un ancestro que otros pueden escribir (grupo u otros) deja que alguien reemplace la ruta, o la cree 0777 tras
	// una limpieza de tmpfiles: no se acepta si no es del usuario (/tmp, /var/tmp y /dev/shm caen aquí).
	for a := filepath.Dir(real); ; a = filepath.Dir(a) {
		mode, uid, err := AncestorInfo(a)
		if err != nil {
			return "", outputsErr("prefs.outputs.ilegible_ruta", "dir", a, "err", err)
		}
		if mode&0o022 != 0 && uid != uint32(ProcUID()) {
			return "", outputsErr("prefs.outputs.ancestro_inseguro", "dir", real, "anc", a, "mode", mode, "uid", uid)
		}
		if a == "/" || a == filepath.Dir(a) {
			break
		}
	}
	if !probe {
		return real, nil
	}
	f, err := CreateTemp(real, ".mcw-")
	if err != nil {
		return "", outputsErr("prefs.outputs.no_escribible", "dir", real, "err", err)
	}
	f.Close()
	os.Remove(f.Name())
	return real, nil
}

func RealAncestorInfo(p string) (os.FileMode, uint32, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return 0, 0, err
	}
	uid, _ := FileOwner(fi)
	return fi.Mode(), uid, nil
}
