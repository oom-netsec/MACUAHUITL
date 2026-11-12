package service

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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

// outputsErr arma el error con el código estable prefs.outputs.<motivo> al inicio (el paso de idioma de la
// fase 30a lo traduce); el texto va en español.
func outputsErr(code, format string, a ...any) error {
	return status.Errorf(codes.InvalidArgument, "prefs.outputs.%s: %s", code, fmt.Sprintf(format, a...))
}

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
		return "", outputsErr("relativa", "la ruta debe ser absoluta: %q", dir)
	}
	if slices.Contains(strings.Split(dir, string(filepath.Separator)), "..") {
		return "", outputsErr("punto_punto", "la ruta no puede llevar \"..\": %q", dir)
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", outputsErr("no_existe", "la carpeta no existe: %s (créala con permisos 0700)", dir)
		}
		return "", outputsErr("ilegible", "no se pudo leer la carpeta %s: %v", dir, err)
	}
	fi, err := os.Stat(real)
	if err != nil {
		return "", outputsErr("ilegible", "no se pudo leer la carpeta %s: %v", real, err)
	}
	if !fi.IsDir() {
		return "", outputsErr("no_directorio", "%s no es una carpeta", real)
	}
	if real == "/" || (st.Home != "" && real == resolve(st.Home)) || real == resolve("/tmp") {
		return "", outputsErr("reservada", "%s no puede ser la carpeta de salidas", real)
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
			return "", outputsErr("reservada", "%s está dentro de una carpeta reservada (%s)", real, r)
		}
		if inside(r, real) { // la elegida contiene una reservada: el núcleo escribiría entre sus propios datos
			return "", outputsErr("reservada", "%s contiene la carpeta reservada %s", real, r)
		}
	}
	if uid, ok := FileOwner(fi); !ok || uid != uint32(ProcUID()) {
		return "", outputsErr("otro_dueno", "la carpeta %s no es del usuario que corre el núcleo", real)
	}
	if m := fi.Mode().Perm(); m != 0o700 {
		return "", outputsErr("permisos", "la carpeta %s tiene modo %04o y debe ser 0700; corrígelo con: chmod 700 %s", real, m, real)
	}
	// Un ancestro que otros pueden escribir (grupo u otros) deja que alguien reemplace la ruta, o la cree 0777 tras
	// una limpieza de tmpfiles: no se acepta si no es del usuario (/tmp, /var/tmp y /dev/shm caen aquí).
	for a := filepath.Dir(real); ; a = filepath.Dir(a) {
		mode, uid, err := AncestorInfo(a)
		if err != nil {
			return "", outputsErr("ilegible", "no se pudo leer %s: %v", a, err)
		}
		if mode&0o022 != 0 && uid != uint32(ProcUID()) {
			return "", outputsErr("ancestro_inseguro", "%s cuelga de %s, que otros usuarios pueden escribir (modo %s, dueño uid %d): otro usuario podría reemplazar la ruta; elige una carpeta bajo tu carpeta personal", real, a, mode, uid)
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
		return "", outputsErr("no_escribible", "no se puede escribir en %s: %v", real, err)
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
