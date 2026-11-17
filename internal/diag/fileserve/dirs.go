package fileserve

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// sensitiveDirs son carpetas donde ni se publica ni se recibe nada: ni ellas ni lo que
// cuelga de ellas ("/" solo se rechaza exacta, porque todo cuelga de ella).
var sensitiveDirs = []string{"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/boot", "/proc", "/sys", "/dev", "/run",
	"/root", "/opt", "/snap", "/var/lib", "/var/spool", "/var/run"}

// sensitiveHome son carpetas del usuario con secretos o desde donde algo se ejecuta o se carga
// solo (autostart y servicios de ~/.config, ~/.local/bin y ~/.local/share, ~/bin, los bin de las
// herramientas de desarrollo, los *.d del shell): escribir ahí sería ejecución de código. Cubren
// también las de la propia app (bóveda, base de datos, known_hosts). $HOME exacto se rechaza aparte.
var sensitiveHome = []string{".ssh", ".gnupg", ".aws", ".kube", ".docker", ".config", ".local", "bin",
	".cargo", ".rustup", "go/bin", ".nvm", ".pyenv", ".rbenv", ".npm-global",
	".bashrc.d", ".profile.d", ".bash_completion.d", ".zshrc.d", ".mozilla", ".pki"}

// goos es variable para que las pruebas simulen la rama de Windows en cualquier sistema.
var goos = runtime.GOOS

// exigeUnidad: en Windows de verdad (no en la simulación, que usa rutas del anfitrión) la ruta debe empezar con letra de unidad.
var exigeUnidad = runtime.GOOS == "windows"

// sinLetraDeUnidad dice si p no empieza con «X:» (letra de unidad): \\?\C:\, \\.\, \??\ y las UNC saltarían la
// lista de Windows porque ni Clean ni EvalSymlinks les quitan el prefijo. Pura: se prueba en cualquier sistema.
func sinLetraDeUnidad(p string) bool { return sys.NoDriveLetter(p) }

// finalPath es la ruta real de un handle abierto (sys.FinalPath); variable para simularla en pruebas.
var finalPath = sys.FinalPath

// accountHome es la carpeta de perfil de la cuenta (en Windows sale del token, no del entorno); "" si no se sabe.
var accountHome = func() string {
	if u, err := user.Current(); err == nil && filepath.IsAbs(u.HomeDir) {
		return u.HomeDir
	}
	return ""
}

// evalSymlinks y homeDir son variables para que las pruebas simulen su fallo.
var evalSymlinks = filepath.EvalSymlinks

// homeDir es $HOME o, si falta, el de la cuenta; sin ninguno, error (quien llama rechaza la operación).
var homeDir = func() (string, error) {
	if h := os.Getenv("HOME"); filepath.IsAbs(h) {
		return h, nil
	}
	if u, err := user.Current(); err == nil && filepath.IsAbs(u.HomeDir) {
		return u.HomeDir, nil
	}
	return "", i18n.New("fileserve.err.no_home", nil)
}

// windowsSensitiveDirs son las carpetas del sistema de Windows (donde se carga y ejecuta lo que haya) según el entorno:
// ni se publica ni se recibe en ellas ni en lo que cuelga de ellas. Vacías si la variable no está.
func windowsSensitiveDirs() []string {
	var out []string
	for _, env := range []string{"SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "APPDATA", "LOCALAPPDATA"} {
		if v := os.Getenv(env); filepath.IsAbs(v) {
			out = append(out, v)
			if r, err := evalSymlinks(v); err == nil && r != v { // la ruta real también (C:\WINDOWS, enlaces, nombres cortos)
				out = append(out, r)
			}
		}
	}
	return out
}

func denyList(extra []string) []string {
	out := append([]string(nil), sensitiveDirs...)
	if goos == "windows" {
		out = append(out, windowsSensitiveDirs()...)
	}
	if _, err := homeDir(); err == nil {
		for _, hm := range homesOf() { // $HOME (y en Windows el perfil real) tal cual y resuelto: la ruta real es la que se elige
			for _, h := range sensitiveHome {
				out = append(out, filepath.Join(hm, h))
			}
			if goos == "windows" { // AppData guarda credenciales y la carpeta Inicio (Startup) ejecuta lo que haya
				out = append(out, filepath.Join(hm, "AppData"))
			}
		}
	}
	// Config y datos XDG enteros (autostart/, systemd/user, applications/ cargan y ejecutan lo que haya), aunque
	// apunten fuera de $HOME; del estado solo lo de la app.
	for _, env := range []string{"XDG_CONFIG_HOME", "XDG_DATA_HOME"} {
		if v := os.Getenv(env); filepath.IsAbs(v) {
			out = append(out, v)
			if r, err := evalSymlinks(v); err == nil && r != v { // la ruta real también: es la que se elige al servir
				out = append(out, r)
			}
		}
	}
	if v := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(v) {
		out = append(out, filepath.Join(v, "macuahuitl"))
	}
	for _, e := range extra {
		out = append(out, e)
		if r, err := evalSymlinks(e); err == nil && r != e { // como las XDG: la ruta real también
			out = append(out, r)
		}
	}
	return out
}

// ValidateDir valida una carpeta elegida por el usuario y devuelve su ruta real, que es la
// que se usa desde entonces (una sola resolución al iniciar). Debe ser absoluta, existir y
// ser una carpeta; si la ruta misma es un enlace simbólico se rechaza (se pide la ruta real,
// así lo que se muestra y se audita es lo que se usa). Los enlaces en los componentes
// anteriores se resuelven antes de compararla con las carpetas sensibles y extra.
func ValidateDir(dir string, extraDeny ...string) (string, error) {
	r, real, err := OpenDir(dir, extraDeny...) // abre y cierra: así también aplica la ruta final del handle
	if err != nil {
		return "", err
	}
	r.Close()
	return real, nil
}

// OpenDir valida la carpeta (ValidateDir) y la abre una sola vez con os.Root; toda la E/S
// posterior va por ese Root, así cambiar la carpeta por un enlace simbólico después de validarla
// no la desvía. Comprueba que lo abierto es la misma carpeta que se validó (cierra la carrera
// entre validar y abrir). Quien la llama cierra el Root.
func OpenDir(dir string, extraDeny ...string) (*os.Root, string, error) {
	real, st, err := validateDir(dir, extraDeny)
	if err != nil {
		return nil, "", err
	}
	root, err := os.OpenRoot(real)
	if err != nil {
		return nil, "", fmt.Errorf("fileserve: %w", err)
	}
	if rst, err := root.Stat("."); err != nil || !os.SameFile(st, rst) {
		root.Close()
		return nil, "", i18n.New("fileserve.err.dir_changed", i18n.A("dir", real))
	}
	d, err := root.Open(".")
	if err == nil {
		err = checkFinal(d, extraDeny)
		d.Close()
	}
	if err != nil {
		root.Close()
		return nil, "", err
	}
	return root, real, nil
}

// validateDir devuelve también el Lstat de la carpeta validada (para compararlo con lo que se abre).
func validateDir(dir string, extraDeny []string) (string, os.FileInfo, error) {
	if !filepath.IsAbs(dir) {
		return "", nil, i18n.New("fileserve.err.dir_relative", i18n.A("dir", dir))
	}
	clean := filepath.Clean(dir)
	if exigeUnidad && sinLetraDeUnidad(clean) {
		return "", nil, i18n.New("fileserve.err.dir_no_drive", i18n.A("dir", clean))
	}
	st, err := os.Lstat(clean)
	if err != nil {
		return "", nil, i18n.Wrap("fileserve.err.dir_unreadable", err, nil)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return "", nil, i18n.New("fileserve.err.dir_symlink", i18n.A("dir", clean))
	}
	if !st.IsDir() {
		return "", nil, i18n.New("fileserve.err.dir_not_dir", i18n.A("dir", clean))
	}
	real, err := evalSymlinks(clean)
	if err != nil {
		return "", nil, fmt.Errorf("fileserve: %w", err)
	}
	if exigeUnidad && sinLetraDeUnidad(real) {
		return "", nil, i18n.New("fileserve.err.dir_no_drive", i18n.A("dir", real))
	}
	home, err := homeDir()
	if err != nil {
		return "", nil, err
	}
	for _, d := range denyList(extraDeny) {
		for _, p := range []string{clean, real} {
			if denied(p, d) {
				return "", nil, i18n.New("fileserve.err.dir_sensitive", i18n.A("dir", p, "deny", d))
			}
		}
	}
	for _, p := range []string{clean, real} {
		if h := hiddenUnderHome(p); h != "" {
			return "", nil, i18n.New("fileserve.err.dir_sensitive", i18n.A("dir", p, "deny", h))
		}
	}
	if filepath.Dir(real) == real || filepath.Dir(clean) == clean { // «/» o la raíz de una unidad (C:\)
		return "", nil, i18n.New("fileserve.err.dir_root", nil)
	}
	if _, err := evalSymlinks(home); err != nil { // sin $HOME real no se puede descartar que la carpeta pedida sea $HOME por otro camino: se rechaza
		return "", nil, fmt.Errorf("fileserve: %w", err)
	}
	for _, h := range homesOf() { // $HOME y, en Windows, el perfil real, tal cual y resuelto
		for _, p := range []string{clean, real} {
			if p == h || goos == "windows" && strings.EqualFold(p, h) {
				return "", nil, i18n.New("fileserve.err.dir_home", nil)
			}
		}
	}
	return real, st, nil
}

// denied dice si p cae en la carpeta sensible d. Excepción: <home>\AppData\Local\Temp (la carpeta temporal del
// usuario en Windows, equivalente de /tmp) y lo que cuelga de ella; no depende de TMP/TEMP, que el usuario puede
// apuntar a AppData. El resto de AppData sigue bloqueado: quien pasa un enlace desde Temp hacia Roaming también
// entrega su ruta real (validateDir/checkPathsDeny prueban ambas), y esa sí cae en Roaming.
func denied(p, d string) bool {
	if !inside(p, d) {
		return false
	}
	if goos == "windows" {
		for _, hm := range homesOf() {
			if t := filepath.Join(hm, "AppData", "Local", "Temp"); inside(t, d) && inside(p, t) {
				return false
			}
		}
	}
	return true
}

// homesOf es $HOME tal cual y resuelto; en Windows también el perfil de la cuenta (HOME lo definen Git for Windows,
// Emacs y otros y no manda sobre el perfil real), igualmente tal cual y resuelto.
func homesOf() []string {
	var cands []string
	if home, err := homeDir(); err == nil {
		cands = append(cands, home)
	}
	if goos == "windows" {
		if a := accountHome(); a != "" {
			cands = append(cands, a)
		}
	}
	var out []string
	add := func(p string) {
		p = filepath.Clean(p)
		for _, o := range out {
			if o == p || goos == "windows" && strings.EqualFold(o, p) {
				return
			}
		}
		out = append(out, p)
	}
	for _, c := range cands {
		add(c)
		if r, err := evalSymlinks(c); err == nil {
			add(r)
		}
	}
	return out
}

// checkFinal aplica la lista negada a la ruta real del handle ya abierto (f): en Windows una junction, un subst o una
// unidad de red en un tramo intermedio no los resuelve EvalSymlinks, y esta ruta es la de lo que de verdad se abrió.
// En Linux finalPath no devuelve nada y no se hace nada.
func checkFinal(f *os.File, extra []string) error {
	p, err := finalPath(f)
	if err != nil {
		return fmt.Errorf("fileserve: %w", err)
	}
	if p == "" {
		return nil
	}
	return checkPathsDeny(extra, p)
}

// inside dice si p es d o cuelga de d (en Windows sin distinguir mayúsculas).
func inside(p, d string) bool {
	d = filepath.Clean(d)
	if goos == "windows" {
		return len(p) >= len(d) && strings.EqualFold(p[:len(d)], d) && (len(p) == len(d) || p[len(d)] == filepath.Separator)
	}
	return p == d || strings.HasPrefix(p, d+string(filepath.Separator))
}

// checkPathsDeny aplica la lista de carpetas sensibles y la regla de ocultos a cada ruta (la dada y la real:
// un enlace simbólico no lo disfraza). Sin $HOME conocido rechaza.
func checkPathsDeny(extra []string, paths ...string) error {
	if _, err := homeDir(); err != nil {
		return err
	}
	for _, p := range paths {
		if exigeUnidad && sinLetraDeUnidad(p) {
			return i18n.New("fileserve.err.dir_no_drive", i18n.A("dir", p))
		}
	}
	for _, d := range denyList(extra) {
		for _, p := range paths {
			if denied(p, d) {
				return i18n.New("fileserve.err.dir_sensitive", i18n.A("dir", p, "deny", d))
			}
		}
	}
	for _, p := range paths {
		if h := hiddenUnderHome(p); h != "" {
			return i18n.New("fileserve.err.dir_sensitive", i18n.A("dir", p, "deny", h))
		}
	}
	return nil
}

// hiddenUnderHome devuelve la ruta oculta (~/.password-store, ~/.cache/x…) si algún componente de p bajo $HOME
// empieza con «.»; ~/c9300.bin y ~/Descargas/x no lo son. Se prueba con $HOME tal cual y resuelto.
func hiddenUnderHome(p string) string {
	for _, h := range homesOf() {
		rel, err := filepath.Rel(h, p)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		parts := strings.Split(rel, string(filepath.Separator))
		for i, c := range parts {
			if strings.HasPrefix(c, ".") && c != "." {
				return filepath.Join(h, filepath.Join(parts[:i+1]...))
			}
		}
	}
	return ""
}
