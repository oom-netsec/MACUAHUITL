package fileserve

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
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

func denyList(extra []string) []string {
	out := append([]string(nil), sensitiveDirs...)
	if home, err := homeDir(); err == nil {
		for _, h := range sensitiveHome {
			out = append(out, filepath.Join(home, h))
		}
	}
	for _, env := range []string{"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"} {
		if v := os.Getenv(env); filepath.IsAbs(v) {
			out = append(out, filepath.Join(v, "macuahuitl"))
		}
	}
	return append(out, extra...)
}

// ValidateDir valida una carpeta elegida por el usuario y devuelve su ruta real, que es la
// que se usa desde entonces (una sola resolución al iniciar). Debe ser absoluta, existir y
// ser una carpeta; si la ruta misma es un enlace simbólico se rechaza (se pide la ruta real,
// así lo que se muestra y se audita es lo que se usa). Los enlaces en los componentes
// anteriores se resuelven antes de compararla con las carpetas sensibles y extra.
func ValidateDir(dir string, extraDeny ...string) (string, error) {
	real, _, err := validateDir(dir, extraDeny)
	return real, err
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
	return root, real, nil
}

// validateDir devuelve también el Lstat de la carpeta validada (para compararlo con lo que se abre).
func validateDir(dir string, extraDeny []string) (string, os.FileInfo, error) {
	if !filepath.IsAbs(dir) {
		return "", nil, i18n.New("fileserve.err.dir_relative", i18n.A("dir", dir))
	}
	clean := filepath.Clean(dir)
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
	home, err := homeDir()
	if err != nil {
		return "", nil, err
	}
	for _, d := range denyList(extraDeny) {
		for _, p := range []string{clean, real} {
			if inside(p, d) {
				return "", nil, i18n.New("fileserve.err.dir_sensitive", i18n.A("dir", p, "deny", d))
			}
		}
	}
	for _, p := range []string{clean, real} {
		if h := hiddenUnderHome(p); h != "" {
			return "", nil, i18n.New("fileserve.err.dir_sensitive", i18n.A("dir", p, "deny", h))
		}
	}
	if real == "/" || clean == "/" {
		return "", nil, i18n.New("fileserve.err.dir_root", nil)
	}
	hr, err := evalSymlinks(home)
	if err != nil { // sin $HOME real no se puede descartar que la carpeta pedida sea $HOME por otro camino: se rechaza
		return "", nil, fmt.Errorf("fileserve: %w", err)
	}
	if clean == filepath.Clean(home) || real == hr {
		return "", nil, i18n.New("fileserve.err.dir_home", nil)
	}
	return real, st, nil
}

// inside dice si p es d o cuelga de d.
func inside(p, d string) bool {
	d = filepath.Clean(d)
	return p == d || strings.HasPrefix(p, d+string(filepath.Separator))
}

// checkPathsDeny aplica la lista de carpetas sensibles y la regla de ocultos a cada ruta (la dada y la real:
// un enlace simbólico no lo disfraza). Sin $HOME conocido rechaza.
func checkPathsDeny(extra []string, paths ...string) error {
	if _, err := homeDir(); err != nil {
		return err
	}
	for _, d := range denyList(extra) {
		for _, p := range paths {
			if inside(p, d) {
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
	home, err := homeDir()
	if err != nil {
		return ""
	}
	homes := []string{filepath.Clean(home)}
	if hr, err := evalSymlinks(home); err == nil {
		homes = append(homes, hr)
	}
	for _, h := range homes {
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
