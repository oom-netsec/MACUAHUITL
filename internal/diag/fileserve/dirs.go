package fileserve

import (
	"fmt"
	"os"
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

func denyList(extra []string) []string {
	out := append([]string(nil), sensitiveDirs...)
	if home, err := os.UserHomeDir(); err == nil && filepath.IsAbs(home) {
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
	real, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", nil, fmt.Errorf("fileserve: %w", err)
	}
	for _, d := range denyList(extraDeny) {
		for _, p := range []string{clean, real} {
			if inside(p, d) {
				return "", nil, i18n.New("fileserve.err.dir_sensitive", i18n.A("dir", p, "deny", d))
			}
		}
	}
	if real == "/" || clean == "/" {
		return "", nil, i18n.New("fileserve.err.dir_root", nil)
	}
	if home, err := os.UserHomeDir(); err == nil && filepath.IsAbs(home) {
		if hr, err := filepath.EvalSymlinks(home); err == nil && (real == hr || clean == filepath.Clean(home)) {
			return "", nil, i18n.New("fileserve.err.dir_home", nil)
		}
	}
	return real, st, nil
}

// inside dice si p es d o cuelga de d.
func inside(p, d string) bool {
	d = filepath.Clean(d)
	return p == d || strings.HasPrefix(p, d+string(filepath.Separator))
}

// checkFileDeny aplica la lista de carpetas sensibles a un archivo suelto, tanto a su ruta como a la real
// (un enlace simbólico no lo disfraza).
func checkFileDeny(file string, extra []string) error {
	clean := filepath.Clean(file)
	paths := []string{clean}
	if real, err := filepath.EvalSymlinks(clean); err == nil {
		paths = append(paths, real)
	}
	for _, d := range denyList(extra) {
		for _, p := range paths {
			if inside(p, d) {
				return i18n.New("fileserve.err.dir_sensitive", i18n.A("dir", p, "deny", d))
			}
		}
	}
	// Directo en $HOME (.bash_history, .netrc, .git-credentials…): igual que $HOME como carpeta de envío.
	if home, err := os.UserHomeDir(); err == nil && filepath.IsAbs(home) {
		hr, _ := filepath.EvalSymlinks(home)
		for _, p := range paths {
			if d := filepath.Dir(p); d == filepath.Clean(home) || d == hr {
				return i18n.New("fileserve.err.dir_home", nil)
			}
		}
	}
	return nil
}
