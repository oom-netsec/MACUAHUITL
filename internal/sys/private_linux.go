package sys

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// MkdirPrivate crea la carpeta y sus padres con 0700 (ADR 0012, c); la ruta debe ser absoluta. En Windows la deja con
// una DACL protegida.
func MkdirPrivate(path string) error {
	if err := requireAbs(path); err != nil {
		return err
	}
	return os.MkdirAll(path, 0o700)
}

// OpenNewPrivate es OpenNew: el archivo nace 0600 (O_EXCL|O_NOFOLLOW). En Windows nace con la DACL protegida.
func OpenNewPrivate(path string) (*os.File, error) { return OpenNew(path) }

// OpenNewPrivateIn es OpenNewIn: nace 0600, dentro de una carpeta ya abierta.
func OpenNewPrivateIn(root *os.Root, name string) (*os.File, error) { return OpenNewIn(root, name) }

// CreateTempPrivate es os.CreateTemp, que ya crea 0600.
func CreateTempPrivate(dir, pattern string) (*os.File, error) { return os.CreateTemp(dir, pattern) }

// ProtectFile deja el archivo en 0600. Para uno que ya existe; hoy ninguna ruta de producción la necesita (los archivos
// nuevos nacen privados con OpenNewPrivate), queda para eso y para las pruebas.
func ProtectFile(path string) error { return os.Chmod(path, 0o600) }

// ProtectNewStrict protege un archivo recién creado con O_CREATE y 0600 (que en Linux ya nació privado): no hace nada.
func ProtectNewStrict(string) error { return nil }

// OnlyOwnAccess dice si nadie más que el usuario puede tocar el archivo o carpeta. En Linux es lo mismo que IsPrivate.
// En Windows no exige dueño ni DACL protegida: basta que ninguna ACE (heredada o no) dé acceso a un SID que no sea el
// usuario, SYSTEM o Administradores. Es lo que cumple lo que se crea dentro de una carpeta hecha con MkdirPrivate.
func OnlyOwnAccess(path string) (bool, error) { return IsPrivate(path) }

// ReadOnlyDir deja la carpeta sin permiso de escritura (0500) y devuelve cómo restaurarla. Es para pruebas: en Windows
// chmod no cierra una carpeta, ahí se deja una DACL de solo lectura (sin ACE de escritura).
func ReadOnlyDir(path string) (restore func(), err error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o500); err != nil {
		return nil, err
	}
	return func() { os.Chmod(path, fi.Mode().Perm()) }, nil
}

// IsPrivate dice si el archivo o la carpeta no da acceso a grupo ni a otros. Es para pruebas.
func IsPrivate(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fi.Mode().Perm()&0o077 == 0, nil
}

// PrivateDir comprueba una carpeta de salidas ya resuelta (sin enlaces): del usuario, 0700 exacto y sin ancestros que
// otros puedan escribir. internal/service/outputs.go conserva su propia versión en Linux (con ganchos de prueba); esta
// es la misma regla con la API común de los dos sistemas.
func PrivateDir(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return &PrivateDirError{Reason: PrivateDirRead, Path: path, Err: err}
	}
	if uid, ok := Owner(fi); !ok || uid != uint32(os.Geteuid()) {
		return &PrivateDirError{Reason: PrivateDirOwner, Path: path}
	}
	if m := fi.Mode().Perm(); m != 0o700 {
		return &PrivateDirError{Reason: PrivateDirACL, Path: path, SID: m.String()}
	}
	for a := filepath.Dir(path); ; a = filepath.Dir(a) {
		fi, err := os.Lstat(a)
		if err != nil {
			return &PrivateDirError{Reason: PrivateDirRead, Path: a, Err: err}
		}
		uid, _ := Owner(fi)
		if fi.Mode()&0o022 != 0 && uid != uint32(os.Geteuid()) {
			return &PrivateDirError{Reason: PrivateDirAncestor, Path: a, SID: fi.Mode().String()}
		}
		if a == filepath.Dir(a) {
			return nil
		}
	}
}

// Ganchos de las pruebas de ForeignWriters.
var (
	geteuid, getegid = func() uint32 { return uint32(os.Geteuid()) }, func() uint32 { return uint32(os.Getegid()) }
	groupFile        = "/etc/group"
	passwdFile       = "/etc/passwd"
	mountInfoFile    = "/proc/self/mountinfo"
	// hasPosixACL: la carpeta lleva un ACL POSIX de acceso (system.posix_acl_access): los bits de grupo ya no dicen quién escribe.
	// Sin xattr o sin soporte, no; cualquier otro error (no se sabe) cuenta como que sí.
	hasPosixACL = func(f *os.File) bool {
		_, err := unix.Fgetxattr(int(f.Fd()), "system.posix_acl_access", nil)
		return err == nil || !(errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP))
	}
)

// groupShared: el gid tiene algún miembro suplementario en /etc/group, o es el grupo primario de otro uid en /etc/passwd. Si
// no se pueden leer los archivos o el grupo no está en /etc/group (NSS: LDAP, sssd) no se sabe: cuenta como compartido.
func groupShared(gid, uid uint32) bool {
	g, err := os.ReadFile(groupFile)
	if err != nil {
		return true
	}
	found := false
	for _, l := range strings.Split(string(g), "\n") {
		f := strings.Split(l, ":")
		if len(f) >= 4 && f[2] == strconv.FormatUint(uint64(gid), 10) {
			found = true
			if strings.TrimSpace(f[3]) != "" {
				return true
			}
		}
	}
	p, err := os.ReadFile(passwdFile)
	if err != nil || !found {
		return true
	}
	for _, l := range strings.Split(string(p), "\n") {
		f := strings.Split(l, ":")
		if len(f) >= 4 && f[3] == strconv.FormatUint(uint64(gid), 10) && f[2] != strconv.FormatUint(uint64(uid), 10) {
			return true
		}
	}
	return false
}

// groupIsPrivate dice si g+w de la carpeta no da escritura a nadie más: el grupo es el privado del usuario (UPG: Debian, Ubuntu y
// Fedora crean un grupo con su mismo gid y uid, y con el umask 002 toda carpeta nueva sale 0775), no tiene otros miembros
// (groupShared) y la carpeta no lleva un ACL POSIX.
func groupIsPrivate(f *os.File, st *syscall.Stat_t) bool {
	uid, gid := geteuid(), getegid()
	return st.Gid == gid && gid == uid && !hasPosixACL(f) && !groupShared(gid, uid)
}

// noPermsFuse: la línea de mountinfo del dispositivo dev es un ntfs-3g sin «permissions» (el núcleo FUSE no aplica
// default_permissions): los modos son inventados y cualquier usuario del equipo accede.
func noPermsFuse(info string, dev uint64) bool {
	want := fmt.Sprintf("%d:%d", unix.Major(dev), unix.Minor(dev))
	for _, l := range strings.Split(info, "\n") {
		pre, post, ok := strings.Cut(l, " - ")
		if f := strings.Fields(pre); ok && len(f) > 2 && f[2] == want {
			g := strings.Fields(post)
			if len(g) < 3 || !(g[0] == "fuseblk" || strings.HasPrefix(g[0], "fuse.ntfs") || g[0] == "ntfs-3g") {
				return false
			}
			return !slices.Contains(strings.Split(g[2], ","), "default_permissions")
		}
	}
	return false
}

// noPermsVolume dice si el volumen de f no tiene permisos por usuario: FAT (vfat, msdos), exFAT y ntfs-3g sin «permissions».
func noPermsVolume(f *os.File, st *syscall.Stat_t) bool {
	var s syscall.Statfs_t
	if syscall.Fstatfs(int(f.Fd()), &s) != nil {
		return false
	}
	switch int64(s.Type) {
	case 0x4d44, 0x2011BAB0: // MSDOS_SUPER_MAGIC (vfat y msdos), EXFAT_SUPER_MAGIC
		return true
	case 0x65735546: // FUSE_SUPER_MAGIC (ntfs-3g es fuseblk)
		b, _ := os.ReadFile(mountInfoFile)
		return noPermsFuse(string(b), uint64(st.Dev))
	}
	return false
}

// ForeignWritersFile dice quién más que el usuario puede escribir en la carpeta abierta f: su dueño si no es el usuario («owner»; cambiarlo exige
// privilegios), los bits de grupo (salvo grupo privado sin otros miembros ni ACL) y los de otros («g+w», «o+w»). Un volumen sin
// permisos por usuario devuelve errors.ErrUnsupported.
func ForeignWritersFile(f *os.File) (Writers, error) {
	fi, err := f.Stat()
	if err != nil {
		return Writers{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return Writers{}, errors.New("sys: sin datos de dueño")
	}
	if noPermsVolume(f, st) {
		return Writers{}, errors.ErrUnsupported
	}
	var w Writers
	if st.Uid != geteuid() {
		w.Who, w.ForeignOwner = append(w.Who, "owner"), true
	}
	if fi.Mode().Perm()&0o020 != 0 && !groupIsPrivate(f, st) {
		w.Who = append(w.Who, "g+w")
	}
	if fi.Mode().Perm()&0o002 != 0 {
		w.Who = append(w.Who, "o+w")
	}
	return w, nil
}
