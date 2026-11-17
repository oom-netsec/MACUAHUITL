package sys

import (
	"errors"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// fileReadExec es FILE_GENERIC_READ|FILE_GENERIC_EXECUTE.
const fileReadExec = 0x1200A9

func currentSID() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid, nil
}

// readACL lee dueño, protección y ACE que dan acceso de la DACL (ver aceFromRaw). Una DACL nula da acceso total a todos.
func readACL(path string) (owner string, protected bool, aces []ace, err error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", false, nil, err
	}
	return parseSD(sd)
}

// readACLHandle es readACL sobre un handle abierto: lo que se lee es lo que se abrió, no lo que la ruta nombra ahora.
func readACLHandle(h windows.Handle) (owner string, protected bool, aces []ace, err error) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", false, nil, err
	}
	return parseSD(sd)
}

func parseSD(sd *windows.SECURITY_DESCRIPTOR) (owner string, protected bool, aces []ace, err error) {
	o, _, err := sd.Owner()
	if err != nil {
		return "", false, nil, err
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		return "", false, nil, err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return "", false, nil, err
	}
	if acl == nil {
		return o.String(), false, []ace{{sid: "S-1-1-0", mask: anyAccess}}, nil
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &a); err != nil {
			return "", false, nil, err
		}
		var sid string // solo los tipos 0x0 y 0x9 traen el SID en SidStart; en los de objeto la posición cambia
		if t := a.Header.AceType; t == windows.ACCESS_ALLOWED_ACE_TYPE || t == 0x9 {
			sid = (*windows.SID)(unsafe.Pointer(&a.SidStart)).String()
		}
		if e, ok := aceFromRaw(a.Header.AceType, a.Header.AceFlags, uint32(a.Mask), sid); ok {
			aces = append(aces, e)
		}
	}
	return o.String(), ctrl&windows.SE_DACL_PROTECTED != 0, aces, nil
}

// protect fija dueño = usuario y una DACL protegida solo con usuario, SYSTEM y Administradores. Con inherit la ACE se
// hereda a lo que se cree dentro (OI|CI); SetNamedSecurityInfo la propaga también a lo que ya hay.
func protect(path string, inherit bool) error {
	user, err := currentSID()
	if err != nil {
		return err
	}
	inh := uint32(windows.NO_INHERITANCE)
	if inherit {
		inh = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	var entries []windows.EXPLICIT_ACCESS
	for _, s := range []string{user.String(), sidSystem, sidAdmins} {
		sid, err := windows.StringToSid(s)
		if err != nil {
			return err
		}
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: fileAllAccess,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inh,
			Trustee:           windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeValue: windows.TrusteeValueFromSID(sid)},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	// Cambiar el dueño exige WRITE_OWNER, que quien solo tiene «Modificar» no tiene: solo se pide si hace falta.
	info, owner := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION), (*windows.SID)(nil)
	if cur, _, _, rerr := readACL(path); rerr != nil || cur != user.String() {
		info |= windows.OWNER_SECURITY_INFORMATION
		owner = user
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, owner, nil, acl, nil)
	if errors.Is(err, windows.ERROR_NOT_SUPPORTED) || errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
		err = errors.Join(errors.ErrUnsupported, err)
	}
	return err
}

// MkdirPrivate crea la carpeta y los padres que falten (como MkdirAll) y les pone la DACL protegida con herencia
// OI|CI, para que lo que se cree adentro la herede. La ruta debe ser absoluta. Si la carpeta ya existe (la UI puede
// crearla antes que el núcleo, con la ACL heredada):
//   - un enlace simbólico o una junction se rechaza (PrivateDirACL): la ACL que se leería es la del destino;
//   - si su dueño es el usuario o Administradores (el dueño por omisión de un token elevado) se le reaplica la DACL,
//     que deja al usuario como dueño, salvo que ya sea privada y heredable, para no recorrer el árbol en cada arranque;
//   - si el dueño es otro SID devuelve el error sys.err.not_owner.
func MkdirPrivate(path string) error {
	if err := requireAbs(path); err != nil {
		return err
	}
	user, err := currentSID()
	if err != nil {
		return err
	}
	path = filepath.Clean(path)
	var nuevas []string
	for p := path; ; p = filepath.Dir(p) {
		if _, err := os.Stat(p); err == nil || filepath.Dir(p) == p {
			break
		}
		nuevas = append(nuevas, p)
	}
	if len(nuevas) == 0 || nuevas[0] != path { // ya existía
		fi, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !fi.IsDir() { // junction (ModeIrregular) o enlace simbólico (ModeSymlink)
			return &PrivateDirError{Reason: PrivateDirLink, Path: path}
		}
		owner, protected, aces, err := readACL(path)
		if err != nil {
			return err
		}
		if !ownerAcceptable(owner, user.String()) {
			return i18n.New("sys.err.not_owner", i18n.A("path", path))
		}
		if isPrivateACL(owner, user.String(), protected, aces) && allInherit(aces) {
			return nil
		}
		nuevas = append(nuevas, path)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	for _, p := range nuevas {
		if err := protect(p, true); err != nil {
			return err
		}
	}
	return nil
}

// OpenNewPrivate crea un archivo nuevo para leer y escribir que NACE con la DACL protegida (dueño el usuario; usuario,
// SYSTEM y Administradores, sin herencia): el descriptor va en el CreateFile, así que no hay un hueco con la ACL heredada
// en el que otro usuario con acceso a la carpeta pueda abrir el archivo. Como OpenNew, falla si la ruta existe y no
// sigue enlaces (CREATE_NEW con FILE_FLAG_OPEN_REPARSE_POINT) y rechaza rutas UNC y de dispositivo. Un sistema de
// archivos sin ACL (FAT, exFAT) ignora el descriptor y el archivo se crea igual.
func OpenNewPrivate(path string) (*os.File, error) {
	if err := checkPath(path); err != nil {
		return nil, err
	}
	user, err := currentSID()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString(privateSDDL(user.String()))
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// OpenNewPrivateIn es OpenNewPrivate dentro de una carpeta ya abierta (os.Root). Crea por nombre (root.Name()) y luego
// comprueba que el archivo creado sea el mismo que ve la carpeta abierta: si alguien renombró la carpeta y puso una
// junction en su lugar, el archivo cayó en otro sitio y se rechaza antes de escribir nada (a lo sumo queda ahí un
// archivo vacío y privado). Va con lo que se recibe por red (fileserve, transfer), cuyo nombre elige quien envía.
// shortcut: NtCreateFile con RootDirectory (el handle de la carpeta) cerraría también ese archivo vacío.
func OpenNewPrivateIn(root *os.Root, name string) (*os.File, error) {
	if filepath.Base(name) != name || !filepath.IsLocal(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	f, err := OpenNewPrivate(filepath.Join(root.Name(), name))
	if err != nil {
		return nil, err
	}
	fst, e1 := f.Stat()
	rst, e2 := root.Lstat(name)
	if e1 != nil || e2 != nil || !os.SameFile(fst, rst) {
		f.Close()
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	return f, nil
}

// CreateTempPrivate es os.CreateTemp con OpenNewPrivate: el temporal nace privado.
func CreateTempPrivate(dir, pattern string) (*os.File, error) {
	pre, suf, _ := strings.Cut(pattern, "*")
	for i := 0; i < 10000; i++ {
		f, err := OpenNewPrivate(filepath.Join(dir, pre+strconv.FormatUint(uint64(rand.Uint32()), 10)+suf))
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return f, err
	}
	return nil, &fs.PathError{Op: "createtemp", Path: filepath.Join(dir, pattern), Err: fs.ErrExist}
}

// ProtectFile deja un archivo que ya existe con dueño el usuario y DACL protegida sin herencia (usuario, SYSTEM,
// Administradores). Hoy ninguna ruta de producción la necesita (los archivos nuevos nacen privados con OpenNewPrivate);
// queda para eso y para las pruebas.
func ProtectFile(path string) error { return protect(path, false) }

// ProtectNewStrict deja el archivo recién creado con la DACL protegida sin herencia. Un sistema de archivos sin ACL
// (FAT, exFAT) devuelve un error que cumple errors.Is(err, errors.ErrUnsupported).
func ProtectNewStrict(path string) error { return protect(path, false) }

// ReadOnlyDir deja la DACL de la carpeta con solo lectura y ejecución para el usuario, heredable (OI|CI), y devuelve
// cómo restaurar la DACL privada. Es para pruebas: chmod no cierra una carpeta en Windows. No usa una ACE de «negar»
// (una prueba de pack con ella no negó mkdir en el runner) sino la falta de permiso: sin ACE de escritura nadie escribe,
// ni en la carpeta ni en lo que ya hay dentro, y el dueño conserva WRITE_DAC para restaurarla.
func ReadOnlyDir(path string) (restore func(), err error) {
	user, err := currentSID()
	if err != nil {
		return nil, err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: fileReadExec, AccessMode: windows.GRANT_ACCESS, Inheritance: windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeValue: windows.TrusteeValueFromSID(user)},
	}}, nil)
	if err != nil {
		return nil, err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return nil, err
	}
	return func() { protect(path, true) }, nil
}

// IsPrivate dice si el archivo o la carpeta es del usuario, tiene la DACL protegida y solo da acceso al usuario, a
// SYSTEM y a Administradores. Es para pruebas.
func IsPrivate(path string) (bool, error) {
	user, err := currentSID()
	if err != nil {
		return false, err
	}
	owner, protected, aces, err := readACL(path)
	if err != nil {
		return false, err
	}
	return isPrivateACL(owner, user.String(), protected, aces), nil
}

// OnlyOwnAccess: ver la versión de Linux.
func OnlyOwnAccess(path string) (bool, error) {
	user, err := currentSID()
	if err != nil {
		return false, err
	}
	_, _, aces, err := readACL(path)
	if err != nil {
		return false, err
	}
	return foreignSID(aces, user.String(), anyAccess, false) == "", nil
}

// PrivateDir comprueba una carpeta de salidas ya resuelta (ADR 0012, c): dueño el usuario, ninguna ACE que dé acceso
// a otro SID (cuentan también las solo-herencia: lo que se cree adentro las hereda) y ningún ancestro que deje
// escribir a otro SID. shortcut: el ancestro se juzga por su ACL explícita y heredada tal como la lee el sistema, sin
// mirar la pertenencia a grupos del SID ajeno ni los derechos efectivos (AccessCheck); afinar si hace falta.
func PrivateDir(path string) error {
	user, err := currentSID()
	if err != nil {
		return err
	}
	// Desde Go 1.23 EvalSymlinks no resuelve las junctions y readACL leería la ACL del destino: se rechaza el enlace.
	fi, err := os.Lstat(path)
	if err != nil {
		return &PrivateDirError{Reason: PrivateDirRead, Path: path, Err: err}
	}
	if !fi.IsDir() {
		return &PrivateDirError{Reason: PrivateDirLink, Path: path}
	}
	owner, _, aces, err := readACL(path)
	if err != nil {
		return &PrivateDirError{Reason: PrivateDirRead, Path: path, Err: err}
	}
	if owner != user.String() {
		return &PrivateDirError{Reason: PrivateDirOwner, Path: path, SID: owner, SIDs: []string{owner}}
	}
	if sids := foreignSIDs(aces, user.String(), anyAccess, false); len(sids) > 0 {
		pe := &PrivateDirError{Reason: PrivateDirACL, Path: path, SID: strings.Join(sids, ", "), SIDs: sids}
		if u, err := currentSID(); err == nil {
			pe.User = u.String()
		}
		return pe
	}
	for a := filepath.Dir(path); ; a = filepath.Dir(a) {
		_, _, aces, err := readACL(a)
		if err != nil {
			return &PrivateDirError{Reason: PrivateDirRead, Path: a, Err: err}
		}
		if sids := foreignSIDs(aces, user.String(), writeMask, true, ancestorIgnore...); len(sids) > 0 {
			return &PrivateDirError{Reason: PrivateDirAncestor, Path: a, SID: strings.Join(sids, ", "), SIDs: sids}
		}
		if a == filepath.Dir(a) {
			return nil
		}
	}
}

// FILE_PERSISTENT_ACLS (fileapi.h): el volumen guarda ACL (NTFS, ReFS); FAT y exFAT no.
const filePersistentACLs = 0x8

// ForeignWritersFile dice qué SID, además del usuario, SYSTEM y Administradores, tienen en la DACL derecho de escribir en la
// carpeta abierta f o en lo que se cree dentro, y cuenta al dueño si no es el usuario, SYSTEM ni Administradores (ForeignOwner:
// cambiarlo exige privilegios). User es el SID del usuario (para la orden icacls). Un volumen sin ACL persistentes (FAT, exFAT)
// devuelve errors.ErrUnsupported; en NTFS una DACL nula es Everyone con todo y cuenta. shortcut: no mira la pertenencia a grupos ni
// los derechos efectivos (AccessCheck), igual que PrivateDir.
func ForeignWritersFile(f *os.File) (Writers, error) {
	h := windows.Handle(f.Fd())
	var flags uint32
	if err := windows.GetVolumeInformationByHandle(h, nil, 0, nil, nil, &flags, nil, 0); err != nil {
		return Writers{}, err
	}
	if flags&filePersistentACLs == 0 {
		return Writers{}, errors.ErrUnsupported
	}
	user, err := currentSID()
	if err != nil {
		return Writers{}, err
	}
	owner, _, aces, err := readACLHandle(h)
	if err != nil {
		return Writers{}, err
	}
	w := Writers{Who: foreignWriters(aces, user.String()), User: user.String()}
	if foreignOwner(owner, user.String()) {
		w.ForeignOwner = true
		if !slices.Contains(w.Who, owner) {
			w.Who = append(w.Who, owner)
		}
	}
	return w, nil
}
