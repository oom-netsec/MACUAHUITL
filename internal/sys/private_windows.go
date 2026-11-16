package sys

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func currentSID() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid, nil
}

// readACL lee dueño, protección y ACE de «permitir» de la DACL. Una DACL nula da acceso total a todos.
func readACL(path string) (owner string, protected bool, aces []ace, err error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", false, nil, err
	}
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
		if a.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue // las de «negar» no dan acceso; los tipos de objeto no se usan en archivos
		}
		sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
		aces = append(aces, ace{sid: sid.String(), mask: uint32(a.Mask), inheritOnly: a.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0})
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
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		user, nil, acl, nil)
	if errors.Is(err, windows.ERROR_NOT_SUPPORTED) || errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
		err = errors.Join(errors.ErrUnsupported, err)
	}
	return err
}

// MkdirPrivate crea la carpeta y los padres que falten (como MkdirAll) y les pone la DACL protegida con herencia
// OI|CI, para que lo que se cree adentro la herede. Si la carpeta ya existe (la UI puede crearla antes que el núcleo,
// con la ACL heredada) y su dueño es el usuario, se le reaplica; si el dueño es otro SID devuelve el error sys.err.not_owner.
func MkdirPrivate(path string) error {
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
	if len(nuevas) == 0 || nuevas[0] != path { // ya existía: solo se reaplica si es del usuario
		if owner, _, _, err := readACL(path); err != nil {
			return err
		} else if owner != user.String() {
			return i18n.New("sys.err.not_owner", i18n.A("path", path))
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

// ProtectFile deja el archivo con dueño el usuario y DACL protegida sin herencia (usuario, SYSTEM, Administradores).
func ProtectFile(path string) error { return protect(path, false) }

// ProtectNew protege un archivo recién creado (ver la versión de Linux). Un sistema de archivos sin ACL (FAT, exFAT)
// devuelve un error que cumple errors.Is(err, errors.ErrUnsupported), para que quien tolere la falta de permisos lo vea.
func ProtectNew(path string) error { return protect(path, false) }

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
	owner, _, aces, err := readACL(path)
	if err != nil {
		return &PrivateDirError{Reason: PrivateDirRead, Path: path, Err: err}
	}
	if owner != user.String() {
		return &PrivateDirError{Reason: PrivateDirOwner, Path: path, SID: owner}
	}
	if sid := foreignSID(aces, user.String(), anyAccess, false); sid != "" {
		return &PrivateDirError{Reason: PrivateDirACL, Path: path, SID: sid}
	}
	for a := filepath.Dir(path); ; a = filepath.Dir(a) {
		_, _, aces, err := readACL(a)
		if err != nil {
			return &PrivateDirError{Reason: PrivateDirRead, Path: a, Err: err}
		}
		if sid := foreignSID(aces, user.String(), writeMask, true, sidCreatorOwner, sidTrustedInstaller); sid != "" {
			return &PrivateDirError{Reason: PrivateDirAncestor, Path: a, SID: sid}
		}
		if a == filepath.Dir(a) {
			return nil
		}
	}
}
