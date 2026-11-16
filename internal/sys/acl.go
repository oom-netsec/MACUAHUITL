package sys

// Lógica de ACL sin llamadas al sistema, para probarla en Linux: la lectura y la escritura de la DACL son de Windows
// (private_windows.go) y entregan aquí los SID como texto.

import (
	"errors"
	"slices"
)

// SID conocidos (ADR 0012, c). El usuario no es fijo: es el SID del token del proceso.
const (
	sidSystem       = "S-1-5-18"
	sidAdmins       = "S-1-5-32-544"
	sidCreatorOwner = "S-1-3-0"
	// NT SERVICE\TrustedInstaller es dueño de C:\Windows y C:\Program Files.
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

// Derechos de archivo y carpeta (winnt.h).
const (
	fileAddFile     = 0x2
	fileAddSubdir   = 0x4
	fileDeleteChild = 0x40
	deleteRight     = 0x10000
	writeDAC        = 0x40000
	writeOwner      = 0x80000
	genericAll      = 0x10000000
	genericWrite    = 0x40000000
	fileAllAccess   = 0x1F01FF
	anyAccess       = ^uint32(0)
	// writeMask: lo que deja a otro SID reemplazar un hijo de una carpeta o cambiar quién manda en ella. Agregar solo
	// subcarpetas (fileAddSubdir) no cuenta: es lo que Autenticados tiene en la raíz de C:\ y no reemplaza nada.
	writeMask = fileAddFile | fileDeleteChild | deleteRight | writeDAC | writeOwner | genericAll | genericWrite
)

// ace es una ACE de «permitir» de una DACL (las de «negar» no dan acceso y no se miran).
type ace struct {
	sid         string
	mask        uint32
	inheritOnly bool // no aplica a la carpeta misma, solo a lo que se cree dentro
}

// foreignSID devuelve el primer SID que no es el usuario, SYSTEM, Administradores ni uno de ignore y que tiene en
// aces algún derecho de mask. skipInheritOnly salta las ACE que no aplican a la carpeta misma (para ancestros); para
// la carpeta de salidas se cuentan, porque lo que se cree adentro las hereda. Vacío si no hay ninguno.
func foreignSID(aces []ace, user string, mask uint32, skipInheritOnly bool, ignore ...string) string {
	for _, a := range aces {
		if a.mask&mask == 0 || (skipInheritOnly && a.inheritOnly) {
			continue
		}
		if a.sid == user || a.sid == sidSystem || a.sid == sidAdmins || slices.Contains(ignore, a.sid) {
			continue
		}
		return a.sid
	}
	return ""
}

// isPrivateACL: dueño el usuario, DACL protegida (sin herencia del padre) y ningún SID ajeno con acceso.
func isPrivateACL(owner, user string, protected bool, aces []ace) bool {
	return owner == user && protected && foreignSID(aces, user, anyAccess, false) == ""
}

// Motivos de PrivateDirError.
type PrivateDirReason int

const (
	PrivateDirOwner    PrivateDirReason = iota + 1 // el dueño no es el usuario
	PrivateDirACL                                  // otro SID (o, en Linux, el modo) da acceso a la carpeta
	PrivateDirAncestor                             // un ancestro deja escribir a otro SID
	PrivateDirRead                                 // no se pudo leer la protección
)

// PrivateDirError dice por qué PrivateDir rechazó la carpeta: Path es la carpeta o el ancestro culpable; SID el SID
// ajeno (en Linux, el modo de Path en octal); Err la causa cuando es PrivateDirRead.
type PrivateDirError struct {
	Reason PrivateDirReason
	Path   string
	SID    string
	Err    error
}

func (e *PrivateDirError) Error() string {
	s := "sys: carpeta no privada: " + e.Path + " " + e.SID
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *PrivateDirError) Unwrap() error { return e.Err }

// ProtectNew deja un archivo recién creado (con O_CREATE y 0600) igual de privado en los dos sistemas: en Linux no hace
// nada, porque ya nació 0600; en Windows nació con la ACL heredada y aquí queda con la DACL protegida (llámala antes de
// escribir el secreto). Como Linux en un vfat, en un sistema de archivos sin ACL (FAT, exFAT) lo deja como está y no
// falla; quien necesite saberlo, como los respaldos de la bóveda, usa ProtectNewStrict.
func ProtectNew(path string) error { return ignoreUnsupported(ProtectNewStrict(path)) }

func ignoreUnsupported(err error) error {
	if errors.Is(err, errors.ErrUnsupported) {
		return nil
	}
	return err
}
