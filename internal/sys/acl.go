package sys

// Lógica de ACL sin llamadas al sistema, para probarla en Linux: la lectura y la escritura de la DACL son de Windows
// (private_windows.go) y entregan aquí los SID como texto.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// SID conocidos (ADR 0012, c). El usuario no es fijo: es el SID del token del proceso.
const (
	sidSystem       = "S-1-5-18"
	sidAdmins       = "S-1-5-32-544"
	sidCreatorOwner = "S-1-3-0"
	// NT SERVICE\TrustedInstaller es dueño de C:\Windows y C:\Program Files.
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

// ancestorIgnore son los SID que no cuentan como «otro» en un ancestro de la carpeta de salidas.
var ancestorIgnore = []string{sidCreatorOwner, sidTrustedInstaller}

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

// Banderas de ACE (winnt.h) y tipos de ACE.
const (
	aceOI          = 0x1
	aceCI          = 0x2
	aceInheritOnly = 0x8
)

// ace es una ACE que da acceso en una DACL (las de «negar» no dan acceso y no se miran).
type ace struct {
	sid         string
	mask        uint32
	flags       uint8
	inheritOnly bool // no aplica a la carpeta misma, solo a lo que se cree dentro
}

// aceFromRaw convierte una ACE leída del sistema. Las de «permitir» (0x0) y las de «permitir» condicionales (0x9, la
// condición solo puede restringir, pero no se evalúa) cuentan como permitir; las de «negar» (0x1, 0x6, 0xA, 0xC) no dan
// acceso y se descartan; cualquier otro tipo falla cerrado: cuenta como un SID ajeno con todo el acceso.
func aceFromRaw(typ, flags uint8, mask uint32, sid string) (ace, bool) {
	switch typ {
	case 0x0, 0x9:
		return ace{sid: sid, mask: mask, flags: flags, inheritOnly: flags&aceInheritOnly != 0}, true
	case 0x1, 0x6, 0xA, 0xC:
		return ace{}, false
	}
	return ace{sid: fmt.Sprintf("tipo-ace-%d", typ), mask: anyAccess, flags: flags, inheritOnly: flags&aceInheritOnly != 0}, true
}

// allInherit dice si toda ACE se hereda a archivos y subcarpetas (OI|CI): sin eso lo que se cree dentro no la hereda.
func allInherit(aces []ace) bool {
	for _, a := range aces {
		if a.flags&(aceOI|aceCI) != aceOI|aceCI {
			return false
		}
	}
	return len(aces) > 0
}

// ownerAcceptable: el dueño previo de una carpeta que MkdirPrivate reaplica. Con un token elevado, el dueño por
// omisión de lo que se crea es BUILTIN\Administrators; el usuario lo reclama después (protect lo deja como dueño).
func ownerAcceptable(owner, user string) bool { return owner == user || owner == sidAdmins }

// requireAbs: MkdirPrivate aplica una DACL con propagación; con una ruta vacía o relativa caería en el directorio actual.
func requireAbs(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%q: %w (la ruta debe ser absoluta)", path, fs.ErrInvalid)
	}
	return nil
}

// privateSDDL es el descriptor de seguridad de un archivo privado: dueño el usuario y DACL protegida (sin herencia)
// con acceso total solo para el usuario, SYSTEM y Administradores. Windows lo aplica al crear, sin hueco intermedio.
func privateSDDL(user string) string {
	return "O:" + user + "D:P(A;;FA;;;" + user + ")(A;;FA;;;SY)(A;;FA;;;BA)"
}

// foreignSID devuelve el primer SID que no es el usuario, SYSTEM, Administradores ni uno de ignore y que tiene en
// aces algún derecho de mask. skipInheritOnly salta las ACE que no aplican a la carpeta misma (para ancestros); para
// la carpeta de salidas se cuentan, porque lo que se cree adentro las hereda. Vacío si no hay ninguno.
func foreignSID(aces []ace, user string, mask uint32, skipInheritOnly bool, ignore ...string) string {
	if all := foreignSIDs(aces, user, mask, skipInheritOnly, ignore...); len(all) > 0 {
		return all[0]
	}
	return ""
}

// foreignSIDs es foreignSID con todos los SID ajenos, sin repetir y en orden.
func foreignSIDs(aces []ace, user string, mask uint32, skipInheritOnly bool, ignore ...string) []string {
	var out []string
	for _, a := range aces {
		if a.mask&mask == 0 || (skipInheritOnly && a.inheritOnly) {
			continue
		}
		if a.sid == user || a.sid == sidSystem || a.sid == sidAdmins || slices.Contains(ignore, a.sid) || slices.Contains(out, a.sid) {
			continue
		}
		out = append(out, a.sid)
	}
	return out
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
	PrivateDirLink                                 // es una junction o un enlace, no una carpeta (Windows)
)

// PrivateDirError dice por qué PrivateDir rechazó la carpeta: Path es la carpeta o el ancestro culpable; SID el SID
// ajeno (en Linux, el modo de Path en octal); Err la causa cuando es PrivateDirRead.
type PrivateDirError struct {
	Reason PrivateDirReason
	Path   string
	SID    string   // los SID ajenos separados por coma
	SIDs   []string // los mismos, uno por elemento
	User   string   // el SID del usuario que corre el núcleo (para la orden icacls); vacío si no se pudo leer
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

// ProtectNew deja un archivo YA creado (con O_CREATE y 0600) igual de privado en los dos sistemas: en Linux no hace
// nada, porque ya nació 0600; en Windows nació con la ACL heredada y aquí queda con la DACL protegida. Hay un hueco
// entre crear y proteger: para contenido sensible usa OpenNewPrivate, que nace privado. Como Linux en un vfat, en un sistema de archivos sin ACL (FAT, exFAT) lo deja como está y no
// falla; quien necesite saberlo, como los respaldos de la bóveda, usa ProtectNewStrict.
func ProtectNew(path string) error { return ignoreUnsupported(ProtectNewStrict(path)) }

func ignoreUnsupported(err error) error {
	if errors.Is(err, errors.ErrUnsupported) {
		return nil
	}
	return err
}

// Quién puede escribir la carpeta además de su dueño (carpetas de transferencia de fileserve). En Windows Who son SID y User el SID
// del usuario del proceso; en Linux Who son «g+w» y «o+w» (bits de grupo y otros) y User va vacío.
type Writers struct {
	Who          []string
	User         string
	ForeignOwner bool // el dueño de la carpeta es otro (Who lo incluye): cambiarlo exige privilegios, ninguna orden lo arregla
}

// ForeignWriters abre la carpeta path y dice quién más escribe en ella (ver ForeignWritersFile). Un volumen sin permisos por
// usuario (FAT, exFAT, ntfs-3g sin permissions) devuelve errors.ErrUnsupported.
func ForeignWriters(path string) (Writers, error) {
	f, err := os.Open(path)
	if err != nil {
		return Writers{}, err
	}
	defer f.Close()
	return ForeignWritersFile(f)
}

// ForeignWritersRoot es ForeignWriters sobre una carpeta ya abierta (os.Root): lo que se mira es el handle, no la ruta.
func ForeignWritersRoot(root *os.Root) (Writers, error) {
	f, err := root.Open(".")
	if err != nil {
		return Writers{}, err
	}
	defer f.Close()
	return ForeignWritersFile(f)
}

// foreignOwner: el dueño no es el usuario, SYSTEM ni Administradores (que el dueño sea Administradores es lo normal con un token elevado).
func foreignOwner(owner, user string) bool {
	return owner != user && owner != sidSystem && owner != sidAdmins
}

// foreignWriters: los SID ajenos (no el usuario, SYSTEM ni Administradores) con derecho de escritura sobre la carpeta misma o
// sobre lo que se cree dentro (cuentan las ACE solo-herencia). Pura: se prueba en cualquier sistema.
func foreignWriters(aces []ace, user string) []string {
	return foreignSIDs(aces, user, writeMask, false, ancestorIgnore...)
}

// SafeShellPath son las rutas que se pueden poner en una orden de terminal sin citar: letras (también con acento), números y unos pocos
// signos; nada de espacios, comillas, $ ni caracteres de formato (bidi).
var SafeShellPath = regexp.MustCompile(`^[\p{L}\p{M}\p{N}/._+,@%=:-]+$`)

// SafeCmdPath son las rutas de Windows que van entre comillas en una orden de cmd sin que nada se expanda: sin %, !, ^, $ ni
// comillas invertidas ni caracteres de formato (bidi).
var SafeCmdPath = regexp.MustCompile(`^[\p{L}\p{M}\p{N} :\\/._+,@=()-]+$`)

// SIDRe es la forma de un SID en texto: lo único que puede ir dentro de las comillas de una orden icacls.
var SIDRe = regexp.MustCompile(`^S-1-\d+(-\d+)*$`)

// IcaclsFix arma la orden icacls (para cmd) que quita de path a los SID dados y deja el control solo al usuario, SYSTEM y
// Administradores. Vacía si la ruta no es segura de pegar en cmd, si el usuario o algún SID no tiene forma de SID, o si no hay nada que quitar.
func IcaclsFix(path, user string, sids []string) string {
	if !SafeCmdPath.MatchString(path) || !SIDRe.MatchString(user) || len(sids) == 0 {
		return ""
	}
	var rm []string
	for _, sid := range sids {
		if !SIDRe.MatchString(sid) {
			return ""
		}
		rm = append(rm, `/remove "*`+sid+`"`)
	}
	return `icacls "` + path + `" /inheritance:r ` + strings.Join(rm, " ") + ` /grant:r "*` + user + `:(OI)(CI)F" "*` + sidSystem + `:(OI)(CI)F" "*` + sidAdmins + `:(OI)(CI)F"`
}

// ChmodFix arma «chmod go-w <ruta>» (o solo g-w u o-w); vacía si la ruta no es segura de pegar en una terminal.
func ChmodFix(path string, who []string) string {
	var bits []string
	for _, w := range who {
		switch w {
		case "g+w":
			bits = append(bits, "g-w")
		case "o+w":
			bits = append(bits, "o-w")
		}
	}
	if !SafeShellPath.MatchString(path) || len(bits) == 0 {
		return ""
	}
	return "chmod " + strings.Join(bits, ",") + " " + path
}
