package sys

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// nonBlock no existe en Windows: no hay FIFO que bloquee al abrir.
const nonBlock = 0

// Mkfifo no existe en Windows; las pruebas que la usan se saltan con errors.ErrUnsupported.
func Mkfifo(string) error { return errors.ErrUnsupported }

// HardLinked siempre es false en Windows: un os.FileInfo no trae la cuenta de enlaces. Es solo un filtro de listado;
// lo que decide es HardLinkedFile sobre el handle ya abierto, que es el que se sirve.
func HardLinked(os.FileInfo) bool { return false }

// HardLinkedFile dice si el archivo abierto tiene más de un nombre (NumberOfLinks > 1 en GetFileInformationByHandle).
// Si no se puede saber, devuelve el error y quien llama rechaza.
func HardLinkedFile(f *os.File) (bool, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return false, err
	}
	var info windows.ByHandleFileInformation
	var ierr error
	if err := rc.Control(func(fd uintptr) { ierr = windows.GetFileInformationByHandle(windows.Handle(fd), &info) }); err != nil {
		return false, err
	}
	return info.NumberOfLinks > 1, ierr
}

// checkPath rechaza antes de abrir las rutas UNC y de dispositivo: \\host\share abre SMB (salida a la red fuera de
// EgressGuard y hash NTLM filtrado) y \\.\pipe\x o \\.\COM1 se abren antes de que Stat los rechace.
func checkPath(path string) error {
	// Un nombre reservado (NUL, COM1, CON…) abre el dispositivo aunque vaya en una carpeta: IsLocal los marca.
	if unsafeVolume(filepath.VolumeName(path)) || !filepath.IsLocal(filepath.Base(path)) {
		return fmt.Errorf("%s: %w", path, fs.ErrInvalid)
	}
	return nil
}

// Owner falla cerrado en Windows: (0, false). La verificación del dueño por SID va en 43a3.
func Owner(os.FileInfo) (uid uint32, ok bool) { return 0, false }

// ONoFollow es 0 en Windows. Basta con O_EXCL: Go abre con CREATE_NEW y FILE_FLAG_OPEN_REPARSE_POINT
// (syscall.Open), y CREATE_NEW falla si la ruta existe, aunque sea un enlace simbólico o una junction.
const ONoFollow = 0

// RenameNoReplaceIn renombra old a new dentro de root sin sobrescribir: MoveFileEx sin MOVEFILE_REPLACE_EXISTING falla
// si new existe (fs.ErrExist). shortcut: arma rutas absolutas con root.Name() en vez de operar sobre el handle de la
// carpeta, así cambiar la carpeta por un enlace entre la apertura y el renombrado podría desviarlo; pasar a
// NtSetInformationFile (FILE_RENAME_INFO con RootDirectory) si hace falta cerrarlo.
func RenameNoReplaceIn(root *os.Root, old, new string) error {
	// Base(n) != n: «sub\x», con sub una junction, saldría de la carpeta.
	if filepath.Base(old) != old || filepath.Base(new) != new || !filepath.IsLocal(old) || !filepath.IsLocal(new) {
		return fmt.Errorf("rename %s %s: %w", old, new, fs.ErrInvalid)
	}
	from, err := windows.UTF16PtrFromString(filepath.Join(root.Name(), old))
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(filepath.Join(root.Name(), new))
	if err != nil {
		return err
	}
	err = windows.MoveFileEx(from, to, 0)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
		return fmt.Errorf("rename %s %s: %w", old, new, fs.ErrExist)
	}
	return err
}

// ErrNoAtomicRename es el error de un sistema de archivos que no sabe renombrar sin sobrescribir (para simularlo en
// pruebas). MoveFileEx sin REPLACE_EXISTING comprueba la existencia dentro del sistema de archivos, así que casi
// nunca ocurre; ERROR_NOT_SUPPORTED es lo que darían los raros que no lo soporten.
var ErrNoAtomicRename error = windows.ERROR_NOT_SUPPORTED

// NoAtomicRename dice si err es que el sistema de archivos no sabe renombrar sin sobrescribir.
func NoAtomicRename(err error) bool {
	return errors.Is(err, windows.ERROR_NOT_SUPPORTED) || errors.Is(err, windows.ERROR_INVALID_FUNCTION)
}
