package sys

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// StartupName es el archivo con la causa del último arranque fallido del núcleo, dentro de State (ADR 0012 g). Lo lee la UI.
const StartupName = "macuahuitld.startup"

type startupDoc struct {
	At   string            `json:"at"`
	Code string            `json:"code"`
	Args map[string]string `json:"args"`
	Text string            `json:"text"`
}

// StartupJSON arma la línea del archivo: la hora (UTC), el código y los argumentos del i18n.Error si err lo es (vacíos si
// no) y el texto en inglés, que va siempre.
func StartupJSON(at time.Time, err error) []byte {
	d := startupDoc{At: at.UTC().Format(time.RFC3339), Args: map[string]string{}, Text: i18n.In(i18n.En, err)}
	var ie *i18n.Error
	if errors.As(err, &ie) {
		d.Code = ie.Code
		for k, v := range ie.Args {
			d.Args[k] = v
		}
	}
	b, _ := json.Marshal(d) // solo cadenas: no falla
	return append(b, '\n')
}

// startupDirOK decide si un proceso elevado puede escribir en State: ya existe como carpeta de verdad (el Lstat no la
// ve como enlace ni junction) y su dueño es exactamente el usuario (no Administradores): State cuelga de una variable de
// entorno que controla el usuario, y un proceso elevado que escribiera donde él diga le daría un medio de escribir como
// administrador. Los datos van inyectados para probarlo sin Windows.
func startupDirOK(fi fs.FileInfo, owner, user string) bool {
	return fi != nil && fi.Mode().IsDir() && fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) == 0 &&
		owner != "" && strings.EqualFold(owner, user)
}

// WriteStartup deja en dir/macuahuitld.startup la causa err de un arranque fallido, sobrescribiendo la anterior. Mejor
// esfuerzo: un fallo se ignora. Sin elevar crea dir con MkdirPrivate si falta; elevado (sys.Privileged) NO crea nada ni le
// cambia la ACL, y solo escribe si startupDirOK. En los dos casos, si el archivo ya existe y no es regular (un enlace) no
// se toca, y se crea nuevo con OpenNewPrivate después de borrar el anterior, sin seguir enlaces.
func WriteStartup(dir string, err error) { writeStartup(dir, err, Privileged()) }

func writeStartup(dir string, cause error, elevated bool) {
	if elevated {
		fi, err := os.Lstat(dir)
		if err != nil {
			return
		}
		owner, user, err := startupOwners(dir, fi)
		if err != nil || !startupDirOK(fi, owner, user) {
			return
		}
	} else if MkdirPrivate(dir) != nil {
		return
	}
	path := filepath.Join(dir, StartupName)
	if fi, err := os.Lstat(path); err == nil {
		if !fi.Mode().IsRegular() || os.Remove(path) != nil {
			return
		}
	}
	f, err := OpenNewPrivate(path)
	if err != nil {
		return
	}
	f.Write(StartupJSON(time.Now(), cause))
	f.Close()
}

// ClearStartup borra la causa de un arranque fallido cuando el núcleo ya abrió el canal. Si no es un archivo regular
// no la toca.
func ClearStartup(dir string) {
	path := filepath.Join(dir, StartupName)
	if fi, err := os.Lstat(path); err == nil && fi.Mode().IsRegular() {
		os.Remove(path)
	}
}
