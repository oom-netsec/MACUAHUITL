package sys

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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

// isPrivileged es variable para probar la rama elevada, que en Linux sería root.
var isPrivileged = Privileged

// WriteStartup deja en dir/macuahuitld.startup la causa err de un arranque fallido, sobrescribiendo la anterior. Mejor
// esfuerzo: un fallo se ignora. Un proceso elevado (sys.Privileged) NO escribe nada, igual que LogFailure: dir sale de una
// variable de entorno que controla el usuario y validar la ruta y luego abrirla por ruta deja una carrera (una junction
// puesta en medio redirigiría la escritura elevada). Sin elevar crea dir con MkdirPrivate si falta. Si el archivo ya existe
// y no es regular (un enlace) no se toca; si lo es, se borra y se crea de nuevo con OpenNewPrivate, sin seguir enlaces.
func WriteStartup(dir string, cause error) {
	if isPrivileged() || MkdirPrivate(dir) != nil {
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
