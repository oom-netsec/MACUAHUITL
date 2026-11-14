package cli

import (
	"errors"
	"regexp"
	"strings"
)

// placeholders traduce los marcadores en mayúsculas de las líneas «uso: mctl …» (son sintaxis, no prosa); las
// banderas y los valores técnicos (renombrar|reemplazar|omitir, --asistido) no se tocan.
var placeholders = strings.NewReplacer(
	"uso: mctl", "usage: mctl",
	"campo=valor", "field=value",
	"(mctl snippet list muestra los campos)", "(mctl snippet list shows the fields)",
	"PUERTO-ALTO", "HIGH-PORT", "IP-DE-ESCUCHA", "LISTEN-IP",
	"<archivo.mpack>", "<file.mpack>", "(todas las colecciones, también favoritos)", "(all collections, including favorites)",
)

var placeholderWord = map[string]string{
	"EQUIPO": "DEVICE", "ARCHIVO": "FILE", "PUERTO": "PORT", "CARPETA": "FOLDER", "TRABAJO": "JOB", "RUTA": "PATH",
	"NOMBRE": "NAME", "TEXTO": "TEXT", "HUELLA": "FINGERPRINT", "DIRECCIÓN": "ADDRESS", "DIRECCION": "ADDRESS",
	"VALOR": "VALUE", "SERVIDOR": "SERVER", "SEG": "SEC", "SALIDA": "OUTPUT", "PREFIJO": "PREFIX",
	"MÁSCARA": "MASK", "MASCARA": "MASK", "COMANDO": "COMMAND", "RESPALDO": "BACKUP", "RED": "NETWORK",
	"PATRON": "PATTERN", "MNEMONICO": "MNEMONIC", "LLAVE": "KEY", "EJECUCION": "RUN",
}

var upperWord = regexp.MustCompile(`[A-ZÁÉÍÓÚ][A-ZÁÉÍÓÚ_-]+`)

// LocalizeUsage escribe en inglés los errores «uso: mctl …» cuando mctl va en inglés (por omisión); con --lang es
// quedan como están.
func LocalizeUsage(err error) error {
	if err == nil || locale != "en" || !strings.Contains(err.Error(), "uso: mctl") {
		return err
	}
	s := placeholders.Replace(err.Error())
	s = upperWord.ReplaceAllStringFunc(s, func(w string) string {
		if r, ok := placeholderWord[w]; ok {
			return r
		}
		return w
	})
	return errors.New(s)
}
