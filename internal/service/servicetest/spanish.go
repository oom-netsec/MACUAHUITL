package servicetest

import (
	"regexp"
	"strings"
)

var (
	quoted   = regexp.MustCompile(`"(\\.|[^"\\])*"`)
	accents  = regexp.MustCompile(`[áéíóúñÁÉÍÓÚÑ]`)
	wordsRe  = regexp.MustCompile(`[\p{L}_]+`)
	spanishW = map[string]bool{}
)

func init() {
	for _, w := range strings.Fields(`de pasaron razon carpeta equipo equipos trabajo destino archivo archivos credencial
		puerto puertos usuario secreto ronda rondas borrados conservar hechos fallidos pendientes entradas truncado metodo
		nuevos nuevas reemplazados reemplazadas renombrados renombradas omitidos omitidas decisiones sesion recibidos enviados
		transferencias rechazos servidor escribir origenes topes revocado marcado desmarcado fijado desfijado incluida llave
		dias algoritmo perfil serie formato hallazgos muestras mensajes patrones lineas ocultas anomalias resultados fase nombre
		imagen comandos fallas revisar plantilla salida todas alrededor ventana eventos canales filas tipo modo bloqueada
		inactividad pantalla bloqueada cerrada pausa ingeniero pedido pedida`) {
		spanishW[w] = true
	}
}

// SpanishWords lista las palabras en español del detalle de una auditoría (la auditoría va siempre en inglés).
// Los valores entre comillas son datos (rutas, nombres, ids) y no cuentan.
func SpanishWords(detail string) []string {
	d := quoted.ReplaceAllString(detail, "")
	var out []string
	for _, w := range wordsRe.FindAllString(strings.ToLower(d), -1) {
		if spanishW[w] || accents.MatchString(w) {
			out = append(out, w)
		}
	}
	return out
}
