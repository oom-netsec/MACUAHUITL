package servicetest

import (
	"regexp"
	"strings"
)

var (
	quoted  = regexp.MustCompile(`"(\\.|[^"\\])*"`)
	tokenRe = regexp.MustCompile(`([\p{L}\p{N}_]+)(=?)`)
	// keys son las claves clave=valor del detalle viejo en español; fixed, textos fijos que tenía el detalle.
	// Los mensajes de error sin código siguen en español (no se traducen), así que no se buscan palabras sueltas
	// como «equipo» o «sesión»: solo el vocabulario propio del detalle.
	keys = set(`pasaron razon equipos equipo carpeta trabajo destino archivos archivo credencial puerto puertos usuario secreto ronda rondas conservar hechos fallidos pendientes entradas truncado metodo sesion recibidos enviados transferencias rechazos servidor escribir origenes topes llave dias algoritmo perfil serie formato hallazgos muestras mensajes patrones lineas líneas ocultas anomalias resultados fase nombre imagen comandos fallas revisar plantilla salida todas alrededor ventana eventos canales filas tipo modo función respaldo duración contraseña descartes flujos errores enmascarado borrados motivo grabacion intervalo rutas perfiles servidores profundo cambios huerfanas orden ssh_antiguo cambiados estado resultado interfaz`)
	// fixed son los textos fijos del detalle viejo, solo en la forma en que aparecían (un número delante,
	// el detalle completo, o la frase): así un nombre de job, script o host con «nuevos» o «ninguna» no cuenta.
	fixed = []*regexp.Regexp{
		regexp.MustCompile(`\d+ (nuevos|nuevas|reemplazados|reemplazadas|renombrados|renombradas|omitidos|omitidas|fusionadas|inválidos|iguales|credenciales|colecciones)\b`),
		regexp.MustCompile(`^(marcado|desmarcado|fijado|desfijado|inactividad|ninguna|usuario)$`),
		regexp.MustCompile(`guard=(revocado|sin autorizar)|decisiones( de colecciones)?:|borrado por exceder|conservada( como)?|sesión nueva abierta|sesión inservible|bóveda cerrada y trabajos|pantalla bloqueada|pedid[oa] por el ingeniero|… y \d+ más`),
	}
)

func set(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

// SpanishWords lista lo que en el detalle de una auditoría es español viejo (la auditoría va siempre en inglés):
// claves clave=valor y textos fijos de antes. Los valores entre comillas son datos y no cuentan.
func SpanishWords(detail string) []string {
	var out []string
	d := strings.ToLower(strings.TrimSpace(quoted.ReplaceAllString(detail, "")))
	for _, re := range fixed {
		out = append(out, re.FindAllString(d, -1)...)
	}
	for _, m := range tokenRe.FindAllStringSubmatch(d, -1) {
		if m[2] == "=" && keys[m[1]] {
			out = append(out, m[1])
		}
	}
	return out
}
