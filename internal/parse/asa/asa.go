// Package asa convierte salidas de Cisco ASA 9.x (formato de la documentación pública de Cisco y
// fixtures reconstruidas; sin validar en laboratorio, "not yet tested in a lab") en tipos de Go.
// No depende de otros paquetes internos ni toca la red.
//
// Convención: cada parser devuelve (resultado, ok). ok=false significa "no reconozco este
// formato": quien llama debe avisar, nunca tomarlo como "sin filas". Las tabulaciones y los
// espacios valen igual (el equipo real sangra con tabulaciones); las líneas desconocidas se
// ignoran en lugar de romper el parseo.
package asa

import (
	"regexp"
	"strconv"
	"strings"
)

// lines normaliza la salida: sin \r, con cada tabulación convertida en dos espacios (separa
// columnas igual que un hueco de espacios) y sin espacios al final de línea.
func lines(s string) []string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r", ""), "\t", "  ")
	ls := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range ls {
		ls[i] = strings.TrimRight(l, " ")
	}
	return ls
}

func atoi(s string) int64 { n, _ := strconv.ParseInt(s, 10, 64); return n }

// cols separa una línea en columnas por huecos de 2 o más espacios.
var colSep = regexp.MustCompile(` {2,}`)

func cols(s string) []string { return colSep.Split(strings.TrimSpace(s), -1) }

// kv parte "clave : valor" en la primera ':'.
func kv(l string) (k, v string, ok bool) {
	k, v, ok = strings.Cut(l, ":")
	return strings.TrimSpace(k), strings.TrimSpace(v), ok && strings.TrimSpace(k) != ""
}
