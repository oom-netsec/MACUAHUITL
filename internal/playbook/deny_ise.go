package playbook

import (
	"regexp"
	"strings"
)

// Sistemas de archivos locales de ADE-OS (disk:, localdisk:, nfs:…): un show con uno de ellos lee o escribe en el nodo.
var iseDevicePath = regexp.MustCompile(`^(?:disk\d*|localdisk|harddisk|flash|nvram|usb|cdrom|nfs|system|cache|repository):`)

// Opciones numéricas de ping de ADE-OS (CLI Reference 3.1-3.4): pingcount es la palabra documentada; count se
// acepta también por si una versión la usa. Nunca df ni nada fuera de la lista.
var isePingOpts = map[string][2]int{"pingcount": {1, 10}, "count": {1, 10}, "packetsize": {1, 1500}}

// checkISE: CLI ADE-OS de Cisco ISE 3.x (prompt «host/admin#», sin enable). Lista blanca sin abreviaturas:
// «show …», «ping», «traceroute», «nslookup» acotados y «terminal length 0»; un solo filtro de pipe de la lista
// documentada. application, reload, backup, patch, tech, etc. no están en la lista y caen en el rechazo general.
func checkISE(cmd string) error {
	if strings.Contains(cmd, "?") { // ayuda en línea: no es un comando
		return denied(cmd, "playbook.why.show_ise")
	}
	cmdPart, pipe, hasPipe := strings.Cut(strings.ToLower(cmd), "|")
	f := strings.Fields(cmdPart)
	if len(f) == 0 {
		if hasPipe {
			return denied(cmd, "playbook.why.empty_pipe")
		}
		return denied(cmd, "playbook.why.not_read")
	}
	switch f[0] {
	case "show":
		if err := iseShow(cmd, f); err != nil {
			return err
		}
	case "ping":
		if len(f) < 2 || !asaDest(f[1]) || !asaOpts(f[2:], isePingOpts) {
			return denied(cmd, "playbook.why.probe_ise")
		}
	case "traceroute", "nslookup":
		if len(f) != 2 || !asaDest(f[1]) {
			return denied(cmd, "playbook.why.probe_ise")
		}
	case "terminal": // solo lo que el driver manda para desactivar la paginación
		if len(f) != 3 || f[1] != "length" || f[2] != "0" || hasPipe {
			return denied(cmd, "playbook.why.terminal_ise")
		}
	default:
		return denied(cmd, "playbook.why.not_read")
	}
	for _, a := range f[1:] {
		if err := isePath(cmd, a); err != nil {
			return err
		}
	}
	if !hasPipe {
		return nil
	}
	return iseFilter(cmd, strings.Fields(pipe), strings.Contains(pipe, "|"))
}

// isePath: rutas remotas (el nodo se conectaría a otro servidor) o de sistemas de archivos del equipo.
func isePath(cmd, a string) error {
	if remotePath(a) {
		return denied(cmd, "playbook.why.remote")
	}
	if iseDevicePath.MatchString(a) {
		return denied(cmd, "playbook.why.local_path")
	}
	return nil
}

// iseShow: «tail» sigue el archivo para siempre, «file» escribe (show tech-support file X), «show top» es continuo y
// «show repository NOMBRE» hace que el nodo se conecte al repositorio remoto. ADE-OS completa prefijos: de «tail» y
// «file» cuenta cualquiera desde 1 letra; de «top» y «repository», desde 2 y 3 («show t» solo es ambiguo).
func iseShow(cmd string, f []string) error {
	for i, a := range f[1:] {
		if Abbrev(a, "tail") || Abbrev(a, "file") || i == 0 && (len(a) >= 2 && Abbrev(a, "top") || len(a) >= 3 && Abbrev(a, "repository") && len(f) > 2) {
			return denied(cmd, "playbook.why.show_ise")
		}
	}
	return nil
}

// iseFilter: un solo operador de pipe de ADE-OS con sus argumentos; sin segunda «|», sin sumideros ni rutas.
func iseFilter(cmd string, t []string, second bool) error {
	if second || len(t) == 0 {
		return denied(cmd, "playbook.why.pipe_ise")
	}
	op, args := t[0], t[1:]
	ok := false
	switch op {
	case "include", "exclude", "begin", "end":
		ok = len(args) > 0
	case "count":
		ok = len(args) == 0
	case "last": // last [N]
		ok = len(args) == 0
		if len(args) == 1 {
			_, ok = probeNum(args[0], 1, 9999)
		}
	}
	if !ok {
		return denied(cmd, "playbook.why.pipe_ise")
	}
	for _, a := range args {
		if err := isePath(cmd, a); err != nil {
			return err
		}
	}
	return nil
}
