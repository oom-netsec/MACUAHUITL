package cli

import (
	"strconv"
	"strings"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// AcceptKeys reparte los valores de --accept: «EQUIPO=HUELLA» o «EQUIPO:PUERTO=HUELLA» van al campo nuevo
// (atados a ese equipo). Una huella sola se ata al único destino si hay uno; con varios es error de uso
// (hay que decir de quién es cada huella). Con targets vacío (el núcleo resuelve los destinos, p. ej. job arm)
// la huella sola viaja en el campo anterior y es el núcleo quien decide.
func AcceptKeys(items, targets []string) (fps []string, keys []*v1.AcceptedHostKey, err error) {
	for _, it := range items {
		host, fp, paired := strings.Cut(it, "=")
		if !paired {
			host, fp = "", it
		}
		host, fp = strings.TrimSpace(host), strings.TrimSpace(fp)
		switch {
		case fp == "" || (paired && host == ""):
			return nil, nil, Err("mctl.accept.form", "value", it)
		case paired:
			keys = append(keys, &v1.AcceptedHostKey{Host: host, Fingerprint: fp})
		case len(targets) == 1:
			keys = append(keys, &v1.AcceptedHostKey{Host: targets[0], Fingerprint: fp})
		case len(targets) > 1:
			return nil, nil, Err("mctl.accept.need_host", "fp", fp)
		default:
			fps = append(fps, fp)
		}
	}
	return fps, keys, nil
}

// HostPort es «host» o «host:puerto» para AcceptKeys (puerto 0 = el de omisión).
func HostPort(host string, port uint32) string {
	if port == 0 {
		return host
	}
	if strings.Contains(host, ":") { // IPv6
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(int(port))
}
