package fileserve

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ServerHint explica qué teclear en el equipo para usar el servidor, y cómo llegar a los
// puertos estándar sin privilegios (la app nunca ejecuta esos comandos). names son los
// archivos que se pueden leer. Sintaxis de IOS 15.x sin validar en laboratorio.
func ServerHint(c Config, r Ready, names []string) string {
	host, port, _ := net.SplitHostPort(r.Addr)
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsUnspecified() {
		host = "IP-DE-ESTA-MÁQUINA"
	}
	h := host
	if strings.Contains(h, ":") {
		h = "[" + h + "]" // IPv6 en una URL
	}
	var b strings.Builder
	line := func(f string, a ...any) { fmt.Fprintf(&b, "  "+f+"\n", a...) }
	b.WriteString("En el equipo:\n")
	switch c.Proto {
	case "tftp":
		for _, n := range names {
			line("copy tftp://%s/%s flash:", h, n)
		}
		if c.Write {
			line("copy running-config tftp://%s/r1-config.txt", h)
			line("copy flash:crashinfo_20260101-000000 tftp://%s/crashinfo", h)
			line("AVISO: %s", udpAllowNote)
		}
	case "ftp":
		line("AVISO: FTP manda el usuario y la contraseña en claro por la red; úsalo solo en un enlace directo o una red de confianza (SCP o SFTP no lo hacen)")
		line("conf t / ip ftp username %s / ip ftp password %s / ip ftp passive / end", r.User, r.Pass)
		line("(IOS usa FTP activo salvo que le pongas ip ftp passive: este servidor solo habla pasivo)")
		for _, n := range names {
			line("copy ftp://%s/%s flash:", h, n)
		}
		if c.Write {
			line("copy running-config ftp://%s/r1-config.txt", h)
		}
		line("al terminar, borra la credencial del equipo: conf t / no ip ftp password / end")
	case "scp", "sftp":
		for _, n := range names {
			line("copy %s://%s@%s/%s flash:   (contraseña: %s)", c.Proto, r.User, h, n, r.Pass)
		}
		if c.Write {
			line("copy running-config %s://%s@%s/r1-config.txt   (contraseña: %s)", c.Proto, r.User, h, r.Pass)
		}
		for i, fp := range r.Fingerprints {
			line("huella de la llave de host %d (ed25519, RSA): %s", i+1, fp)
		}
		if c.Proto == "sftp" {
			line("(IOS 15.2 puede no traer cliente SFTP; si copy sftp: no existe, usa scp)")
		}
	case "http":
		for _, n := range names {
			line("copy http://%s:%s/%s flash:", h, port, n)
		}
	}
	if s, ok := standard[c.Proto]; ok {
		p, _ := strconv.Atoi(port)
		fmt.Fprintf(&b, "IOS usa el puerto %d de %s y no deja elegir otro; escucho en el %d. Sin privilegios para la app:\n", s.port, c.Proto, p)
		fmt.Fprintf(&b, "  redirección (recomendada): %s\n", RedirectHint(c.Proto, host, p))
		fmt.Fprintf(&b, "  alternativa más amplia, para un servidor propio que sí use el puerto bajo (esta app no): %s\n", SetcapHint("RUTA-DEL-SERVIDOR"))
	}
	return b.String()
}
