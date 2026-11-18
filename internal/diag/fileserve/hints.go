package fileserve

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// hostKeyKinds es el tipo de cada huella de Ready.Fingerprints, en el orden fijo de hostSigners.
var hostKeyKinds = []string{"ed25519", "RSA"}

// ServerHint explica qué teclear en el equipo para usar el servidor y, si no escucha en el puerto
// estándar, cómo llegar a él con una redirección (la app nunca ejecuta esos comandos). names son los
// archivos que se pueden leer. Sintaxis de IOS 15.x sin validar en laboratorio.
func ServerHint(c Config, r Ready, names []string) string { return ServerHintIn(i18n.Es, c, r, names) }

// ServerHintIn es ServerHint con el texto en el idioma dado; los comandos no cambian.
func ServerHintIn(loc string, c Config, r Ready, names []string) string {
	h, _ := ServerHintWarnings(loc, c, r, names)
	return h
}

// ServerHintWarnings es ServerHintIn y, aparte, los avisos de carpeta que lleva: una sola lectura de permisos, así la
// ayuda y los avisos estructurados no pueden decir cosas distintas.
func ServerHintWarnings(loc string, c Config, r Ready, names []string) (string, []DirWarning) {
	ws := dirWarnings(loc, c)
	t := func(code string, kv ...any) string { return i18n.Msg(loc, code, i18n.A(kv...)) }
	host, port, _ := net.SplitHostPort(r.Addr)
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsUnspecified() {
		host = t("fileserve.hint.this_host")
	}
	h := host
	if strings.Contains(h, ":") {
		h = "[" + h + "]" // IPv6 en una URL
	}
	var b strings.Builder
	line := func(f string, a ...any) { fmt.Fprintf(&b, "  "+f+"\n", a...) }
	for _, w := range ws {
		line("%s", w.hint) // avisos de las carpetas publicada y de recepción (escritores ajenos, volumen sin permisos)
	}
	b.WriteString(t("fileserve.hint.head") + "\n")
	// IOS no decodifica %20: un nombre con espacios no tiene copy utilizable, se avisa que se renombre.
	each := func(f func(n string)) {
		for _, n := range names {
			if strings.ContainsRune(n, ' ') {
				line("%s", t("fileserve.hint.name_spaces", "name", n, "proto", strings.ToUpper(c.Proto)))
				continue
			}
			f(n)
		}
	}
	switch c.Proto {
	case "tftp":
		each(func(n string) {
			line("copy tftp://%s/%s flash:", h, n)
		})
		if c.Write {
			line("copy running-config tftp://%s/r1-config.txt", h)
			line("copy flash:crashinfo_20260101-000000 tftp://%s/crashinfo", h)
			line("%s", t("fileserve.hint.warn_udp"))
		}
	case "ftp":
		line("%s", t("fileserve.hint.warn_ftp"))
		line("conf t / ip ftp username %s / ip ftp password %s / ip ftp passive / end", r.User, r.Pass)
		line("%s", t("fileserve.hint.ftp_passive"))
		each(func(n string) {
			line("copy ftp://%s/%s flash:", h, n)
		})
		if c.Write {
			line("copy running-config ftp://%s/r1-config.txt", h)
		}
		line("%s", t("fileserve.hint.ftp_cleanup"))
	case "scp", "sftp":
		each(func(n string) {
			line("copy %s://%s@%s/%s flash:   %s", c.Proto, r.User, h, n, t("fileserve.hint.password", "pass", r.Pass))
		})
		if c.Write {
			line("copy running-config %s://%s@%s/r1-config.txt   %s", c.Proto, r.User, h, t("fileserve.hint.password", "pass", r.Pass))
		}
		for i, fp := range r.Fingerprints {
			line("%s", t("fileserve.hint.fingerprint", "n", i+1, "fp", fp, "kind", hostKeyKinds[min(i, len(hostKeyKinds)-1)]))
		}
		if c.Proto == "sftp" {
			line("%s", t("fileserve.hint.sftp_note"))
		}
	case "http":
		each(func(n string) {
			line("copy http://%s:%s/%s flash:", h, port, n)
		})
	}
	if s, ok := standard[c.Proto]; ok {
		p, _ := strconv.Atoi(port)
		if isWindows() && esLoopback(host) {
			// loopback no pasa por el firewall: ni prosa ni regla
		} else if isWindows() {
			code := "fileserve.hint.win_std_port"
			if p == s.port {
				code = "fileserve.hint.win_std_port_ok"
			}
			b.WriteString(t(code, "std", s.port, "proto", c.Proto, "port", p) + "\n")
			if rule := firewallRule(loc, c.Proto, host, p, exePath(), c.PassivePorts); rule != "" {
				b.WriteString("  " + t("fileserve.hint.win_redirect", "cmd", rule) + "\n")
			}
		} else if p == s.port {
			b.WriteString(t("fileserve.hint.std_port_ok", "std", s.port, "proto", c.Proto) + "\n")
		} else { // puerto propio: la redirección es la alternativa a abrir el estándar
			b.WriteString(t("fileserve.hint.std_port", "std", s.port, "proto", c.Proto, "port", p) + "\n")
			b.WriteString("  " + t("fileserve.hint.redirect", "cmd", RedirectHintIn(loc, c.Proto, host, p)) + "\n")
		}
	}
	return b.String(), ws
}
