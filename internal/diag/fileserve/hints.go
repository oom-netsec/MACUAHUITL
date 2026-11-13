package fileserve

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// ServerHint explica qué teclear en el equipo para usar el servidor, y cómo llegar a los
// puertos estándar sin privilegios (la app nunca ejecuta esos comandos). names son los
// archivos que se pueden leer. Sintaxis de IOS 15.x sin validar en laboratorio.
func ServerHint(c Config, r Ready, names []string) string { return ServerHintIn(i18n.Es, c, r, names) }

// ServerHintIn es ServerHint con el texto en el idioma dado; los comandos no cambian.
func ServerHintIn(loc string, c Config, r Ready, names []string) string {
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
	b.WriteString(t("fileserve.hint.head") + "\n")
	switch c.Proto {
	case "tftp":
		for _, n := range names {
			line("copy tftp://%s/%s flash:", h, n)
		}
		if c.Write {
			line("copy running-config tftp://%s/r1-config.txt", h)
			line("copy flash:crashinfo_20260101-000000 tftp://%s/crashinfo", h)
			line("%s", t("fileserve.hint.warn_udp"))
		}
	case "ftp":
		line("%s", t("fileserve.hint.warn_ftp"))
		line("conf t / ip ftp username %s / ip ftp password %s / ip ftp passive / end", r.User, r.Pass)
		line("%s", t("fileserve.hint.ftp_passive"))
		for _, n := range names {
			line("copy ftp://%s/%s flash:", h, n)
		}
		if c.Write {
			line("copy running-config ftp://%s/r1-config.txt", h)
		}
		line("%s", t("fileserve.hint.ftp_cleanup"))
	case "scp", "sftp":
		for _, n := range names {
			line("copy %s://%s@%s/%s flash:   %s", c.Proto, r.User, h, n, t("fileserve.hint.password", "pass", r.Pass))
		}
		if c.Write {
			line("copy running-config %s://%s@%s/r1-config.txt   %s", c.Proto, r.User, h, t("fileserve.hint.password", "pass", r.Pass))
		}
		for i, fp := range r.Fingerprints {
			line("%s", t("fileserve.hint.fingerprint", "n", i+1, "fp", fp))
		}
		if c.Proto == "sftp" {
			line("%s", t("fileserve.hint.sftp_note"))
		}
	case "http":
		for _, n := range names {
			line("copy http://%s:%s/%s flash:", h, port, n)
		}
	}
	if s, ok := standard[c.Proto]; ok {
		p, _ := strconv.Atoi(port)
		b.WriteString(t("fileserve.hint.std_port", "std", s.port, "proto", c.Proto, "port", p) + "\n")
		b.WriteString("  " + t("fileserve.hint.redirect", "cmd", RedirectHintIn(loc, c.Proto, host, p)) + "\n")
		b.WriteString("  " + t("fileserve.hint.setcap_alt", "cmd", SetcapHintIn(loc, "RUTA-DEL-SERVIDOR")) + "\n")
	}
	return b.String()
}
