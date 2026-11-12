package compliance

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/iosconf"
)

type rule struct {
	id, title, ref string
	check          func(cfg *iosconf.Node) (Status, string, []*iosconf.Node)
}

const guide = "Cisco Guide to Harden Cisco IOS XE Devices"

// Sin validar en laboratorio: escritas sobre la guía pública y la referencia de comandos.
var rules = []rule{
	{"aaa-new-model", "AAA habilitado (aaa new-model)", guide + " — Management Plane: AAA", func(c *iosconf.Node) (Status, string, []*iosconf.Node) {
		return need(c, `aaa new-model`, "sin aaa new-model: la autenticación depende de contraseñas de línea")
	}},
	{"ssh-v2", "Solo SSH versión 2", guide + " — Management Plane: SSH", func(c *iosconf.Node) (Status, string, []*iosconf.Node) {
		return need(c, `ip ssh version 2`, "falta ip ssh version 2; decláralo para no aceptar SSHv1")
	}},
	{"vty-transport", "VTY solo por SSH (sin telnet)", guide + " — Management Plane: Restricting Interactive Access", vtyTransport},
	{"http-server", "Sin HTTP en claro; HTTPS solo con autenticación", guide + " — Management Plane: HTTP", httpServer},
	{"ntp-auth", "NTP autenticado", guide + " — Management Plane: Network Time Protocol", ntpAuth},
	{"logging-host", "Logging a un servidor remoto", guide + " — Management Plane: Logging", func(c *iosconf.Node) (Status, string, []*iosconf.Node) {
		return need(c, `logging (host \S+.*|\d+\.\d+\.\d+\.\d+.*)`, "sin logging host: los eventos solo quedan en el equipo")
	}},
	{"password-encryption", "service password-encryption", guide + " — Password Management", func(c *iosconf.Node) (Status, string, []*iosconf.Node) {
		return need(c, `service password-encryption`, "sin service password-encryption: las contraseñas tipo 0 se ven en claro")
	}},
	{"secret-types", "Secretos tipo 8/9 en vez de contraseñas reversibles", guide + " — Password Management: enable secret / username secret", secretTypes},
	{"banner", "Banner de acceso legal", guide + " — Management Plane: Warning Banners", func(c *iosconf.Node) (Status, string, []*iosconf.Node) {
		return need(c, `banner (login|motd) .*`, "sin banner login ni motd")
	}},
	{"exec-timeout", "exec-timeout en consola y VTY", guide + " — Management Plane: Session Timeouts", execTimeout},
	{"copp", "Control Plane Policing presente", guide + " — Control Plane: CoPP", copp},
	{"snmp-community", "SNMP sin comunidades por defecto ni v1/v2c sin ACL", guide + " — Management Plane: SNMP", snmpCommunity},
	{"source-route", "no ip source-route", guide + " — Data Plane: IP Source Routing", func(c *iosconf.Node) (Status, string, []*iosconf.Node) {
		return need(c, `no ip source-route`, "falta no ip source-route; el enrutamiento por origen viene habilitado por defecto")
	}},
	{"tcp-keepalives", "service tcp-keepalives-in", guide + " — Management Plane: TCP Keepalives", func(c *iosconf.Node) (Status, string, []*iosconf.Node) {
		if c.Has(`service tcp-keepalives-in`) {
			return Pass, "", nil
		}
		return Warn, "sin service tcp-keepalives-in: sesiones VTY huérfanas quedan abiertas", nil
	}},
}

// Hardening evalúa todas las reglas incluidas, en orden.
func Hardening(cfg *iosconf.Node) []Finding {
	out := make([]Finding, 0, len(rules))
	for _, r := range rules {
		st, detail, ns := r.check(cfg)
		out = append(out, Finding{Rule: r.id, Title: r.title, Status: st, Detail: detail, Lines: lineNums(ns), Reference: r.ref})
	}
	return out
}

func need(c *iosconf.Node, pattern, why string) (Status, string, []*iosconf.Node) {
	if c.Has(pattern) {
		return Pass, "", nil
	}
	return Fail, why, nil
}

func vtyTransport(c *iosconf.Node) (Status, string, []*iosconf.Node) {
	vtys := c.Find(`line vty .*`)
	if len(vtys) == 0 {
		return Warn, "no hay líneas VTY en la configuración", nil
	}
	var bad []string
	var ns []*iosconf.Node
	for _, v := range vtys {
		ti := v.Find(`transport input .*`)
		switch {
		case len(ti) == 0:
			bad = append(bad, v.Line+": sin transport input (el valor por defecto depende de la versión; decláralo)")
			ns = append(ns, v)
		case ti[0].Line != "transport input ssh" && ti[0].Line != "transport input none":
			bad = append(bad, v.Line+": "+ti[0].Line)
			ns = append(ns, ti[0])
		}
	}
	if len(bad) > 0 {
		return Fail, strings.Join(bad, "; "), ns
	}
	return Pass, "", nil
}

func httpServer(c *iosconf.Node) (Status, string, []*iosconf.Node) {
	if ns := c.Find(`ip http server`); len(ns) > 0 {
		return Fail, "ip http server habilitado: la gestión web viaja en claro", ns
	}
	if ns := c.Find(`ip http secure-server`); len(ns) > 0 && !c.Has(`ip http authentication (local|aaa)( .*)?`) {
		return Fail, "ip http secure-server sin ip http authentication local|aaa", ns
	}
	return Pass, "", nil
}

func ntpAuth(c *iosconf.Node) (Status, string, []*iosconf.Node) {
	servers := c.Find(`ntp server .*`)
	if len(servers) == 0 {
		return Fail, "sin ntp server: los registros no tendrán hora confiable", nil
	}
	var miss []string
	for _, p := range []string{`ntp authenticate`, `ntp authentication-key \d+ .*`, `ntp trusted-key \d+.*`} {
		if !c.Has(p) {
			miss = append(miss, strings.Fields(p)[0]+" "+strings.Fields(p)[1])
		}
	}
	var nokey []*iosconf.Node
	for _, s := range servers {
		if !strings.Contains(" "+s.Line+" ", " key ") {
			nokey = append(nokey, s)
		}
	}
	if len(nokey) > 0 {
		miss = append(miss, "servidores sin key ("+lineList(nokey)+")")
	}
	if len(miss) > 0 {
		return Fail, "falta: " + strings.Join(miss, ", "), nokey
	}
	return Pass, "", nil
}

var (
	reversible = regexp.MustCompile(`^(enable password .*|username \S+ .*\bpassword .*)$`)
	md5Secret  = regexp.MustCompile(`^(enable|username \S+ .*) secret [45] .*$`)
	linePass   = regexp.MustCompile(`^password( [07])? .*$`)
)

func secretTypes(c *iosconf.Node) (Status, string, []*iosconf.Node) {
	var fails, warns []*iosconf.Node
	c.Walk(func(n *iosconf.Node) {
		switch {
		case n.Parent.Parent == nil && reversible.MatchString(n.Line):
			fails = append(fails, n)
		case n.Parent.Parent == nil && md5Secret.MatchString(n.Line):
			warns = append(warns, n)
		case n.Parent.Parent != nil && strings.HasPrefix(n.Parent.Line, "line ") && linePass.MatchString(n.Line):
			warns = append(warns, n)
		}
	})
	all := append(append([]*iosconf.Node{}, fails...), warns...)
	switch {
	case len(fails) > 0:
		d := "contraseñas reversibles (usa secret tipo 8 o 9): " + lineList(fails)
		if len(warns) > 0 {
			d += "; además: " + lineList(warns)
		}
		return Fail, d, all
	case len(warns) > 0:
		return Warn, "secretos tipo 4 (SHA-256 sin sal) o 5 (MD5) o contraseñas de línea: " + lineList(warns), all
	}
	return Pass, "", nil
}

func execTimeout(c *iosconf.Node) (Status, string, []*iosconf.Node) {
	var fails, warns []string
	var ns []*iosconf.Node
	for _, l := range c.Find(`line (con 0|vty .*)`) {
		et := l.Find(`exec-timeout .*`)
		switch {
		case len(et) == 0:
			warns = append(warns, l.Line+": sin exec-timeout (10 min por defecto)")
		case et[0].Line == "exec-timeout 0" || et[0].Line == "exec-timeout 0 0":
			fails = append(fails, l.Line+": "+et[0].Line+" (sin límite)")
			ns = append(ns, et[0])
		}
	}
	switch {
	case len(fails) > 0:
		return Fail, strings.Join(append(fails, warns...), "; "), ns
	case len(warns) > 0:
		return Warn, strings.Join(warns, "; "), nil
	}
	return Pass, "", nil
}

func copp(c *iosconf.Node) (Status, string, []*iosconf.Node) {
	for _, cp := range c.Find(`control-plane( host)?`) {
		if cp.Has(`service-policy input .*`) {
			return Pass, "", nil
		}
	}
	return Fail, "sin service-policy input bajo control-plane (en Catalyst 9000 es system-cpp-policy)", nil
}

// snmpCommunity: snmp-server community NOMBRE [view V] [RO|RW] [ipv6 ACL6] [ACL].
func snmpCommunity(c *iosconf.Node) (Status, string, []*iosconf.Node) {
	var fails, warns []string
	var ns []*iosconf.Node
	for _, n := range c.Find(`snmp-server community .*`) {
		f := strings.Fields(n.Line)
		name, acl := f[2], ""
		for i := 3; i < len(f); i++ {
			switch strings.ToLower(f[i]) {
			case "view", "ipv6":
				i++
			case "ro", "rw":
			default:
				acl = f[i]
			}
		}
		switch {
		case strings.EqualFold(name, "public") || strings.EqualFold(name, "private"):
			fails = append(fails, fmt.Sprintf("línea %d: comunidad por defecto %q", n.Num, name))
			ns = append(ns, n)
		case acl == "":
			fails = append(fails, fmt.Sprintf("línea %d: comunidad v1/v2c sin ACL", n.Num))
			ns = append(ns, n)
		default:
			warns = append(warns, fmt.Sprintf("línea %d: v1/v2c con ACL %s; la comunidad viaja en claro, prefiere SNMPv3 priv", n.Num, acl))
		}
	}
	switch {
	case len(fails) > 0:
		return Fail, strings.Join(append(fails, warns...), "; "), ns
	case len(warns) > 0:
		return Warn, strings.Join(warns, "; "), nil
	}
	return Pass, "", nil
}
