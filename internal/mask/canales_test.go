package mask_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/syslogd"
	"github.com/oom-netsec/MACUAHUITL/internal/mask"
	"github.com/oom-netsec/MACUAHUITL/internal/terminal"
)

// Prueba absoluta de canales: el mismo comando con secreto pasa por todas las vías que lo repiten (tecleado, CFGLOG,
// archive log, accounting, syslog de ASA, historial, diff, texto citado, syslog multilínea y la sesión completa de la
// terminal con eco normal y desplazado). Ningún marcador Zq##### puede verse en ninguna. {1}, {2} y {3} son valores
// distintos (con símbolos); cada plantilla usa los que lleva.
var canalPlantillas = []struct{ plat, tpl string }{
	// IOS / IOS-XE
	{"ios-xe", "enable secret {1}"}, {"ios-xe", "enable secret 5 {1}"}, {"ios-xe", "enable secret 0 {1}"},
	{"ios-xe", "enable password {1}"}, {"ios-xe", "enable password level 15 {1}"}, {"ios-xe", "enable password 7 {1}"},
	{"ios-xe", "ena sec {1}"}, {"ios-xe", "enable algorithm-type scrypt secret {1}"}, {"ios-xe", "enable algorithm-type sha256 secret {1}"},
	{"ios-xe", "username u secret {1}"}, {"ios-xe", "username u secret 0 {1}"}, {"ios-xe", "username u password 7 {1}"},
	{"ios-xe", "username u privilege 15 secret 9 {1}"}, {"ios-xe", "username u pass {1} secret 0 {2}"},
	{"ios-xe", "username u privilege 15 password 0 {1}"}, {"ios-xe", "user u sec {1}"},
	{"ios-xe", "username u algorithm-type scrypt secret {1}"}, {"ios-xe", "username u view V secret 5 {1}"},
	{"ios-xe", "username admin password 0 {1} role network-admin"},
	{"ios-xe", "snmp-server community {1} RO"}, {"ios-xe", "snmp-server community {1} RW"}, {"ios-xe", "snmp-server community {1} RO 10"},
	{"ios-xe", "snmp-server community {1} view V RW 20"}, {"ios-xe", "snmp-s comm {1}"}, {"ios-xe", "snmp-server community {1}"},
	{"ios-xe", "snmp-server host 10.1.1.1 {1}"}, {"ios-xe", "snmp-server host 10.1.1.1 version 2c {1}"},
	{"ios-xe", "snmp-server host 10.1.1.1 vrf MGMT informs version 2c {1}"}, {"ios-xe", "snmp-s ho 10.1.1.1 vrf MGMT {1} udp-port 162"},
	{"ios-xe", "snmp-server user u g v3 auth sha {1} priv aes 128 {2} access 10"}, {"ios-xe", "snmp-server user u g v3 auth md5 {1}"},
	{"ios-xe", "snmp-server user u g v3 auth sha {1} priv aes 128 {2}"}, {"ios-xe", "snmp-server user u g v3 encrypted auth md5 {1} priv des {2}"},
	{"ios-xe", "snmp-server user u g remote 10.1.1.1 v3 auth sha {1} priv 3des {2}"},
	{"ios-xe", "snmp-server user u g v3 auth sha {1} priv aes 256 {2} access ipv6 ACL"},
	{"ios-xe", "ntp authentication-key 10 md5 {1}"}, {"ios-xe", "ntp authentication-key 10 md5 {1} 7"}, {"ios-xe", "ntp authentication-key 10 sha1 {1}"},
	{"ios-xe", "ntp auth-key 10 md5 {1}"},
	{"ios-xe", "ip ospf message-digest-key 1 md5 {1}"}, {"ios-xe", "ip ospf authentication-key {1}"},
	{"ios-xe", "area 0 virtual-link 1.1.1.1 message-digest-key 1 md5 {1}"}, {"ios-xe", "ip ospf message-digest-key 1 md5 7 {1}"},
	{"ios-xe", "crypto isakmp key {1} address 1.1.1.1"}, {"ios-xe", "crypto isakmp key 6 {1} address 1.1.1.1 255.255.255.0"},
	{"ios-xe", "crypto isakmp key {1} hostname H"}, {"ios-xe", "cry isa key {1} add 1.1.1.1"},
	{"ios-xe", "pre-shared-key address 1.1.1.1 key {1}"}, {"ios-xe", "pre-shared-key local {1}"}, {"ios-xe", "pre-shared-key remote {1}"},
	{"ios-xe", "pre-shared-key local {1} remote {2}"}, {"ios-xe", "pre-shared-key hostname H key 0 {1}"},
	{"ios-xe", "tacacs-server key {1}"}, {"ios-xe", "tacacs-server key 7 {1}"}, {"ios-xe", "tacacs-server host 10.1.1.1 key {1}"},
	{"ios-xe", "tacacs-server host 10.1.1.1 key 0 {1} timeout 5"}, {"ios-xe", "tacacs-server host 10.1.1.1 timeout 5 key {1}"},
	{"ios-xe", "radius-server key {1}"}, {"ios-xe", "radius-server host 1.1.1.1 auth-port 1812 key {1}"}, {"ios-xe", "radius-server host 1.1.1.1 key 7 {1}"},
	{"ios-xe", "standby 1 authentication text {1}"}, {"ios-xe", "standby 1 authentication md5 key-string {1}"},
	{"ios-xe", "standby 1 authentication md5 key-string 7 {1}"}, {"ios-xe", "vrrp 1 authentication text {1}"}, {"ios-xe", "glbp 1 authentication text {1}"},
	{"ios-xe", "key-string {1}"}, {"ios-xe", "key-string 7 {1}"},
	{"ios-xe", "area-password {1}"}, {"ios-xe", "domain-password {1}"}, {"ios-xe", "isis password {1} level-1"}, {"ios-xe", "isis password {1}"},
	{"ios-xe", "isis password {1} level-2"},
	{"ios-xe", "wpa-psk ascii {1}"}, {"ios-xe", "wpa-psk ascii 0 {1}"}, {"ios-xe", "security wpa psk set-key ascii 0 {1}"},
	{"ios-xe", "license smart register idtoken {1}"}, {"ios-xe", "license smart register idtoken {1} force"},
	{"ios-xe", "crypto pki export TP pem url scp://admin:{1}@10.1.1.1/tp 3des password {2}"},
	{"ios-xe", "crypto pki export TP pem url scp://admin:{1}@10.1.1.1/tp 3des pass {2}"},
	{"ios-xe", "crypto pki import TP pem url scp://admin:{1}@10.1.1.1/tp password {2}"},
	{"ios-xe", "crypto pki import TP pem url ftp://u:{1}@1.1.1.1/f pass {2}"},
	{"ios-xe", "crypto pki export TP pkcs12 ftp://u:{1}@1.1.1.1/f password {2}"},
	{"ios-xe", "crypto pki export TP pem terminal 3des {1}"},
	{"ios-xe", "crypto key export rsa K pem url ftp://u:{1}@1.1.1.1/k 3des {2}"},
	{"ios-xe", "crypto key import rsa K pem url scp://u:{1}@10.1.1.1/k {2}"},
	{"ios-xe", "crypto ca export TP pkcs12 flash:tp.p12 {1}"},
	{"ios-xe", "api-key {1}"}, {"ios-xe", "api-key {1} secret {2}"}, {"ios-xe", "api-key A secret {1}"},
	{"ios-xe", "mgmtuser username admin pass 0 {1} secret 0 {2}"}, {"ios-xe", "mgmtuser username admin password 0 {1} secret 0 {2}"},
	{"ios-xe", "mgmtuser username admin password {1}"},
	{"ios-xe", "wireless ewc-ap ap-management username U pass {1} secret 0 {2}"},
	{"ios-xe", "wireless ewc-ap ap-management username U password {1} secret 0 {2}"},
	{"ios-xe", "crypto pki export TP pem url scp://a:{1}@1.1.1.1/tp aes pass {2}"}, {"ios-xe", "crypto key export rsa K pem url ftp://a:{1}@1.1.1.1/k aes pass {2}"},
	{"ios-xe", "crypto pki import TP pem url ftp://a:{1}@1.1.1.1/tp 3des pass {2}"}, {"ios-xe", "ip ftp password {1}"}, {"ios-xe", "ip http client password {1}"}, {"ios-xe", "ip msdp password peer 1.1.1.1 {1}"},
	{"ios-xe", "ip pim hello-authentication ah-md5 {1}"}, {"ios-xe", "vtp password {1}"}, {"ios-xe", "cts credentials id X password {1}"},
	{"ios-xe", "cts sxp default password {1}"}, {"ios-xe", "l2tp tunnel password {1}"}, {"ios-xe", "ppp chap password {1}"},
	{"ios-xe", "ip nhrp authentication {1}"}, {"ios-xe", "neighbor 1.1.1.1 password {1}"}, {"ios-xe", "neighbor 1.1.1.1 password 7 {1}"},
	{"ios-xe", "mpls ldp password fallback {1}"}, {"ios-xe", "mpls ldp neighbor 1.1.1.1 password {1}"},
	{"ios-xe", "key config-key password-encrypt {1}"}, {"ios-xe", "eigrp authentication key eigrp 1 {1} key-id 1"},
	{"ios-xe", "bind authenticate root-dn cn=x password {1}"}, {"ios-xe", "ldap-server host 1.1.1.1 rootDN cn=x password {1}"},
	{"ios-xe", "set session-key inbound esp 256 cipher {1}"}, {"ios-xe", "pac key {1}"}, {"ios-xe", "server-key {1}"},
	{"ios-xe", "vpdn username u password {1}"},
	// NX-OS
	{"nx-os", "username admin password 5 {1} role network-operator"}, {"nx-os", "username admin pass {1} role network-admin"},
	{"nx-os", "snmp-server community {1} group network-operator"}, {"nx-os", "snmp-server community {1} ro"},
	{"nx-os", "snmp-server user u network-admin auth md5 {1} priv {2} localizedkey"},
	{"nx-os", "snmp-server user u auth sha {1} priv aes-128 {2}"},
	{"nx-os", "tacacs-server key 7 {1}"}, {"nx-os", "tacacs-server host 1.1.1.1 key 0 {1} timeout 5"},
	{"nx-os", "radius-server key {1}"}, {"nx-os", "radius-server host 1.1.1.1 key {1} authentication"},
	{"nx-os", "key chain K ; key 1 ; key-string 0 {1}"}, {"nx-os", "ntp authentication-key 1 md5 {1}"},
	{"nx-os", "ip ospf authentication-key 3 {1}"}, {"nx-os", "ip ospf message-digest-key 1 md5 3 {1}"},
	{"nx-os", "snmp-server community {1} ro ; username u password 5 {2} role network-admin"},
	{"nx-os", "feature tacacs+ ; tacacs-server key {1}"}, {"nx-os", "ntp server 10.1.1.1 ; ntp authentication-key 2 md5 {1}"},
	{"nx-os", "line vty ; password {1}"},
	// Formatos de la pasada de auditoría de noviembre (sin validar en laboratorio): llaves hex, MSDP con vrf, POD, RSVP,
	// FlexVPN, SIP/CME, PPP, CTS de NX-OS, ASA.
	{"ios-xe", "pre-shared-key hex {1}"}, {"ios-xe", "pre-shared-key local hex {1}"}, {"ios-xe", "pre-shared-key remote hex {1}"},
	{"ios-xe", "authentication local pre-share key hex {1}"},
	{"ios-xe", "ip msdp vrf RED password peer 10.1.1.1 {1}"}, {"ios-xe", "ip msdp vrf RED password peer 10.1.1.1 0 {1}"},
	{"ios-xe", "aaa pod server server-key {1}"}, {"ios-xe", "aaa pod server clients 10.1.1.1 port 1700 auth-type any server-key 0 {1}"},
	{"ios-xe", "ip rsvp authentication key {1}"}, {"ios-xe", "ip rsvp authentication neighbor address 10.1.1.1 key {1}"},
	{"ios-xe", "keyring aaa L name-mangler M password {1}"}, {"ios-xe", "aaa authorization group psk list L name-mangler M password {1}"},
	{"ios-xe", "authentication local eap mschapv2 username u password {1}"}, {"ios-xe", "authentication remote eap mschapv2 username u password 0 {1}"},
	{"ios-xe", "credentials username 1001 password {1} realm cisco.com"}, {"ios-xe", "authentication username u password {1} realm r"},
	{"ios-xe", "web admin system name admin password {1}"}, {"ios-xe", "web admin system name admin secret 0 {1}"}, {"ios-xe", "xml user u password {1} 15"},
	{"ios-xe", "ppp eap password {1}"}, {"ios-xe", "ppp ms-chap password {1}"}, {"ios-xe", "ppp ms-chap-v2 password 0 {1}"},
	{"ios-xe", "nas 10.1.1.1 key {1}"}, {"ios-xe", "user u1 nthash {1}"}, {"ios-xe", "digest secret {1} hash sha"}, {"ios-xe", "digest secret 0 {1}"},
	{"ios-xe", "encryption key 1 size 128bit 0 {1} transmit-key"}, {"ios-xe", "encryption vlan 10 key 1 size 40bit {1}"},
	{"ios-xe", "snmp-server community 7 {1} RO"}, {"ios-xe", "snmp-server community 6 {1}"},
	{"nx-os", "radius-server host 10.1.1.1 test username probe password {1} idle-time 5"}, {"nx-os", "tacacs-server host 10.1.1.2 test username probe password {1}"},
	{"nx-os", "cts sxp connection peer 1.1.1.1 password required {1} mode speaker"},
	{"nx-os", "cts sxp connection peer 1.1.1.1 source 2.2.2.2 password required 7 {1} mode listener vrf x"},
	{"asa", "http-proxy 10.1.1.1 80 username u password {1}"}, {"asa", "https-proxy 10.1.1.1 80 username u password {1}"},
	{"asa", "wccp 61 password {1}"}, {"asa", "wccp web-cache redirect-list X password {1}"}, {"asa", "rip authentication key {1} key_id 1"},
	{"asa", "cluster key {1}"}, {"asa", "ikev2 local-authentication pre-shared-key hex {1}"}, {"asa", "ikev2 remote-authentication pre-shared-key hex {1}"},
	{"asa", "ikev1 pre-shared-key hex {1}"},
	// ASA / FTD
	{"asa", "enable password {1} encrypted"}, {"asa", "passwd {1} encrypted"}, {"asa", "username u password {1} privilege 15"},
	{"asa", "username u password {1} encrypted privilege 15"}, {"asa", "username u password {1} pbkdf2"},
	{"asa", "snmp-server host inside 10.1.1.1 community {1}"}, {"asa", "snmp-server host inside 10.1.1.1 trap community {1} version 2c"},
	{"asa", "snmp-server community {1}"}, {"asa", "aaa-server X (inside) host 1.1.1.1 key {1}"},
	{"asa", "failover key {1}"}, {"asa", "failover key hex {1}"}, {"asa", "failover ipsec pre-shared-key {1}"},
	{"asa", "tunnel-group G ipsec-attributes ; ikev1 pre-shared-key {1}"},
	{"asa", "tunnel-group G ipsec-attributes ; ikev2 remote-authentication pre-shared-key {1}"},
	{"asa", "tunnel-group G ipsec-attributes ; ikev2 local-authentication pre-shared-key {1}"},
	{"asa", "pre-shared-key {1}"}, {"asa", "ldap-login-password {1}"}, {"asa", "radius-common-pw {1}"},
	{"asa", "crypto ca export TP pkcs12 {1}"}, {"asa", "authentication key eigrp 1 {1} key-id 1"},
	{"asa", "ospf authentication-key {1}"}, {"asa", "ospf message-digest-key 1 md5 {1}"},
	{"ftd", "configure manager add 10.1.1.1 {1} {2}"}, {"ftd", "enable password {1}"}, {"ftd", "snmp-server community {1}"},
	// AireOS (solo con palabra clave: sin ella solo las reglas de la plataforma lo ven)
	{"wlc-aireos", "config mgmtuser password admin2 {1}"}, {"wlc-aireos", "config snmp community create {1}"},
	{"wlc-aireos", "config wlan security wpa akm psk set-key ascii {1} 3"},
	{"wlc-aireos", "config ap mgmtuser add username apadmin password {1} secret {2} all"},
	{"wlc-aireos", "config local-auth user-credentials password {1}"}, {"wlc-aireos", "config local-auth method fast server-key {1}"},
	{"wlc-aireos", "config ldap simple-bind authenticated 1 username cn=x password {1}"},
	// ISE (ADE-OS)
	{"ise", "username admin password hash {1} role admin"}, {"ise", "username jdoe password plain {1} role user"},
	{"ise", "tacacs-server key {1}"}, {"ise", "snmp-server community {1} ro"},
}

var canalSimbolos = []string{"", "", "", "!", "#", "$", "%", "^", "&", "*", "-", "_", "+", "=", ".", ",", ":", "~", "@", "?", "/", "(", ")", "<", ">"}

// canalValor: un valor con símbolos y un marcador único de ancho fijo.
func canalValor(r *rand.Rand, n int) string {
	pre := canalSimbolos[r.Intn(len(canalSimbolos))]
	suf := canalSimbolos[r.Intn(len(canalSimbolos))]
	if pre == "" && suf == "" || len(pre+suf) > 0 && r.Intn(4) == 0 {
		suf += "x"
	}
	return fmt.Sprintf("%sZq%05d%s", pre, n, suf)
}

var canalMarca = regexp.MustCompile(`Zq\d{5}`)

type canalFallo struct{ canal, plat, in, out string }

// canalTotal: el corpus completo, o una vuelta por plantilla con -race (ver raceOn).
func canalTotal() int {
	if raceOn {
		return len(canalPlantillas)
	}
	return 7150
}

func canalCasos(total int) (cmds []string, plats []string) {
	r := rand.New(rand.NewSource(20261115))
	for n := 0; n < total; n++ {
		tp := canalPlantillas[n%len(canalPlantillas)]
		c := tp.tpl
		for i := 1; i <= 3; i++ {
			c = strings.ReplaceAll(c, fmt.Sprintf("{%d}", i), canalValor(r, n*10+i))
		}
		cmds, plats = append(cmds, c), append(plats, tp.plat)
	}
	return
}

// canalSesion: sesión completa de la terminal; eco normal o desplazado («R1(config)#$<cola>»).
func canalSesion(cmd string, shifted bool) string {
	var buf bytes.Buffer
	t0 := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	rec := terminal.NewRecorder(&buf, func() time.Time { return t0 })
	rec.Output([]byte("R1(config)#"))
	rec.Input([]byte(cmd + "\r"))
	echo := cmd
	if shifted {
		echo = "$" + cmd[max(0, len(cmd)-40):]
	}
	rec.Output([]byte(echo + "\r\nR1(config)#"))
	rec.Close()
	return buf.String()
}

var canales = []struct {
	nombre string
	f      func(plat, cmd string) string
}{
	{"1 Typed + corte", func(p, c string) string { return nuevo.typed(p, c) }},
	{"2 CFGLOG", func(p, c string) string {
		o, _ := mask.Apply(p, "%PARSER-5-CFGLOG_LOGGEDCMD: User:bob  logged command:"+c+"\n")
		return o
	}},
	{"3 archive log", func(p, c string) string { o, _ := mask.Apply(p, "  7     3    bob@vty0   |  "+c+"\n"); return o }},
	{"4 accounting NX-OS", func(p, c string) string {
		o, _ := mask.Apply(p, "Sun Nov 15 10:00:00 2026:type=update:id=10.1.1.1@pts/0:user=admin:cmd=configure terminal ; "+c+" (SUCCESS)\n")
		return o
	}},
	{"5 ASA 111008", func(_, c string) string {
		o, _ := mask.Apply("asa", "%ASA-5-111008: User 'enable_15' executed the '"+c+"' command.\n")
		return o
	}},
	{"5 ASA 111010", func(_, c string) string {
		o, _ := mask.Apply("asa", "%ASA-5-111010: User 'bob', running 'CLI' from IP 10.1.1.1, executed '"+c+"'\n")
		return o
	}},
	{"6 CMD", func(p, c string) string {
		o, _ := mask.Apply(p, "CMD: '"+c+"' 10:00:00 UTC Sun Nov 15 2026\n")
		return o
	}},
	{"7 diff +", func(p, c string) string { o, _ := mask.Apply(p, "+"+c+"\n"); return o }},
	{"8 Cmd", func(p, c string) string { return mask.Cmd(p, c) }},
	{"9 show tech ASA", func(p, c string) string {
		o, _ := mask.Apply(p, "*** Output from config line 9, \""+c+"\"\n")
		return o
	}},
	{"10 ERROR", func(p, c string) string { o, _ := mask.Apply(p, "ERROR: \""+c+"\"\n"); return o }},
	{"11 syslog multilínea", func(_, c string) string {
		i := strings.IndexByte(c[len(c)/2:], ' ')
		if i < 0 {
			i = strings.IndexByte(c, ' ')
		} else {
			i += len(c) / 2
		}
		if i < 0 {
			return string(syslogd.MaskRaw([]byte("%PARSER-5-CFGLOG_LOGGEDCMD: User:bob  logged command:" + c)))
		}
		return string(syslogd.MaskRaw([]byte("%PARSER-5-CFGLOG_LOGGEDCMD: User:bob  logged command:" + c[:i] + "\n" + c[i+1:])))
	}},
	{"12a terminal eco normal", func(_, c string) string { return canalSesion(c, false) }},
	{"12b terminal eco desplazado", func(_, c string) string { return canalSesion(c, true) }},
}

func TestCanalesNingunSecretoSeVe(t *testing.T) {
	cmds, plats := canalCasos(canalTotal())
	porCanal := map[string]int{}
	var fallos []canalFallo
	for i, c := range cmds {
		marcas := canalMarca.FindAllString(c, -1)
		for _, ch := range canales {
			out := ch.f(plats[i], c)
			for _, m := range marcas {
				if strings.Contains(out, m) {
					porCanal[ch.nombre]++
					fallos = append(fallos, canalFallo{ch.nombre, plats[i], c, strings.TrimSpace(out)})
					break
				}
			}
		}
	}
	if len(fallos) == 0 {
		return
	}
	nombres := make([]string, 0, len(porCanal))
	for k := range porCanal {
		nombres = append(nombres, k)
	}
	sort.Strings(nombres)
	for _, k := range nombres {
		t.Errorf("canal %s: %d fugas", k, porCanal[k])
	}
	// Los primeros 30, repartidos: uno por plantilla distinta y canal.
	visto := map[string]bool{}
	n := 0
	for _, f := range fallos {
		k := f.canal + "|" + canalMarca.ReplaceAllString(f.in, "")
		if visto[k] || n >= 30 {
			continue
		}
		visto[k] = true
		n++
		t.Errorf("[%s] (%s)\n  entrada: %q\n  salida:  %q", f.canal, f.plat, f.in, f.out)
	}
}

// Canal 13: idempotencia. Aplicar dos veces no tapa más que una.
func TestCanalesIdempotencia(t *testing.T) {
	cmds, plats := canalCasos(canalTotal())
	malos := 0
	for i, c := range cmds {
		for _, in := range []string{c, "%PARSER-5-CFGLOG_LOGGEDCMD: User:bob  logged command:" + c} {
			a, _ := mask.Apply(plats[i], in+"\n")
			b, _ := mask.Apply(plats[i], a)
			if a != b {
				if malos++; malos <= 30 {
					t.Errorf("(%s)\n  entrada: %q\n  1.ª: %q\n  2.ª: %q", plats[i], in, strings.TrimSpace(a), strings.TrimSpace(b))
				}
			}
		}
	}
	if malos > 30 {
		t.Errorf("%d casos no idempotentes en total", malos)
	}
}

func TestCanalesCantidad(t *testing.T) {
	if len(canalPlantillas) < 130 {
		t.Fatalf("faltan plantillas: %d", len(canalPlantillas))
	}
}
