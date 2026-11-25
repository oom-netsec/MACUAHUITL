package mask

import (
	"strings"
	"testing"
)

// ejemploRegla: una línea que alguna regla de secreto enmascara (bloque y plataforma donde aplica). Todo valor
// secreto empieza con «Cl4ve»: la prueba exige que ninguno sobreviva.
type ejemploRegla struct{ block, platform, line string }

var ejemplosReglas = []ejemploRegla{
	// Pasada de auditoría de noviembre (sin validar en laboratorio).
	{"", "ios", " ip msdp vrf RED password peer 1.1.1.1 Cl4ve"},
	{"", "ios", "aaa pod server server-key Cl4ve"},
	{"", "ios", "ip rsvp authentication key Cl4ve"},
	{"", "ios", " keyring aaa L name-mangler M password Cl4ve"},
	{"", "ios", " authentication local eap mschapv2 username U password Cl4ve"},
	{"", "ios", " credentials username 1 password Cl4ve realm r"},
	{"", "ios", " web admin system name A password Cl4ve"},
	{"", "ios", " xml user U password Cl4ve 15"},
	{"", "ios", " ppp eap password Cl4ve"},
	{"", "ios", " encryption key 1 size 128bit Cl4ve transmit-key"},
	{"", "nx-os", "radius-server host 1.1.1.1 test username U password Cl4ve"},
	{"", "nx-os", "cts sxp connection peer 1.1.1.1 password required Cl4ve mode speaker"},
	{"", "asa", " http-proxy 1.1.1.1 80 username U password Cl4ve"},
	{"", "asa", " rip authentication key Cl4ve key_id 1"},
	{"vpnlb", "asa", " cluster key Cl4ve"},
	{"mount", "asa", " password Cl4ve"},
	{"radiuslocal", "ios", " nas 1.1.1.1 key Cl4ve"},
	{"radiuslocal", "ios", " user U nthash Cl4ve"},
	{"l2tp", "ios", " digest secret Cl4ve hash sha"},
	{"", "ios", "enable secret 0 Cl4ve"},
	{"", "ios", "username U secret 0 Cl4ve"},
	{"", "ios", "snmp-server community Cl4ve RO"},
	{"", "ios", "tacacs-server key Cl4ve"},
	{"", "ios", "radius-server key Cl4ve"},
	{"", "ios", "crypto isakmp key Cl4ve address 1.1.1.1"},
	{"", "asa", "isakmp key Cl4ve address 1.1.1.1 netmask 255.255.255.255"},
	{"", "nx-os", `"community_name": "Cl4ve",`},
	{"", "nx-os", "<community_name>Cl4ve</community_name>"},
	{"", "ios", " pre-shared-key address 1.1.1.1 key Cl4ve"},
	{"", "ios", " pre-shared-key local Cl4ve"},
	{"", "ios", "ntp authentication-key 1 md5 Cl4ve"},
	{"", "ios", "snmp-server user U G v3 auth sha Cl4veA priv aes 128 Cl4veB"},
	{"", "asa", "snmp-server host inside 1.1.1.1 community Cl4ve"},
	{"", "asa", "snmp-server host-group inside 1.1.1.1 community Cl4ve"},
	{"", "ios", "snmp-server host 1.1.1.1 version 2c Cl4ve udp-port 162"},
	{"", "ios", "snmp mib community-map Cl4ve context c"},
	{"", "ios", " neighbor 1.1.1.1 password Cl4ve"},
	{"", "ios", " ppp chap password Cl4ve"},
	{"", "ios", " security wpa psk set-key ascii 0 Cl4ve"},
	{"", "ios", " psk key Cl4ve"},
	{"", "ios", " standby 1 authentication md5 key-string Cl4ve"},
	{"", "ios", " glbp 1 authentication text Cl4ve"},
	{"", "nxos", "  authentication text Cl4ve"},
	{"", "ios", " key-string 0 Cl4ve"},
	{"", "ios", " server-private 1.1.1.1 key Cl4ve"},
	{"", "ios", "ip ftp password Cl4ve"},
	{"", "ios", "key config-key password-encrypt Cl4veOld Cl4veNew"},
	{"", "ios", "configure manager add 1.1.1.1 Cl4veA Cl4veB"},
	{"", "ios", "key config-key 1 Cl4ve"},
	{"", "ios", " ip ospf authentication-key 7 Cl4ve"},
	{"", "ios", " ip ospf message-digest-key 1 md5 7 Cl4ve"},
	{"", "ios", " area 1 virtual-link 1.1.1.1 message-digest-key 1 md5 Cl4ve"},
	{"", "ios", " ipv6 ospf authentication ipsec spi 256 md5 Cl4ve"},
	{"", "ios", " ipv6 ospf encryption ipsec spi 256 esp aes-cbc 128 Cl4ve"},
	{"", "ios", " ipv6 ospf encryption ipsec spi 256 esp null md5 Cl4ve"},
	{"", "ios", " area 1 authentication ipsec spi 256 md5 Cl4ve"},
	{"", "ios", " area 1 encryption ipsec spi 256 esp aes-cbc 128 Cl4ve"},
	{"", "ios", " area 1 encryption ipsec spi 256 esp null sha1 Cl4ve"},
	{"", "ios", " authentication mode hmac-sha-256 0 Cl4ve"},
	{"", "ios", " pac key Cl4ve"},
	{"", "ios", " server-key Cl4ve"},
	{"", "ios", " dtls key Cl4ve"},
	{"", "ios", " authentication-key Cl4ve"},
	{"", "ios", " map-server 1.1.1.1 key Cl4ve"},
	{"", "ios", "mgmtuser username U password 0 Cl4ve"},
	{"", "ios", "mgmtuser username U secret 0 Cl4ve"},
	{"", "ios", " dot1x username U password 0 Cl4ve"},
	{"", "ios", "wireless ewc-ap U password Cl4ve"},
	{"", "ios", "wireless ewc-ap U secret Cl4ve"},
	{"username", "ios", "  password 0 Cl4ve"},
	{"", "ios", " bind authenticate root-dn cn=x password Cl4ve"},
	{"", "nxos", "ldap-server host 1.1.1.1 rootDN cn=x password Cl4ve"},
	{"", "ios", " area-password Cl4ve"},
	{"", "ios", " domain-password Cl4ve"},
	{"", "ios", " isis password Cl4ve"},
	{"", "ios", "mpls ldp neighbor 1.1.1.1 password Cl4ve"},
	{"", "ios", "mpls ldp password fallback Cl4ve"},
	{"", "ios", "ip msdp password peer 1.1.1.1 Cl4ve"},
	{"", "ios", " ip pim hello-authentication ah-md5 Cl4ve"},
	{"", "ios", " bfd authentication meticulous-keyed-sha-1 key-id 1 key Cl4ve"},
	{"", "asa", "passwd Cl4ve"},
	{"", "asa", "ikev1 pre-shared-key Cl4ve"},
	{"", "asa", "failover key Cl4ve"},
	{"", "asa", "ldap-login-password Cl4ve"},
	{"", "asa", " eigrp authentication key 1 Cl4ve key-id 1"},
	{"", "asa", " authentication key eigrp 1 Cl4ve key-id 1"},
	{"aaaserver", "asa", " key Cl4ve"},
	{"cluster", "asa", " key Cl4ve"},
	{"", "asa", "radius-common-pw Cl4ve"},
	{"", "ios", "vpdn username U password Cl4ve"},
	{"", "asa", "aaa-server G (inside) host 1.1.1.1 Cl4ve"},
	{"licsmart", "ios", "  token Cl4ve"},
	{"", "ios", " authentication remote pre-share key Cl4ve"},
	{"ezvpn", "ios", " key Cl4ve"},
	{"", "ios", " group G key Cl4ve"},
	{"", "ios", " l2tp tunnel password Cl4ve"},
	{"", "ios", " ip nhrp authentication Cl4ve"},
	{"", "ios", " set session-key inbound esp 256 cipher Cl4ve"},
	{"", "ios", " set session-key inbound esp 256 authenticator Cl4ve"},
	{"", "ios", " set session-key inbound ah 256 Cl4ve"},
	{"trustpoint", "ios", " password Cl4ve"},
	{"", "ios", "database archive pkcs12 password Cl4ve"},
	{"", "ios", "crypto pki export TP password Cl4ve"},
	{"", "ios", "crypto pki export TP pem terminal 3des Cl4ve"},
	{"", "ios", "crypto ca export TP pkcs12 ftp://x Cl4ve"},
	{"", "ios", "cts credentials id I password Cl4ve"},
	{"", "ios", "cts sxp default password Cl4ve"},
	{"", "ios", "cts device-id D password Cl4ve"},
	{"", "ios", " sap pmk Cl4ve"},
	{"", "ios", " key-octet-string Cl4ve"},
	{"", "ios", "ip wccp web-cache password Cl4ve"},
	{"", "ios", "vtp password Cl4ve"},
	{"umbrella", "ios", " token Cl4ve"},
	{"", "ios", " api-key Cl4ve"},
	{"", "ios", " api-key K secret Cl4ve"},
	{"", "ios", "license smart register idtoken Cl4ve"},
	{"", "ios", "Community name: Cl4ve"},
	{"", "ios", "user: Cl4ve    security model: v2c"},
	{"", "ios", "Pre-shared Key: Cl4ve"},
	{"", "ios", "Key 1 -- text Cl4ve"},
	{"", "ios", "Authentication text, string Cl4ve"},
	{"", "ios", "VTP Password: Cl4ve"},
	{"", "ios", "PAC-Opaque: Cl4ve"},
	{"", "ios", "Mgmt Password: Cl4ve"},
	{"", "ios", "Dot1x Password: Cl4ve"},
	{"", "wlc-aireos", "Cl4ve 10.0.0.1 255.255.255.0 Read Only Enable"},
	{"", "ios", "PSK: Cl4ve"},
	{"tacacs", "ios", " key Cl4ve"},
	{"radius", "ios", " key Cl4ve"},
	{"dot1x", "ios", " password Cl4ve"},
	{"line", "ios", " password Cl4ve"},
	{"", "ios", "transfer download password Cl4ve"},
	{"", "ios", "transfer download certpassword Cl4ve"},
	{"", "ise", "username U password hash Cl4ve"},
	{"", "ise", "snmp-server user U v3 hash Cl4veA Cl4veB"},
	{"", "ise", "snmp-server host 1.1.1.1 version 3 U auth hash Cl4veA Cl4veB"},
	{"", "ise", "user U password hash Cl4ve"},
	{"", "ise", "backup X encryption-key hash Cl4ve"},
}

// Cuerpos AireOS: valen con «config » y sin él dentro de «config» (bloque aireconfig).
var cuerposAireos = []string{
	"radius auth add 1 1.1.1.1 1812 ascii Cl4ve",
	"radius auth keywrap add ascii Cl4veA Cl4veB",
	"tacacs auth add 1 1.1.1.1 49 ascii Cl4ve",
	"mgmtuser add U Cl4ve read-write",
	"mgmtuser add encrypt U Cl4ve",
	"mesh security psk provisioning key Cl4ve",
	"snmp community create Cl4ve",
	"snmp community ipaddr 1.1.1.1 255.255.255.0 Cl4ve",
	"snmp v3user create U ro HMAC-SHA AES Cl4veA Cl4veB",
	"local-auth method fast server-key Cl4ve",
	"local-auth user-credentials password Cl4ve",
	"ap mgmtuser add username U password Cl4veA secret Cl4veB",
	"ap 802.1Xuser add username U password Cl4ve",
	"wlan security static-wep-key encryption 1 1 ascii Cl4ve",
	"ldap simple-bind authenticated 1 username U password Cl4ve",
}

func todosLosEjemplos() []ejemploRegla {
	ex := append([]ejemploRegla(nil), ejemplosReglas...)
	for _, b := range cuerposAireos {
		ex = append(ex, ejemploRegla{"", "wlc-aireos", "config " + b}, ejemploRegla{"aireconfig", "wlc-aireos", b})
	}
	return ex
}

// dispara: la regla r enmascararía la línea del ejemplo (misma lógica que maskLine, sin aplicarla).
func dispara(r rule, e ejemploRegla) bool {
	if r.block != "" && r.block != e.block || r.not != nil && r.not.MatchString(e.line) || r.notFn != nil && r.notFn(e.line, e.platform) {
		return false
	}
	m := r.re.FindStringSubmatch(e.line)
	return m != nil && !strings.HasPrefix(m[2], "<MASKED:") && !(r.guard && isGuard(m[2]))
}

// Cada regla de secreto de iosRules (incluidas las de AireOS e ISE) debe tener un ejemplo; así una regla nueva sin
// ejemplo rompe la prueba y no puede dejar abierto el hueco de las líneas «no …».
func TestTodaReglaTieneEjemplo(t *testing.T) {
	ex := todosLosEjemplos()
	for i, r := range iosRules {
		ok := false
		for _, e := range ex {
			if dispara(r, e) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("regla %d (%s, bloque %q) sin ejemplo: %s", i, r.kind, r.block, r.re)
		}
	}
}

// Para cada ejemplo, la forma negada (sin sangría, con ella y con espacios de más) también sale enmascarada.
func TestEjemplosNegadosSeEnmascaran(t *testing.T) {
	for _, e := range todosLosEjemplos() {
		if got := maskLine(e.line, e.block, e.platform, map[string]int{}); strings.Contains(got, "Cl4ve") {
			t.Errorf("el ejemplo %q ni siquiera se enmascara: %q", e.line, got)
		}
		if strings.HasPrefix(e.line, "Cl4ve 10.") {
			continue // fila de show snmpcommunity de AireOS: sin comando, no hay forma negada
		}
		base := strings.TrimLeft(e.line, " ")
		lead := e.line[:len(e.line)-len(base)]
		// También en mayúsculas (IOS acepta NO/No y la terminal guarda lo tecleado), con «default» y con «no» repetido.
		for _, pre := range []string{"no ", " no ", "  no   ", "NO ", " No ", "nO ", "default ", " DEFAULT ", "no no "} {
			in := lead + pre + base
			got := maskLine(in, e.block, e.platform, map[string]int{})
			kw := strings.TrimLeft(pre, " ")
			ind := len(lead) + len(pre) - len(kw)
			if strings.Contains(got, "Cl4ve") || !strings.HasPrefix(got, in[:ind]) || !strings.HasPrefix(strings.TrimLeft(got, " "), kw) {
				t.Errorf("%q -> %q", in, got)
			}
		}
	}
}
