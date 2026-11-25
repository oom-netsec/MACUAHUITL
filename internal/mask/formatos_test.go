package mask_test

import (
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/mask"
)

// Formatos de configuración impresa con su bloque (como los imprime show running-config). Sintaxis de la documentación
// de Cisco (IOS-XE, NX-OS, ASA), sin validar en laboratorio. Cada línea lleva el marcador LEAK.
var formatosPositivos = []struct{ plat, cfg string }{
	{"ios-xe", "crypto ikev2 keyring KR\n peer P\n  pre-shared-key hex 4C45414B0011AABB\n  pre-shared-key local hex 4C45414B0011AABC\n  pre-shared-key remote hex 4C45414B0011AABD\n"},
	{"ios-xe", "crypto ikev2 profile P\n authentication local pre-share key hex 4C45414B0011AABB\n authentication local eap mschapv2 username u password LEAKa\n aaa authorization group psk list L name-mangler M password LEAKb\n keyring aaa L name-mangler M password LEAKc\n"},
	{"ios-xe", "ip msdp vrf RED password peer 10.1.1.1 0 LEAKd\nip msdp vrf RED password peer 10.1.1.1 LEAKe\naaa pod server server-key LEAKf\naaa pod server clients 10.1.1.1 port 1700 auth-type any server-key 0 LEAKg\n"},
	{"ios-xe", "radius-server local\n nas 10.0.0.1 key LEAKh\n nas 10.0.0.1 key 0 LEAKi\n user u1 password LEAKj\n user u2 nthash LEAK0123456789ABCDEF\n user u3 nthash 7 LEAK0123456789ABCDEE\n!\n"},
	{"ios-xe", "interface Gi0/0\n ip rsvp authentication key LEAKk\nip rsvp authentication neighbor address 1.1.1.1 key LEAKl\n"},
	{"ios-xe", "l2tp-class L\n digest secret LEAKm hash sha\n digest secret 0 LEAKn\n password LEAKo\n password 7 LEAKp\n"},
	{"ios-xe", "sip-ua\n credentials username 1001 password LEAKq realm cisco.com\n authentication username u password LEAKr\ntelephony-service\n web admin system name a password LEAKs\n xml user u password LEAKt 15\n"},
	{"ios-xe", "interface Dialer1\n ppp eap password LEAKu\n ppp ms-chap password LEAKv\n ppp ms-chap-v2 password LEAKw\n"},
	{"ios-xe", "interface Dot11Radio0\n encryption key 1 size 128bit 0 LEAK1234567890ABCDEF transmit-key\n encryption vlan 10 key 1 size 40bit LEAK123456\n"},
	{"ios-xe", "snmp-server host 10.0.0.1 version 2c 7 LEAKx\nsnmp-server host 10.0.0.1 vrf M version 2c 6 LEAKy udp-port 162\n"},
	{"ios-xe", "crypto ikev2 profile P\n aaa authorization group override psk list L name-mangler M password LEAKz\n aaa authorization group cert override list L G password 0 LEAKw\n"},
	{"ios-xe", "line con 0\npassword LEAKl1\nline vty 0 4\npassword 7 LEAKl2\nlogin\n"},
	{"ios-xe", "cellular 0/1/0 lte sim authenticate 0 LEAKpin slot 0\ncellular 0/1/0 lte sim authenticate 7 LEAKpin2\n"},
	{"ios-xe", "event manager applet A\n action 1.0 cli command \"enable secret LEAKeem\"\n action 2.0 cli command \"username a secret LEAKeem2\"\n"},
	{"nx-os", "radius-server test username U password LEAKt1 idle-time 5\ntacacs-server test username U password LEAKt2\nradius-server test password LEAKt3\n"},
	{"asa", "interface g0/0\n rip authentication key 0 LEAKr1 key_id 1\n rip authentication key 8 LEAKr2 key_id 2\n isis authentication key LEAKi1\n isis authentication key 8 LEAKi2 level-1\nrouter isis\n authentication key LEAKi3 level-2\n authentication key 0 LEAKi4\n"},
	{"asa", "http-proxy 10.1.1.1 username u password LEAKp1\nhttps-proxy 10.1.1.1 username u password LEAKp2\n"},
	{"asa", "vpn load-balancing  \n  cluster key LEAKv1\n"},
	{"ios-xe", "radius-server local  \n nas 1.1.1.1 key LEAKn1\n"},
	{"nx-os", "radius-server host 10.1.1.1 test username probe password LEAKnx1 idle-time 5\ntacacs-server host 10.1.1.2 test username probe password LEAKnx2\ncts sxp connection peer 1.1.1.1 password required LEAKnx3 mode speaker\ncts sxp connection peer 1.1.1.1 source 2.2.2.2 password required 7 LEAKnx4 mode listener vrf x\n"},
	{"asa", "webvpn\n http-proxy 10.1.1.1 80 username u password LEAKa1\n https-proxy 10.1.1.1 80 username u password LEAKa2\nwccp 61 password LEAKa3\nmount M type cifs\n server 1.1.1.1\n username u\n password LEAKa4\n domain d\nmount F type ftp\n password LEAKa5\ninterface g0/0\n rip authentication key LEAKa6 key_id 1\nvpn load-balancing\n cluster key LEAKa7\n"},
	{"asa", "tunnel-group X ipsec-attributes\n ikev1 pre-shared-key hex 4C45414B00112233\n ikev2 local-authentication pre-shared-key hex 4C45414B00112234\n ikev2 remote-authentication pre-shared-key hex 4C45414B00112244\n"},
}

func TestFormatosAuditoriaConfigImpresa(t *testing.T) {
	for _, c := range formatosPositivos {
		out, _ := mask.Apply(c.plat, c.cfg)
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "LEAK") || strings.Contains(l, "4C45414B") {
				t.Errorf("[%s] fuga: %q", c.plat, l)
			}
		}
		// la forma tecleada de cada línea (sin sangría) también se tapa
		for _, l := range strings.Split(c.cfg, "\n") {
			if o := mask.Cmd(c.plat, strings.TrimSpace(l)); strings.Contains(o, "LEAK") || strings.Contains(o, "4C45414B") {
				t.Errorf("[%s] Cmd deja ver: %q -> %q", c.plat, l, o)
			}
		}
	}
}

// Parecidas que NO son secreto: no se tapan (la regla nueva no puede comerse lo demás).
func TestFormatosAuditoriaNegativos(t *testing.T) {
	for _, c := range []struct{ plat, cfg string }{
		{"ios-xe", "crypto ikev2 keyring KR\n peer P\n  address 10.0.0.1\n  identity fqdn x.com\n"},
		{"ios-xe", "ip msdp vrf RED peer 10.1.1.1 connect-source Loopback0\nip msdp vrf RED originator-id Loopback0\n"},
		{"ios-xe", "aaa pod server clients 10.1.1.1 port 1700 auth-type any\n"},
		{"ios-xe", "radius-server local\n nas 10.0.0.1\n group G\n user u1 group G\n"},
		{"ios-xe", "interface Gi0/0\n ip rsvp bandwidth 1000\n ip rsvp authentication\n ip rsvp authentication key-chain KC\n ip rsvp authentication window-size 5\n"},
		{"ios-xe", "l2tp-class L\n hostname R1\n hello 30\n digest hash sha1\n"},
		{"ios-xe", "sip-ua\n authentication username u password\n registrar ipv4:1.1.1.1 expires 3600\n"},
		{"ios-xe", "interface Dialer1\n ppp eap identity bob\n ppp eap refuse\n ppp ms-chap refuse\n"},
		{"ios-xe", "snmp-server community public RO\n"},
		{"nx-os", "radius-server host 10.1.1.1 test idle-time 5\ncts sxp connection peer 1.1.1.1 password none mode speaker\ncts sxp connection peer 1.1.1.1 password default mode listener\n"},
		{"asa", "http-proxy 10.1.1.1 80\nwccp 61 redirect-list X\nmount M type cifs\n server 1.1.1.1\n share s\n username u\n domain d\n"},
		{"asa", "vpn load-balancing\n cluster ip address 1.1.1.1\n cluster encryption\n"},
	} {
		out, _ := mask.Apply(c.plat, c.cfg)
		if strings.Contains(out, "<MASKED") && !strings.Contains(c.cfg, "community public") {
			t.Errorf("[%s] taparon de más:\n%s", c.plat, out)
		}
		if strings.Contains(c.cfg, "community public") && !strings.Contains(out, "<MASKED:snmp-community>") {
			t.Errorf("la comunidad public sigue tapándose como siempre:\n%s", out)
		}
	}
}

// El tipo 0 deja pasar las palabras del propio comando que siguen al valor (realm, transmit-key, hash, idle-time, mode…).
func TestFormatosAuditoriaColaTipo0(t *testing.T) {
	for _, c := range []struct{ plat, in, want string }{
		{"ios-xe", "sip-ua\n credentials username 1001 password 0 LEAK uno dos realm cisco.com\n", " realm cisco.com"},
		{"ios-xe", "interface Dot11Radio0\n encryption key 1 size 128bit 0 LEAK uno transmit-key\n", " transmit-key"},
		{"ios-xe", "l2tp-class L\n digest secret 0 LEAK uno hash sha\n", " hash sha"},
		{"nx-os", "radius-server host 1.1.1.1 test username u password 0 LEAK uno idle-time 5\n", " idle-time 5"},
		{"nx-os", "cts sxp connection peer 1.1.1.1 password required 0 LEAK uno mode speaker\n", " mode speaker"},
		{"ios-xe", "telephony-service\n xml user u password 0 LEAK uno 15\n", " 15"},
		{"ios-xe", "aaa authorization group psk list L name-mangler M password 0 LEAK uno\n", ""},
	} {
		out, _ := mask.Apply(c.plat, c.in)
		if strings.Contains(out, "LEAK") || strings.Contains(out, "uno") || !strings.HasSuffix(strings.TrimSpace(out), strings.TrimSpace(c.want)) || !strings.Contains(out, "<MASKED") {
			t.Errorf("[%s] %q -> %q (se esperaba valor tapado y cola %q)", c.plat, c.in, out, c.want)
		}
	}
}

// El prompt «Password:», password-encryption y la comunidad que se llama «7» no se tocan.
func TestFormatosAuditoriaNoTapaDeMas(t *testing.T) {
	for _, in := range []string{
		"line vty 0 4\nPassword: \n", "line vty 0 4\npassword encryption aes\n", "line vty 0 4\nlogin\n", "service password-encryption\n",
		"snmp-server community 7 RO\n", "radius-server test idle-time 5\n", "line con 0\nexec-timeout 0 0\n",
	} {
		out, _ := mask.Apply("ios-xe", in)
		if in == "snmp-server community 7 RO\n" {
			if strings.Contains(out, "RO") && !strings.Contains(out, "<MASKED") {
				t.Errorf("la comunidad 7 debe taparse como siempre: %q", out)
			}
			continue
		}
		if strings.Contains(out, "<MASKED") {
			t.Errorf("taparon de más %q -> %q", in, out)
		}
	}
}

// 2.ª revisión: la comunidad de un dígito seguida de una palabra protegida se sigue tapando (como la v0.6.5), y en
// tipo 0 la comunidad llega hasta udp-port o el tipo de notificación.
func TestFormatosAuditoriaSnmpHostDigito(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"snmp-server host 10.1.1.1 version 2c 7 udp-port 1162", "snmp-server host 10.1.1.1 version 2c <MASKED:snmp-community> udp-port 1162"},
		{"snmp-server host 10.1.1.1 traps version 2c 0 informs", "snmp-server host 10.1.1.1 traps version 2c <MASKED:snmp-community> informs"},
		{"snmp-server host 10.1.1.1 version 2c 6 vrf", "snmp-server host 10.1.1.1 version 2c <MASKED:snmp-community> vrf"},
		{"snmp-server host 10.1.1.1 version 2c 0 MYCOMM udp-port 1162 bgp", "snmp-server host 10.1.1.1 version 2c 0 <MASKED:snmp-community> udp-port 1162 bgp"},
		{"snmp-server host 10.1.1.1 version 2c 0 MYCOMM bgp config", "snmp-server host 10.1.1.1 version 2c 0 <MASKED:snmp-community> bgp config"},
	} {
		if out, _ := mask.Apply("ios-xe", c.in+"\n"); strings.TrimSpace(out) != c.want {
			t.Errorf("%q -> %q, se esperaba %q", c.in, strings.TrimSpace(out), c.want)
		}
	}
}

// Cmd no toca los filtros de un show ni los textos entre comillas que no son secretos, ni desescapa comillas sin tapar.
func TestFormatosAuditoriaCmdNoTapaDeMas(t *testing.T) {
	for _, in := range []string{
		`show logging | include "password changed"`, `show run | i "pre-shared-key address"`,
		`do show run | i "secret x"`, `action 1 puts \"hola\"`,
	} {
		if out := mask.Cmd("ios-xe", in); out != in {
			t.Errorf("Cmd cambió %q -> %q", in, out)
		}
	}
	if out := mask.Cmd("ios-xe", `action 1.0 cli command "enable secret LEAKeem"`); strings.Contains(out, "LEAK") {
		t.Errorf("EEM visible: %q", out)
	}
}

// NX-OS: tras «line vty», password strength-check / secure-mode / prompt sin sangría son comandos, no la contraseña.
func TestFormatosAuditoriaSetupPasswordNxos(t *testing.T) {
	for _, in := range []string{"line vty\npassword strength-check\n", "line vty\npassword secure-mode\n", "line vty\npassword prompt username\n"} {
		if out, _ := mask.Apply("nx-os", in); strings.Contains(out, "<MASKED") {
			t.Errorf("taparon de más %q -> %q", in, out)
		}
	}
}
