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
	{"ios-xe", "snmp-server community 7 LEAKx RO\nsnmp-server community 6 LEAKy RO\n"},
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
