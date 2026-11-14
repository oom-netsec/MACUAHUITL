package mask

import "testing"

// Sintaxis de configuración de AireOS (aparece en grabaciones de terminal) y falsos positivos.
var aireosCases = []struct{ in, want string }{
	{"config radius auth add 1 10.1.1.5 1812 ascii Rad1usK3y", "config radius auth add 1 10.1.1.5 1812 ascii <MASKED:radius-key>"},
	{"config radius acct add 2 10.1.1.5 1813 hex 0a1b2c3d", "config radius acct add 2 10.1.1.5 1813 hex <MASKED:radius-key>"},
	{"config tacacs auth add 1 10.1.1.6 49 ascii TacK3y", "config tacacs auth add 1 10.1.1.6 49 ascii <MASKED:tacacs-key>"},
	{"config tacacs acct add 1 10.1.1.6 49 hex 0a1b", "config tacacs acct add 1 10.1.1.6 49 hex <MASKED:tacacs-key>"},
	{"config tacacs athr add 1 10.1.1.6 49 ascii TacK3y", "config tacacs athr add 1 10.1.1.6 49 ascii <MASKED:tacacs-key>"},
	{"config wlan security wpa akm psk set-key ascii WlanPsk123 3", "config wlan security wpa akm psk set-key ascii <MASKED:wifi-psk> 3"},
	{"config wlan security wpa akm psk set-key hex 0a1b2c 3", "config wlan security wpa akm psk set-key hex <MASKED:wifi-psk> 3"},
	{"config mgmtuser add admin2 Secreta1 read-write", "config mgmtuser add admin2 <MASKED:user-secret> read-write"},
	{"config mgmtuser add admin2 Secreta1 read-only Usuario de NOC", "config mgmtuser add admin2 <MASKED:user-secret> read-only Usuario de NOC"},
	{"config mgmtuser password admin2 Nueva1", "config mgmtuser password admin2 <MASKED:user-secret>"},
	{"config netuser add guest1 Guest1Pw 2 userType guest lifetime 86400 description invitado", "config netuser add guest1 <MASKED:user-secret> 2 userType guest lifetime 86400 description invitado"},
	{"config netuser password guest1 Nueva1", "config netuser password guest1 <MASKED:user-secret>"},
	{"config snmp community create Comun1dad", "config snmp community create <MASKED:snmp-community>"},
	{"config snmp community accessmode rw Comun1dad", "config snmp community accessmode rw <MASKED:snmp-community>"},
	{"config snmp community ipaddr 10.1.1.0 255.255.255.0 Comun1dad", "config snmp community ipaddr 10.1.1.0 255.255.255.0 <MASKED:snmp-community>"},
	{"config snmp v3user create u3 ro hmacsha aescfb128 AuthK3y PrivK3y", "config snmp v3user create u3 ro hmacsha aescfb128 <MASKED:snmp-user-auth> <MASKED:snmp-user-priv>"},
	{"config local-auth user-credentials password LocalPw", "config local-auth user-credentials password <MASKED:user-secret>"},
	{"config local-auth method fast server-key FastK3y", "config local-auth method fast server-key <MASKED:psk>"},
	{"config ap mgmtuser add username apadmin password ApPass1 secret ApSec1 all", "config ap mgmtuser add username apadmin password <MASKED:user-secret> secret <MASKED:user-secret> all"},
	{"config ap 802.1Xuser add username ap8021 password Dot1xPw all", "config ap 802.1Xuser add username ap8021 password <MASKED:dot1x-password> all"},
	// show snmpcommunity: la comunidad sale en claro en la primera columna.
	{"public                  0.0.0.0             0.0.0.0           Read Only    Enable", "<MASKED:snmp-community>                  0.0.0.0             0.0.0.0           Read Only    Enable"},
	// Falsos positivos: nada de esto es un secreto.
	{"config wlan ssid 3 Corp-WiFi", "config wlan ssid 3 Corp-WiFi"},
	{"config wlan create 3 Corp Corp-WiFi", "config wlan create 3 Corp Corp-WiFi"},
	{"config ap name AP-Sala1 AP-Sala-2", "config ap name AP-Sala1 AP-Sala-2"},
	{"config ap name AP-Sala1 AP1234", "config ap name AP-Sala1 AP1234"},
	{"show ap summary", "show ap summary"},
	{"AP-Sala1     2  AIR-AP2802I-A-K9  0c:75:bd:11:22:33  Cisco-Lab  10.1.1.20", "AP-Sala1     2  AIR-AP2802I-A-K9  0c:75:bd:11:22:33  Cisco-Lab  10.1.1.20"},
	{"show client summary", "show client summary"},
	{"Number of Clients............................... 3", "Number of Clients............................... 3"},
	{"config mgmtuser description admin2 cambiar el password cada mes", "config mgmtuser description admin2 cambiar el password cada mes"},
	{"config wlan description 3 password de invitados en recepcion", "config wlan description 3 password de invitados en recepcion"},
	{"config snmp community mode enable", "config snmp community mode enable"},
	{"config radius auth delete 1", "config radius auth delete 1"},
	{"config radius auth add 1 10.1.1.5 1812", "config radius auth add 1 10.1.1.5 1812"},
	{"Shared Secret................................... ******", "Shared Secret................................... ******"},
}

func TestAireOSReglas(t *testing.T) {
	for _, c := range aireosCases {
		once, _ := Apply("aireos", c.in+"\n")
		if got := once[:len(once)-1]; got != c.want {
			t.Errorf("Apply(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
		twice, n := Apply("aireos", once)
		if twice != once || len(n) != 0 {
			t.Errorf("no idempotente %q: %q → %q %v", c.in, once, twice, n)
		}
	}
}
