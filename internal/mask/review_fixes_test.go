package mask

import (
	"strings"
	"testing"
)

func TestReviewMaskGaps(t *testing.T) {
	for _, c := range []struct{ in, leak string }{
		{"key chain K1\n key 1\n  key-string 7 S3CR3TA\n", "S3CR3TA"},
		{"snmp-server user U G v3 auth sha AUTHPW priv aes 128 PRIVPW\n", "AUTHPW"},
		{"snmp-server user U G v3 auth sha AUTHPW priv aes 128 PRIVPW\n", "PRIVPW"},
		{"snmp-server host 192.0.2.1 version 2c COMMSTR\n", "COMMSTR"},
		{"router bgp 65000\n neighbor 192.0.2.2 password 7 BGPPW\n", "BGPPW"},
		{"interface Serial0\n ppp chap password 7 CHAPPW\n", "CHAPPW"},
		{"interface Serial0\n ppp pap sent-username U password 7 PAPPW\n", "PAPPW"},
		{"wlan W 1 W\n security wpa psk set-key ascii 0 WLCPSK\n", "WLCPSK"},
		{"dot11 ssid X\n wpa-psk ascii 7 WPAPSK\n", "WPAPSK"},
		{"interface Vlan1\n standby 1 authentication md5 key-string 7 HSRPPW\n", "HSRPPW"},
		{"interface Vlan1\n vrrp 1 authentication text VRRPPW\n", "VRRPPW"},
		{"aaa group server tacacs+ G\n server-private 192.0.2.5 key 7 PRIVKEY\n", "PRIVKEY"},
		{"ntp authentication-key 1 hmac-sha2-256 NTPSHA\n", "NTPSHA"},
		{"ip ftp password 7 FTPPW\n", "FTPPW"},
		{"ip http client password 7 HTTPPW\n", "HTTPPW"},
		{"key config-key password-encrypt MASTERKEY\n", "MASTERKEY"},
	} {
		if got, _ := Apply("ios-xe", c.in); strings.Contains(got, c.leak) {
			t.Errorf("leaked %s:\n%s", c.leak, got)
		}
	}
}
