package mask

import (
	"strings"
	"testing"
)

// Un caso: in es la línea de entrada; want, lo esperado (igual a in = no es un secreto, no se toca).
type huecoCase struct{ in, want string }

// Casos de las auditorías de v0.4.0/v0.4.1: positivos (el secreto se tapa y el resto de la línea queda intacto) y
// negativos (líneas parecidas que no son secretos).
var huecoCases = []huecoCase{
	// Valor con espacios en tipo 0 (llega hasta el fin de línea o hasta una palabra clave del comando).
	{"username bob password 0 my pass word", "username bob password 0 <MASKED:user-secret>"},
	{"username bob password 0 my pass role network-admin", "username bob password 0 <MASKED:user-secret> role network-admin"},
	{"username bob password 5 $5$HASH role network-admin", "username bob password 5 <MASKED:user-secret> role network-admin"},
	{"radius-server key 0 shared key", "radius-server key 0 <MASKED:radius-key>"},
	{"tacacs-server key 0 \"my secret\"", "tacacs-server key 0 <MASKED:tacacs-key>"},
	{"tacacs-server host 10.1.1.1 key 7 \"ab cd\" timeout 5", "tacacs-server host 10.1.1.1 key 7 <MASKED:tacacs-key> timeout 5"},
	{"tacacs server T\n key 0 two words", "tacacs server T\n key 0 <MASKED:tacacs-key>"},
	{"line vty 0 4\n password 0 my pw", "line vty 0 4\n password 0 <MASKED:line-password>"},
	{" mgmtuser username a password 0 x y secret 0 p q", " mgmtuser username a password 0 <MASKED:user-secret> secret 0 <MASKED:user-secret>"},
	{"username bob privilege 15 secret 5 $1$x", "username bob privilege 15 secret 5 <MASKED:user-secret>"},
	{"username bob nopassword", "username bob nopassword"},
	// tacacs-server host con opciones antes de key.
	{"tacacs-server host 10.1.1.1 port 49 timeout 5 key 7 0822455D", "tacacs-server host 10.1.1.1 port 49 timeout 5 key 7 <MASKED:tacacs-key>"},
	{"tacacs-server host 10.1.1.1 single-connection key Cl4ve", "tacacs-server host 10.1.1.1 single-connection key <MASKED:tacacs-key>"},
	{"tacacs-server host 10.1.1.1 port 49", "tacacs-server host 10.1.1.1 port 49"},
	// snmp-server host con vrf; use-vrf no es la comunidad.
	{"snmp-server host 10.0.0.9 vrf MGMT version 2c COMM", "snmp-server host 10.0.0.9 vrf MGMT version 2c <MASKED:snmp-community>"},
	{"snmp-server host 10.1.1.1 vrf Mgmt-intf version 2c PUBLIC", "snmp-server host 10.1.1.1 vrf Mgmt-intf version 2c <MASKED:snmp-community>"},
	{"snmp-server host 10.0.0.9 use-vrf management version 2c COMM udp-port 162", "snmp-server host 10.0.0.9 use-vrf management version 2c <MASKED:snmp-community> udp-port 162"},
	{"snmp-server host 10.0.0.9 use-vrf management", "snmp-server host 10.0.0.9 use-vrf management"},
	{"snmp-server host 10.0.0.9 source-interface Lo0", "snmp-server host 10.0.0.9 source-interface Lo0"},
	{"snmp-server host 10.0.0.9 traps version 2c C1 udp-port 162", "snmp-server host 10.0.0.9 traps version 2c <MASKED:snmp-community> udp-port 162"},
	// snmp-server user: NX-OS y IOS-XE 17.
	{"snmp-server user admin network-admin auth md5 0xAABBCC priv 0xDDEEFF localizedkey", "snmp-server user admin network-admin auth md5 <MASKED:snmp-user-auth> priv <MASKED:snmp-user-priv> localizedkey"},
	{"snmp-server user admin network-admin auth md5 0xAABBCC priv aes-128 0xDDEEFF localizedkey", "snmp-server user admin network-admin auth md5 <MASKED:snmp-user-auth> priv aes-128 <MASKED:snmp-user-priv> localizedkey"},
	{"snmp-server user U G v3 auth sha-2 256 AUTHPW priv aes 256 PRIVPW", "snmp-server user U G v3 auth sha-2 256 <MASKED:snmp-user-auth> priv aes 256 <MASKED:snmp-user-priv>"},
	{"snmp-server user U G v3 access 10", "snmp-server user U G v3 access 10"},
	// Llaves PEM con sangría.
	{"  -----BEGIN RSA PRIVATE KEY-----\n  MIIE\n  -----END RSA PRIVATE KEY-----\nhostname R1", "<MASKED:private-key>\nhostname R1"},
	{"-----BEGIN PUBLIC KEY-----", "-----BEGIN PUBLIC KEY-----"},
	// enable con algorithm-type.
	{"enable algorithm-type scrypt secret Cl4ve", "enable algorithm-type scrypt secret <MASKED:enable-secret>"},
	{"enable algorithm-type sha256 secret level 5 Cl4ve", "enable algorithm-type sha256 secret level 5 <MASKED:enable-secret>"},
	{"enable password level 5 0 two words", "enable password level 5 0 <MASKED:enable-secret>"},
	{"enable use-tacacs", "enable use-tacacs"},
	// RADIUS, LDAP y SNMP.
	{" dtls key 7 0822455D", " dtls key 7 <MASKED:radius-key>"},
	{" dtls idle-timeout 60", " dtls idle-timeout 60"},
	{" bind authenticate root-dn cn=svc,dc=x password 7 0822", " bind authenticate root-dn cn=svc,dc=x password 7 <MASKED:ldap-password>"},
	{" bind authenticate root-dn cn=svc,dc=x password Cl4ve", " bind authenticate root-dn cn=svc,dc=x password <MASKED:ldap-password>"},
	{" base-dn dc=example,dc=com", " base-dn dc=example,dc=com"},
	{"ldap-server host 10.1.1.1 rootDN \"cn=x,dc=y\" password 7 \"ab cd\" port 389", "ldap-server host 10.1.1.1 rootDN \"cn=x,dc=y\" password 7 <MASKED:ldap-password> port 389"},
	{"ldap-server host 10.1.1.1 rootDN \"cn=x\" password Cl4ve", "ldap-server host 10.1.1.1 rootDN \"cn=x\" password <MASKED:ldap-password>"},
	{"ldap-server host 10.1.1.1 enable-ssl", "ldap-server host 10.1.1.1 enable-ssl"},
	{"snmp mib community-map Cl4ve context CTX1", "snmp mib community-map <MASKED:snmp-community> context CTX1"},
	{"snmp mib persist cbqos", "snmp mib persist cbqos"},
	// VPN y PKI.
	{" authentication local pre-share key 6 ABCDEF", " authentication local pre-share key 6 <MASKED:psk>"},
	{" authentication remote pre-share key Cl4ve", " authentication remote pre-share key <MASKED:psk>"},
	{" authentication local rsa-sig", " authentication local rsa-sig"},
	{"crypto isakmp client configuration group G1\n key 6 ABCDEF\n pool P1", "crypto isakmp client configuration group G1\n key 6 <MASKED:psk>\n pool P1"},
	{"crypto isakmp client configuration group G1\n key Cl4ve", "crypto isakmp client configuration group G1\n key <MASKED:psk>"},
	{"interface Tunnel0\n key 5", "interface Tunnel0\n key 5"},
	{" ip nhrp authentication Cl4ve", " ip nhrp authentication <MASKED:nhrp-key>"},
	{" ipv6 nhrp authentication Cl4ve", " ipv6 nhrp authentication <MASKED:nhrp-key>"},
	{" ip nhrp network-id 1", " ip nhrp network-id 1"},
	{" set session-key inbound esp 256 cipher 0123456789ABCDEF", " set session-key inbound esp 256 cipher <MASKED:ipsec-key>"},
	{" set session-key outbound esp 257 cipher AABB authenticator CCDD", " set session-key outbound esp 257 cipher <MASKED:ipsec-key> authenticator <MASKED:ipsec-key>"},
	{" set session-key inbound ah 300 0123456789ABCDEF", " set session-key inbound ah 300 <MASKED:ipsec-key>"},
	{" set peer 10.1.1.1", " set peer 10.1.1.1"},
	{"crypto pki trustpoint TP\n enrollment url http://ca\n password 7 0822455D\n revocation-check none", "crypto pki trustpoint TP\n enrollment url http://ca\n password 7 <MASKED:pki-password>\n revocation-check none"},
	{"crypto pki trustpoint TP\n password Cl4ve", "crypto pki trustpoint TP\n password <MASKED:pki-password>"},
	{"crypto pki trustpoint TP\n rsakeypair K1", "crypto pki trustpoint TP\n rsakeypair K1"},
	{" database archive pkcs12 password 7 0822455D", " database archive pkcs12 password 7 <MASKED:pki-password>"},
	{" database archive pkcs12 password Cl4ve", " database archive pkcs12 password <MASKED:pki-password>"},
	{" database archive pkcs12", " database archive pkcs12"},
	{"crypto pki import TP pkcs12 flash:x.p12 password Cl4ve", "crypto pki import TP pkcs12 flash:x.p12 password <MASKED:pki-password>"},
	{"crypto pki export TP pkcs12 tftp://10.1.1.1/x.p12 password Cl4ve", "crypto pki export TP pkcs12 tftp://10.1.1.1/x.p12 password <MASKED:pki-password>"},
	{"crypto pki export TP pkcs12 tftp://10.1.1.1/x.p12", "crypto pki export TP pkcs12 tftp://10.1.1.1/x.p12"},
	{"crypto key export rsa K1 pem terminal 3des Cl4ve", "crypto key export rsa K1 pem terminal 3des <MASKED:pki-password>"},
	{"crypto key import rsa K1 pem terminal Cl4ve", "crypto key import rsa K1 pem terminal <MASKED:pki-password>"},
	{"crypto pki export TP pem terminal 3des Cl4ve", "crypto pki export TP pem terminal 3des <MASKED:pki-password>"},
	{"crypto key export rsa K1 pem url flash:k.pem 3des Cl4ve", "crypto key export rsa K1 pem url flash:k.pem 3des <MASKED:pki-password>"},
	{"crypto key export rsa K1 pem terminal 3des", "crypto key export rsa K1 pem terminal 3des"},
	{"crypto key generate rsa label K1 modulus 2048", "crypto key generate rsa label K1 modulus 2048"},
	{"crypto key zeroize rsa K1", "crypto key zeroize rsa K1"},
	{"crypto ca export TP pkcs12 bootflash:x.pfx Cl4ve", "crypto ca export TP pkcs12 bootflash:x.pfx <MASKED:pki-password>"},
	{"crypto ca authenticate TP", "crypto ca authenticate TP"},
	// Enrutamiento y redundancia.
	{" area 1 virtual-link 2.2.2.2 message-digest-key 1 md5 Cl4ve", " area 1 virtual-link 2.2.2.2 message-digest-key 1 md5 <MASKED:ospf-key>"},
	{" area 1 virtual-link 2.2.2.2 message-digest-key 5 md5 7 0822", " area 1 virtual-link 2.2.2.2 message-digest-key 5 md5 7 <MASKED:ospf-key>"},
	{" area 1 virtual-link 2.2.2.2 authentication-key Cl4ve", " area 1 virtual-link 2.2.2.2 authentication-key <MASKED:ospf-key>"},
	{" area 1 virtual-link 2.2.2.2 hello-interval 5", " area 1 virtual-link 2.2.2.2 hello-interval 5"},
	{" ip ospf message-digest-key 5 md5 7 0822", " ip ospf message-digest-key 5 md5 7 <MASKED:ospf-key>"},
	{" ospfv3 1 authentication ipsec spi 256 sha1 0123456789ABCDEF0123456789ABCDEF01234567", " ospfv3 1 authentication ipsec spi 256 sha1 <MASKED:ospf-key>"},
	{" ospfv3 authentication ipsec spi 256 md5 0123456789ABCDEF0123456789ABCDEF", " ospfv3 authentication ipsec spi 256 md5 <MASKED:ospf-key>"},
	{" ospfv3 authentication null", " ospfv3 authentication null"},
	{" ipv6 ospf encryption ipsec spi 257 esp aes-cbc 128 AABBCCDDEEFF00112233445566778899 sha1 0123456789ABCDEF0123456789ABCDEF01234567", " ipv6 ospf encryption ipsec spi 257 esp aes-cbc 128 <MASKED:ospf-key> sha1 <MASKED:ospf-key>"},
	{" ospfv3 encryption ipsec spi 257 esp null sha1 0123456789ABCDEF0123456789ABCDEF01234567", " ospfv3 encryption ipsec spi 257 esp null sha1 <MASKED:ospf-key>"},
	{" ospfv3 encryption null", " ospfv3 encryption null"},
	{"  authentication mode hmac-sha-256 7 0822455D", "  authentication mode hmac-sha-256 7 <MASKED:eigrp-key>"},
	{"  authentication mode hmac-sha-256 Cl4ve", "  authentication mode hmac-sha-256 <MASKED:eigrp-key>"},
	{"  authentication mode md5", "  authentication mode md5"},
	{"  neighbor 10.1.1.1\n    password 3 a667d47acc18ea6b", "  neighbor 10.1.1.1\n    password 3 <MASKED:secret>"},
	{"  neighbor 10.1.1.1 remote-as 65001", "  neighbor 10.1.1.1 remote-as 65001"},
	{" standby authentication Cl4ve", " standby authentication <MASKED:fhrp-key>"},
	{" standby 1 authentication md5 key-chain K1", " standby 1 authentication md5 key-chain K1"},
	{" standby authentication md5 key-string 7 0822", " standby authentication md5 key-string 7 <MASKED:fhrp-key>"},
	{" glbp 1 authentication text Cl4ve", " glbp 1 authentication text <MASKED:fhrp-key>"},
	{" glbp 1 authentication md5 key-chain K1", " glbp 1 authentication md5 key-chain K1"},
	{"    authentication text Cl4ve", "    authentication text <MASKED:fhrp-key>"},
	{"    authentication md5 key-string Cl4ve", "    authentication md5 key-string <MASKED:fhrp-key>"},
	{"    authentication md5 key-string 7 0822455D", "    authentication md5 key-string 7 <MASKED:fhrp-key>"},
	{"    authentication md5 key-chain K1", "    authentication md5 key-chain K1"},
	{" area-password Cl4ve", " area-password <MASKED:isis-password>"},
	{" isis password Cl4ve level-1", " isis password <MASKED:isis-password> level-1"},
	{" isis password 7 0822 level-2", " isis password 7 <MASKED:isis-password> level-2"},
	{" isis authentication mode md5", " isis authentication mode md5"},
	{"mpls ldp neighbor vrf V 10.0.0.2 password 7 0822", "mpls ldp neighbor vrf V 10.0.0.2 password 7 <MASKED:ldp-password>"},
	{"mpls ldp password fallback 7 0822", "mpls ldp password fallback 7 <MASKED:ldp-password>"},
	{"mpls ldp password fallback Cl4ve", "mpls ldp password fallback <MASKED:ldp-password>"},
	{"mpls ldp password required", "mpls ldp password required"},
	{"mpls ldp password option 1 for ACL1", "mpls ldp password option 1 for ACL1"},
	{"ip msdp password peer 1.1.1.1 7 0822", "ip msdp password peer 1.1.1.1 7 <MASKED:msdp-password>"},
	{"ip msdp password peer 1.1.1.1 Cl4ve", "ip msdp password peer 1.1.1.1 <MASKED:msdp-password>"},
	{"ip msdp password 1.1.1.1 3 a667d47a", "ip msdp password 1.1.1.1 3 <MASKED:msdp-password>"},
	{"ip msdp peer 1.1.1.1 connect-source Lo0", "ip msdp peer 1.1.1.1 connect-source Lo0"},
	{"  ip pim hello-authentication ah-md5 3 a667d47a", "  ip pim hello-authentication ah-md5 3 <MASKED:pim-key>"},
	{"  bfd authentication keyed-sha1 key-id 1 key Cl4ve", "  bfd authentication keyed-sha1 key-id 1 key <MASKED:bfd-key>"},
	{"  bfd authentication keyed-sha1 key-id 1 hex-key 0123ABCD", "  bfd authentication keyed-sha1 key-id 1 hex-key <MASKED:bfd-key>"},
	{"  bfd interval 50 min_rx 50 multiplier 3", "  bfd interval 50 min_rx 50 multiplier 3"},
	{" ip ospf authentication key-chain K1", " ip ospf authentication key-chain K1"},
	// TrustSec, MACsec y otros.
	{"cts credentials id SW1 password Cl4ve", "cts credentials id SW1 password <MASKED:cts-key>"},
	{"cts credentials id SW1 password 7 0822", "cts credentials id SW1 password 7 <MASKED:cts-key>"},
	{"cts sxp default password 7 0822", "cts sxp default password 7 <MASKED:cts-key>"},
	{"cts sxp default password Cl4ve", "cts sxp default password <MASKED:cts-key>"},
	{"cts sxp default password default", "cts sxp default password default"},
	{"cts sxp connection peer 10.1.1.1 password default mode local", "cts sxp connection peer 10.1.1.1 password default mode local"},
	{"cts sxp connection peer 10.1.1.1 password none mode local", "cts sxp connection peer 10.1.1.1 password none mode local"},
	{"cts device-id SW1 password 7 0822", "cts device-id SW1 password 7 <MASKED:cts-key>"},
	{"cts role-based enforcement", "cts role-based enforcement"},
	{"  sap pmk 0123456789ABCDEF0123456789ABCDEF mode-list gcm-encrypt", "  sap pmk <MASKED:macsec-key> mode-list gcm-encrypt"},
	{"  sap mode-list gcm-encrypt", "  sap mode-list gcm-encrypt"},
	{"    key-octet-string 7 0822455D cryptographic-algorithm aes-128-cmac", "    key-octet-string 7 <MASKED:macsec-key> cryptographic-algorithm aes-128-cmac"},
	{"    key-octet-string Cl4ve cryptographic-algorithm aes-128-cmac", "    key-octet-string <MASKED:macsec-key> cryptographic-algorithm aes-128-cmac"},
	{"  key 1", "  key 1"},
	{"ip wccp 61 password 7 0822", "ip wccp 61 password 7 <MASKED:wccp-password>"},
	{"ip wccp web-cache password Cl4ve", "ip wccp web-cache password <MASKED:wccp-password>"},
	{"ip wccp 61 redirect-list ACL1", "ip wccp 61 redirect-list ACL1"},
	{"vtp password Cl4ve", "vtp password <MASKED:vtp-password>"},
	{"vtp password Cl4ve hidden", "vtp password <MASKED:vtp-password> hidden"},
	{"vtp mode transparent", "vtp mode transparent"},
	{"key config-key 1 Cl4ve", "key config-key 1 <MASKED:config-key>"},
	{"key chain K1", "key chain K1"},
	// Catalyst 9800 y EWC.
	{" mgmtuser username U password 8 $8$abc secret 8 $8$def", " mgmtuser username U password 8 <MASKED:user-secret> secret 8 <MASKED:user-secret>"},
	{" dot1x username U password 8 $8$abc eap-type peap", " dot1x username U password 8 <MASKED:dot1x-password> eap-type peap"},
	{" dot1x username U password Cl4ve", " dot1x username U password <MASKED:dot1x-password>"},
	{" dot1x system-auth-control", " dot1x system-auth-control"},
	{"user-name admin\n password 8 $8$abc", "user-name admin\n password 8 <MASKED:user-secret>"},
	{"user-name admin\n password 0 Cl4ve\n type network-user", "user-name admin\n password 0 <MASKED:user-secret>\n type network-user"},
	{"user-name admin\n description password 0 x", "user-name admin\n description password 0 x"},
	{" psk key 8 $8$abc", " psk key 8 <MASKED:wifi-psk>"},
	{" psk key Cl4ve", " psk key <MASKED:wifi-psk>"},
	{" mpsk-key 0 priority 0 set-key ascii 0 Cl4ve", " mpsk-key 0 priority 0 set-key ascii 0 <MASKED:wifi-psk>"},
	{" mpsk-key 0 priority 0 set-key ascii Cl4ve", " mpsk-key 0 priority 0 set-key ascii <MASKED:wifi-psk>"},
	{" mpsk-key 0 priority 1 name x", " mpsk-key 0 priority 1 name x"},
	{"wireless ewc-ap ap shell username U password 0 Cl4ve secret 0 Otra", "wireless ewc-ap ap shell username U password 0 <MASKED:user-secret> secret 0 <MASKED:user-secret>"},
	{"wireless ewc-ap ap shell username U password Cl4ve secret Otra", "wireless ewc-ap ap shell username U password <MASKED:user-secret> secret <MASKED:user-secret>"},
	{"wireless ewc-ap ap-image preload", "wireless ewc-ap ap-image preload"},
	// Tokens y licencias.
	{"parameter-map type umbrella global\n token ABCD1234\n dnscrypt", "parameter-map type umbrella global\n token <MASKED:token>\n dnscrypt"},
	{"parameter-map type umbrella global\n api-key 7 0822 secret 7 0833", "parameter-map type umbrella global\n api-key 7 <MASKED:token> secret 7 <MASKED:token>"},
	{"parameter-map type umbrella global\n api-key ABCD secret EFGH", "parameter-map type umbrella global\n api-key <MASKED:token> secret <MASKED:token>"},
	{"parameter-map type inspect global\n token ok", "parameter-map type inspect global\n token ok"},
	{"license smart trust idtoken TOKEN123 local", "license smart trust idtoken <MASKED:token> local"},
	{"license smart register idtoken TOKEN123 force", "license smart register idtoken <MASKED:token> force"},
	{"license smart enable", "license smart enable"},
	// URL con credenciales, en cualquier línea.
	{" path scp://admin:Cl4ve@10.1.1.1/cfg", " path scp://admin:<MASKED:url-password>@10.1.1.1/cfg"},
	{"copy running-config scp://u:Cl4ve@h/", "copy running-config scp://u:<MASKED:url-password>@h/"},
	{"cli copy running-config ftp://u:Cl4ve@h/x", "cli copy running-config ftp://u:<MASKED:url-password>@h/x"},
	{"%PARSER-5-CFGLOG_LOGGEDCMD: User:a  logged command:copy tftp://u:Cl4ve@10.1.1.1/x flash:", "%PARSER-5-CFGLOG_LOGGEDCMD: User:a  logged command:copy tftp://u:<MASKED:url-password>@10.1.1.1/x flash:"},
	{"boot system ftp://u:p@ss@h/img.bin", "boot system ftp://u:<MASKED:url-password>@h/img.bin"},
	{" path scp://admin@10.1.1.1/cfg", " path scp://admin@10.1.1.1/cfg"},
	{" path tftp://10.1.1.1:69/cfg", " path tftp://10.1.1.1:69/cfg"},
	{" description backup scp://u:Cl4ve@h/", " description backup scp://u:Cl4ve@h/"},
	// Salidas de show.
	{"Community name: MARKER", "Community name: <MASKED:snmp-community>"},
	{"Pre-shared key (local): Cl4ve", "Pre-shared key (local): <MASKED:psk>"},
	{"Pre-shared key (remote): two words", "Pre-shared key (remote): <MASKED:psk>"},
	{"Pre-shared key authentication enabled", "Pre-shared key authentication enabled"},
	{"      key 1 -- text \"Cl4ve\"", "      key 1 -- text <MASKED:key-string>"},
	{"      Key 1 -- text 7 \"Cl4ve\"", "      Key 1 -- text 7 <MASKED:key-string>"},
	{"      key 1 -- text \"ab cd\"", "      key 1 -- text <MASKED:key-string>"},
	{"      key 1 -- accept lifetime (always valid)", "      key 1 -- accept lifetime (always valid)"},
	{"    Authentication text, string \"Cl4ve\"", "    Authentication text, string <MASKED:fhrp-key>"},
	{"    Authentication MD5, key-chain \"K1\"", "    Authentication MD5, key-chain \"K1\""},
	{"VTP Password: Cl4ve", "VTP Password: <MASKED:vtp-password>"},
	{"VTP Password:", "VTP Password:"},
	{"The VTP password is not configured.", "The VTP password is not configured."},
	{"PAC-Opaque: 000200B00003", "PAC-Opaque: <MASKED:cts-pac>"},
	{"PAC-Info: Valid until", "PAC-Info: Valid until"},
	{"Mgmt Password : Cl4ve", "Mgmt Password : <MASKED:user-secret>"},
	{"Mgmt Secret   : Cl4ve", "Mgmt Secret   : <MASKED:user-secret>"},
	{"Dot1x Password : Cl4ve", "Dot1x Password : <MASKED:dot1x-password>"},
	{"Mgmt User Name : admin", "Mgmt User Name : admin"},
	{"PSK : Cl4ve", "PSK : <MASKED:wifi-psk>"},
	{"PSK : Enabled", "PSK : Enabled"},
	// show archive log config: tras «|» va una línea de configuración.
	{"  1  1  admin@vty0  |username bob privilege 15 secret Cl4ve", "  1  1  admin@vty0  |username bob privilege 15 secret <MASKED:user-secret>"},
	{"  2  1  admin@vty0  |snmp-server community Cl4ve RO", "  2  1  admin@vty0  |snmp-server community <MASKED:snmp-community> RO"},
	{"  3  1  admin@vty0  |interface Gi1", "  3  1  admin@vty0  |interface Gi1"},
	{"  3  1  admin@vty0  |description password 0 x", "  3  1  admin@vty0  |description password 0 x"},
	// Forma genérica: tipos 3 y 4, y palabras clave que no son valor.
	{" algo password 3 a667d47acc18ea6b", " algo password 3 <MASKED:secret>"},
	{" algo secret 4 abcdef", " algo secret 4 <MASKED:secret>"},
	{" ip ospf message-digest-key 5 md5 7 0822", " ip ospf message-digest-key 5 md5 7 <MASKED:ospf-key>"},
	{"ntp authentication-key 7 md5 0822455D 7", "ntp authentication-key 7 md5 <MASKED:ntp-key> 7"},
	{"ntp server 10.1.1.1 key 5 prefer", "ntp server 10.1.1.1 key 5 prefer"},
	{"ntp server 10.1.1.1 key 5 use-vrf management", "ntp server 10.1.1.1 key 5 use-vrf management"},
	{"ntp server vrf X 10.1.1.1 key 5 iburst", "ntp server vrf X 10.1.1.1 key 5 iburst"},
	{" foo key 6 ABC priority 1", " foo key 6 <MASKED:secret> priority 1"},
	{" foo password 0 alpha beta key 7 0822", " foo password 0 <MASKED:secret> key 7 <MASKED:secret>"},
	{" foo password 7 default", " foo password 7 default"},
	{"ip ssh pubkey-chain\n username u\n  key-hash ssh-rsa AABBCC u", "ip ssh pubkey-chain\n username u\n  key-hash ssh-rsa AABBCC u"},
	{"password encryption aes", "password encryption aes"},
	{" tunnel key 5", " tunnel key 5"},
	{"Authentication methods: publickey,keyboard-interactive,password", "Authentication methods: publickey,keyboard-interactive,password"},
	{"show crypto key mypubkey rsa", "show crypto key mypubkey rsa"},
	{"User: monitor\n security model: v3 priv", "User: monitor\n security model: v3 priv"},
	{" description password 0 two words", " description password 0 two words"},
	{" 10 remark key 7 0822", " 10 remark key 7 0822"},
	// Segunda pasada: syslog, palabras con guion, EzVPN cliente, OSPFv3 por área, l2tp, URL con «/» y pares tras tipo 0.
	{"%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:username bob secret Cl4ve", "%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:username bob secret <MASKED:user-secret>"},
	{"%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:snmp-server community Cl4ve RO", "%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:snmp-server community <MASKED:snmp-community> RO"},
	{"%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:tacacs-server key Cl4ve", "%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:tacacs-server key <MASKED:tacacs-key>"},
	{"%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:interface Gi1", "%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:interface Gi1"},
	{" local-key 0 Cl4ve", " local-key 0 <MASKED:secret>"},
	{" pac-password 0 Cl4ve", " pac-password 0 <MASKED:secret>"},
	{" monkey 5 abc", " monkey 5 abc"},
	{" group G1 key Cl4ve", " group G1 key <MASKED:psk>"},
	{" group 14", " group 14"},
	{" area 0 authentication ipsec spi 256 sha1 0123456789ABCDEF0123456789ABCDEF01234567", " area 0 authentication ipsec spi 256 sha1 <MASKED:ospf-key>"},
	{" area 0 encryption ipsec spi 256 esp aes-cbc 128 AABBCCDDEEFF00112233445566778899 sha1 0123456789ABCDEF0123456789ABCDEF01234567", " area 0 encryption ipsec spi 256 esp aes-cbc 128 <MASKED:ospf-key> sha1 <MASKED:ospf-key>"},
	{" area 1 virtual-link 2.2.2.2 authentication ipsec spi 256 md5 0123456789ABCDEF0123456789ABCDEF", " area 1 virtual-link 2.2.2.2 authentication ipsec spi 256 md5 <MASKED:ospf-key>"},
	{" area 0 authentication message-digest", " area 0 authentication message-digest"},
	{" area 0 encryption disable", " area 0 encryption disable"},
	{" l2tp tunnel password Cl4ve", " l2tp tunnel password <MASKED:l2tp-password>"},
	{" l2tp tunnel timeout 30", " l2tp tunnel timeout 30"},
	{"ap dot1x username u password Cl4ve", "ap dot1x username u password <MASKED:dot1x-password>"},
	{"ap dot1x max-sessions 5", "ap dot1x max-sessions 5"},
	{" path scp://u:Cl4/ve@h/x", " path scp://u:<MASKED:url-password>@h/x"},
	{"crypto isakmp key 0 Cl4ve address 0.0.0.0", "crypto isakmp key 0 <MASKED:psk> address 0.0.0.0"},
	{"crypto isakmp key 0 Cl4ve hostname peer.example no-xauth", "crypto isakmp key 0 <MASKED:psk> hostname peer.example no-xauth"},
	{"crypto isakmp key 0 two words address 10.0.0.1 no-xauth", "crypto isakmp key 0 <MASKED:psk> address 10.0.0.1 no-xauth"},
}

func applyOnce(in string) string {
	got, _ := Apply("ios-xe", in+"\n")
	return strings.TrimSuffix(got, "\n")
}

func TestHuecosDeLasAuditorias(t *testing.T) {
	for _, c := range huecoCases {
		if got := applyOnce(c.in); got != c.want {
			t.Errorf("Apply(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

// Idempotencia: aplicar dos veces da lo mismo que una; y lo ya enmascarado no se vuelve a contar.
func TestHuecosIdempotentes(t *testing.T) {
	for _, c := range huecoCases {
		once, n1 := Apply("ios-xe", c.in+"\n")
		twice, n2 := Apply("ios-xe", once)
		if once != twice {
			t.Errorf("no idempotente %q: %q → %q", c.in, once, twice)
		}
		if len(n2) != 0 {
			t.Errorf("recontó %q: primera %v, segunda %v", c.in, n1, n2)
		}
	}
}

// Una línea suelta nunca debe cambiar su cuenta según el tamaño del trozo: cada caso también pasa por Stream.
func TestHuecosPorStream(t *testing.T) {
	for _, c := range huecoCases {
		st := Stream{}
		var out strings.Builder
		for _, l := range strings.SplitAfter(c.in+"\n", "\n") {
			if o, ok := st.Line(l); ok {
				out.WriteString(o)
			}
		}
		if out.String() != c.want+"\n" {
			t.Errorf("Stream(%q) = %q, want %q", c.in, out.String(), c.want)
		}
	}
}

// Tablas de NX-OS: se cierran con Prompted, con una línea sin forma de fila, con línea en blanco o con separador, y
// sus filas también pasan por maskLine.
func TestTablasSNMPSeCierran(t *testing.T) {
	head := "Community            Group / Access      context    acl_filter\n---------            --------------      -------    ----------\n"
	row := "MARKER-RO            network-operator\n"
	hhead := "Host                            Port Version  Level  Type   SecName\n-------------------------------------------------------------------\n"
	hrow := "10.1.1.1                        162  v2c      noauth trap   MARKER-HOST\n"
	run := func(lines ...string) (string, map[string]int) {
		st := Stream{}
		var out strings.Builder
		for _, l := range lines {
			if strings.HasPrefix(l, "PROMPT:") {
				out.WriteString(st.Prompted(strings.TrimPrefix(l, "PROMPT:"), "") + "\n")
				continue
			}
			if o, ok := st.Line(l); ok {
				out.WriteString(o)
			}
		}
		return out.String(), st.counts
	}
	// Prompted cierra la tabla: la línea tecleada pasa por las reglas y no pierde su primera palabra.
	for _, h := range [][2]string{{head, row}, {hhead, hrow}} {
		got, _ := run(h[0], h[1], "PROMPT:username admin password 5 $5$HASH role network-admin")
		if !strings.Contains(got, "username admin password 5 <MASKED:user-secret> role network-admin") {
			t.Errorf("Prompted no cerró la tabla:\n%s", got)
		}
		if strings.Contains(got, "MARKER") {
			t.Errorf("fila en claro:\n%s", got)
		}
	}
	// Tras el prompt la tabla ya no está abierta: una palabra suelta de la salida siguiente no se toma por comunidad.
	for _, h := range [][2]string{{head, row}, {hhead, hrow}} {
		got, _ := run(h[0], h[1], "PROMPT:show version", "palabra-suelta\n")
		if !strings.Contains(got, "palabra-suelta") {
			t.Errorf("la tabla siguió abierta tras Prompted:\n%s", got)
		}
	}
	// Las filas pasan por maskLine (aquí una fila v3 cuyo SecName trae una URL con clave).
	if got, _ := run(hhead, "10.1.1.2                        162  v3       priv   trap   scp://u:Cl4ve@h/x\n"); strings.Contains(got, "Cl4ve") {
		t.Errorf("la fila no pasó por maskLine:\n%s", got)
	}
	// Una línea sin forma de fila cierra la tabla y sigue por las reglas.
	for _, l := range []string{"Cisco Nexus Operating System (NX-OS) Software\n", "switch# show run\n"} {
		got, _ := run(head, row, l, "username admin password 5 HASH role x\n")
		if !strings.Contains(got, l) || !strings.Contains(got, "username admin password 5 <MASKED:user-secret> role x") {
			t.Errorf("la línea %q no cerró la tabla:\n%s", l, got)
		}
	}
	for _, l := range []string{"Cisco Nexus Operating System\n", "Eth1/1 up\n"} {
		got, _ := run(hhead, hrow, l, "snmp-server community Cl4ve RO\n")
		if !strings.Contains(got, l) || strings.Contains(got, "Cl4ve") {
			t.Errorf("la tabla de hosts no se cerró con %q:\n%s", l, got)
		}
	}
	// Una fila desalineada o separada por tab sigue siendo fila: la comunidad es la 1.ª columna.
	for _, r := range []string{"MARKER-X network-operator\n", "MARKER-X\tnetwork-operator\n", "MARKER-X\n"} {
		if got, _ := run(head, row, r); strings.Contains(got, "MARKER-X") {
			t.Errorf("fila %q en claro:\n%s", r, got)
		}
	}
	// Tabla de hosts con varios hosts separados por líneas «Use VRF:» y separadores: todos se tapan.
	hosts := []string{hhead, hrow, "    Use VRF: management\n", "    Source interface: Lo0\n", "-------------------------------------------------------------------\n",
		"10.1.1.2                        162  v2c      noauth trap   MARKER-H2\n", "    Notification type: trap\n",
		"10.1.1.3                        162  v1       noauth trap   MARKER-H3\n", "\n", "10.1.1.4 x\n"}
	if got, c := run(hosts...); strings.Contains(got, "MARKER") || c["snmp-community"] != 3 || !strings.Contains(got, "Use VRF: management") || !strings.Contains(got, "10.1.1.4 x") {
		t.Errorf("hosts (%v):\n%s", c, got)
	}
	// En blanco o separador (con filas ya vistas) cierra; las filas pasan por maskLine.
	for _, sep := range []string{"\n", "-----------\n"} {
		got, _ := run(head, row, sep, "snmp-server community Cl4ve RO\n")
		if strings.Contains(got, "Cl4ve") || strings.Contains(got, "MARKER-RO") {
			t.Errorf("tras %q:\n%s", sep, got)
		}
	}
	got, _ := run(head, "MARKER-RO            network-operator\n", "foo-extra\n")
	if strings.Contains(got, "MARKER-RO") {
		t.Errorf("fila en claro:\n%s", got)
	}
	// Las filas pasan por maskLine: una fila con forma de config también se tapa.
	got, _ = run(head, "snmp-server community Cl4ve RO\n")
	if strings.Contains(got, "Cl4ve") {
		t.Errorf("la fila no pasó por maskLine:\n%s", got)
	}
	// Una línea tras la tabla que no es de la tabla no pierde su primera palabra.
	got, _ = run(hhead, hrow, "\n", "Importante: nada\n")
	if !strings.Contains(got, "Importante: nada") {
		t.Errorf("tapó de más:\n%s", got)
	}
}

// show crypto isakmp key: tabla con la PSK en la última columna (llega hasta el fin de línea).
func TestTablaIsakmpKey(t *testing.T) {
	in := "Keyring      Hostname/Address                            Preshared Key\n\n" +
		"default      10.1.1.1                                    Cl4ve\n" +
		"default      10.1.1.2/255.255.255.255                    two words\n" +
		"\nhostname R1\n"
	got, counts := Apply("ios", in)
	if strings.Contains(got, "Cl4ve") || strings.Contains(got, "words") || counts["psk"] != 2 || !strings.Contains(got, "hostname R1") {
		t.Errorf("%v\n%s", counts, got)
	}
	if again, _ := Apply("ios", got); again != got {
		t.Errorf("no idempotente:\n%s", again)
	}
}
