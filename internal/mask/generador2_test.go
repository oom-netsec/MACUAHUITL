package mask_test

import (
	"fmt"
	"strings"
	"testing"
)

// Segundo generador, independiente del de canales_test.go: otras plantillas (abreviaturas de toda clase, primeras
// palabras que ninguna lista conoce, « ; », sha256 y peer) y otros valores (con comillas, apóstrofos, barras y
// espacios). {1} y {2} son valores distintos. La plantilla elige su plataforma con el prefijo «plat|».
var gen2Plantillas = strings.Split(strings.TrimSpace(`
ios|enable secret {1}
ios|ena sec {1}
ios|en sec 5 {1}
ios|enab pass {1}
ios|enable pass lev 15 {1}
ios|enable algorithm-type sha256 secret {1}
ios|ena algo scrypt sec {1}
ios|username u sec {1}
ios|user u pass {1}
ios|usern u priv 15 sec 9 {1}
ios|username u privilege 15 password 0 {1}
ios|username u password 7 {1}
ios|username u view V secret 5 {1}
ios|username u pass {1} sec 0 {2}
ios|username u algorithm-type sha256 secret {1}
ios|snmp-s comm {1} RO
ios|snmp comm {1} RW 10
ios|snmp-server community {1} view V RO
ios|snmp-s ho 10.1.1.1 {1}
ios|snmp-s ho 10.1.1.1 vrf M inf ver 2c {1}
ios|snmp-server host 10.1.1.1 traps version 2c {1} udp-port 162
ios|snmp-s us u g v3 auth sha {1} priv aes 128 {2}
ios|snmp-server user u g v3 auth sha256 {1}
ios|snmp-s us u g v3 auth md5 {1} priv des {2} acc 10
ios|snmp-server user u g remote 10.1.1.1 v3 enc auth sha {1} priv aes 256 {2}
ios|ntp authentication-key 5 md5 {1}
ios|ntp auth-key 5 sha256 {1}
ios|ntp authentication-key 5 sha1 {1} 7
ios|ntp au 5 md5 {1}
ios|sntp authentication-key 5 md5 {1}
ios|sntp auth-key 5 sha256 {1}
ios|ip ospf authentication-key {1}
ios|ip ospf auth-key {1}
ios|ip ospf message-digest-key 1 md5 {1}
ios|ip os mes 1 md5 7 {1}
ios|ip ospf message-digest-key 3 sha256 {1}
ios|ip rip authentication key-chain K
ios|area 0 virtual-link 1.1.1.1 message-digest-key 1 md5 {1}
ios|crypto isakmp key {1} address 1.1.1.1
ios|cry isa key 6 {1} add 1.1.1.1 255.0.0.0
ios|cry isakmp key {1} hostname H
ios|crypto keyring KR ; pre-shared-key address 1.1.1.1 key {1}
ios|crypto keyring KR ; pre-sh hostname H key 0 {1}
ios|crypto ikev2 keyring KR ; peer P ; pre-shared-key local {1} remote {2}
ios|crypto ikev2 keyring KR ; peer P ; pre-shared-key remote {1}
ios|crypto ikev2 keyring KR ; peer P ; pre local {1}
ios|tacacs-server key {1}
ios|tacacs-s k {1}
ios|tacacs-server host 10.1.1.1 key 7 {1}
ios|tacacs-ser ho 10.1.1.1 ke 0 {1} timeout 5
ios|tacacs server T ; key {1}
ios|tacacs server T ; k 7 {1}
ios|radius-server key {1}
ios|radius-s ho 1.1.1.1 auth-port 1812 key {1}
ios|radius server R ; key 0 {1}
ios|radius server R ; pac key {1}
ios|aaa group server radius G ; key {1}
ios|standby 1 authentication text {1}
ios|stan 1 auth text {1}
ios|standby 1 authentication md5 key-string {1}
ios|vrrp 1 authentication text {1}
ios|glbp 1 auth text {1}
ios|key chain K ; key 1 ; key-string {1}
ios|key chain K ; key 1 ; key-s 7 {1}
ios|key-string 0 {1}
ios|area-password {1}
ios|area-p {1}
ios|domain-password {1}
ios|isis password {1} level-1
ios|isis pass {1}
ios|wpa-psk ascii {1}
ios|wpa-psk ascii 0 {1}
ios|license smart register idtoken {1}
ios|license smart reg idt {1} force
ios|crypto pki export TP pem url scp://u:{1}@1.1.1.1/tp 3des password {2}
ios|cry pki exp TP pem url ftp://u:{1}@1.1.1.1/tp aes pass {2}
ios|crypto pki import TP pkcs12 ftp://u:{1}@1.1.1.1/f password {2}
ios|crypto key export rsa K pem url ftp://u:{1}@1.1.1.1/k 3des {2}
ios|crypto ca import TP pkcs12 flash:t.p12 {1}
ios|vpdn-group G ; l2tp tunnel password {1}
ios|vpdn-group G ; l2tp tun pass {1}
ios|vpdn-g G ; l2 tunnel pass 7 {1}
ios|l2tp-class C ; password {1}
ios|l2tp-class C ; pass 0 {1}
ios|smtp-server 1.1.1.1 password {1}
ios|smtp-server 1.1.1.1 user u password {1}
ios|smtp-ser 1.1.1.1 pass {1}
ios|macsec ; key-string {1}
ios|macsec-key-chain KC ; key 01 ; cryptographic-algorithm aes-128-cmac ; key-string {1}
ios|key 01 ; key-string 7 {1}
ios|lisp ; password {1}
ios|lisp site S ; authentication-key {1}
ios|lisp site S ; authentication-key 7 {1}
ios|site S ; authentication-key {1}
ios|site S ; auth-key {1}
ios|repository R ; url ftp://u:{1}@1.1.1.1/r
ios|repository R ; user u password plain {1}
ios|repo R ; user u pass {1}
ios|webauth ; password {1}
ios|webauth ; pass {1}
ios|dialer ; ppp chap password {1}
ios|dialer ; ppp chap pass 7 {1}
ios|dial ; ppp pap sent-username u password {1}
ios|ppp chap password {1}
ios|ppp pap sent-username u password 0 {1}
ios|group-policy G attributes ; password {1}
ios|group-pol G ; pass {1}
ios|vtp password {1}
ios|vtp pass {1} hidden
ios|cts credentials id X password {1}
ios|cts sxp default password {1}
ios|cts sxp connection peer 1.1.1.1 password {1}
ios|cts sxp conn peer 1.1.1.1 pass {1} mode local
ios|ip nhrp authentication {1}
ios|neighbor 1.1.1.1 password {1}
ios|nei 1.1.1.1 pass 7 {1}
ios|neighbor 1.1.1.1 password {1}
ios|ip msdp password peer 1.1.1.1 {1}
ios|ip msdp pass peer 1.1.1.1 {1}
ios|mpls ldp password fallback {1}
ios|mpls ldp neighbor 1.1.1.1 password {1}
ios|ip pim hello-authentication ah-md5 {1}
ios|ip ftp password {1}
ios|ip ftp pass 7 {1}
ios|ip http client password {1}
ios|ip http client proxy-server px proxy-port 80 password {1}
ios|api-key {1}
ios|api-key A secret {1}
ios|key config-key password-encrypt {1}
ios|key con pass-e {1}
ios|eigrp authentication key eigrp 1 {1} key-id 1
ios|bind authenticate root-dn cn=x password {1}
ios|ldap-server host 1.1.1.1 rootDN cn=x password {1}
ios|server-key {1}
ios|pac key {1}
ios|set session-key inbound esp 256 cipher {1}
ios|mgmtuser username admin pass 0 {1} secret 0 {2}
ios|wireless ewc-ap ap-management username U pass {1} secret 0 {2}
ios|pre-shared-key {1}
ios|pre-shared-key local {1}
ios|psk {1}
ios|ps 7 {1}
ios|license smart register token {1}
ios|passphrase {1}
ios|pass 0 {1}
ios|passw {1}
ios|auth {1}
ios|authentication-key {1}
ios|authentication key-chain K ; key 1 ; key-string {1}
ios|text {1}
ios|authentication text {1}
ios|aut text {1}
ios|show run ; enable secret {1}
ios|no enable secret {1}
ios|no username u secret {1}
ios|no snmp-server community {1} RO
ios|do configure terminal ; enable secret {1}
ios|enable secret 5 $1${1}$abc
nx-os|username admin password 5 {1} role network-admin
nx-os|username admin pass {1} role network-operator
nx-os|user admin pass {1}
nx-os|snmp-server community {1} group network-operator
nx-os|snmp-s comm {1} ro
nx-os|snmp-server user u network-admin auth md5 {1} priv {2} localizedkey
nx-os|snmp-s us u auth sha {1} priv aes-128 {2}
nx-os|tacacs-server key 7 {1}
nx-os|tacacs-server host 1.1.1.1 key 0 {1} timeout 5
nx-os|radius-server key {1}
nx-os|radius-s ho 1.1.1.1 key {1} authentication
nx-os|key chain K ; key 1 ; key-string 0 {1}
nx-os|key chain K ; key 1 ; key-s {1}
nx-os|ntp authentication-key 1 md5 {1}
nx-os|ntp authentication-key 1 sha256 {1}
nx-os|ntp peer 1.1.1.1 ; ntp authentication-key 2 md5 {1}
nx-os|ntp server 1.1.1.1 key 2 ; ntp authentication-key 2 md5 {1}
nx-os|ip ospf authentication-key 3 {1}
nx-os|ip ospf message-digest-key 1 md5 3 {1}
nx-os|snmp-server community {1} ro ; username u password 5 {2} role network-admin
nx-os|feature tacacs+ ; tacacs-server key {1}
nx-os|line vty ; password {1}
nx-os|configure terminal ; interface Eth1/1 ; ip ospf authentication-key {1}
nx-os|feature bgp ; router bgp 1 ; neighbor 1.1.1.1 ; password 3 {1}
asa|enable password {1} encrypted
asa|ena pass {1}
asa|passwd {1} encrypted
asa|username u password {1} privilege 15
asa|username u pass {1} pbkdf2
asa|snmp-server host inside 10.1.1.1 community {1}
asa|snmp-s ho inside 10.1.1.1 trap comm {1} version 2c
asa|snmp-server community {1}
asa|aaa-server X (inside) host 1.1.1.1 ; key {1}
asa|aaa-server X (inside) host 1.1.1.1 ; ke {1}
asa|failover key {1}
asa|failover key hex {1}
asa|failover ipsec pre-shared-key {1}
asa|tunnel-group G ipsec-attributes ; ikev1 pre-shared-key {1}
asa|tunnel-group G ipsec-attributes ; ikev2 remote-authentication pre-shared-key {1}
asa|tunnel-group G ipsec-attributes ; ikev2 local-authentication pre-sh {1}
asa|tunnel-group G ipsec-attributes ; peer-id-validate nocheck ; pre-shared-key {1}
asa|ldap-login-password {1}
asa|radius-common-pw {1}
asa|crypto ca export TP pkcs12 {1}
asa|ospf authentication-key {1}
asa|ospf message-digest-key 1 md5 {1}
asa|webvpn ; group-policy G attributes ; password {1}
asa|crypto isakmp key {1} address 1.1.1.1
ftd|configure manager add 10.1.1.1 {1} {2}
ftd|configure user add u {1}
wlc-aireos|config mgmtuser password admin2 {1}
wlc-aireos|config snmp community create {1}
wlc-aireos|config wlan security wpa akm psk set-key ascii {1} 3
wlc-aireos|config ap mgmtuser add username apadmin password {1} secret {2} all
wlc-aireos|config radius auth add 1 1.1.1.1 1812 ascii {1}
ise|username admin password hash {1} role admin
ise|username jdoe password plain {1} role user
ise|snmp-server community {1} ro
`), "\n")

// gen2Valor: el valor de la plantilla n con un estilo que depende del caso (y de la variante k).
func gen2Valor(n, k int) string {
	m := fmt.Sprintf("Zq%05d", n*10+k)
	switch (n + k*3) % 10 {
	case 0:
		return m
	case 1:
		return "P@$$-" + m + "!"
	case 2:
		return `a\` + m + `\b`
	case 3:
		return "it's-" + m
	case 4:
		return `x"` + m
	case 5:
		return m + "'"
	case 6:
		return `"` + m + ` dos palabras"`
	case 7:
		return "(" + m + ")"
	case 8:
		return `"` + m + `"`
	}
	return m + `\`
}

// gen2Casos: cada plantilla con 3 estilos de valor distintos.
func gen2Casos() (cmds, plats []string) {
	for i, l := range gen2Plantillas {
		plat, tpl, _ := strings.Cut(l, "|")
		for v := 0; v < 3; v++ {
			if raceOn && v > 0 { // ver raceOn: con -race, un estilo de valor por plantilla
				continue
			}
			v1 := gen2Valor(i*3+v, 1)
			if strings.Contains(tpl, "://") && strings.ContainsAny(v1, `" `) { // la clave de una URL no lleva comillas ni espacios
				v1 = fmt.Sprintf("Zq%05d", (i*3+v)*10+1)
			}
			c := strings.ReplaceAll(strings.ReplaceAll(tpl, "{1}", v1), "{2}", gen2Valor(i*3+v, 2))
			cmds, plats = append(cmds, c), append(plats, platDe(plat))
		}
	}
	return
}

func TestGenerador2Cantidad(t *testing.T) {
	if len(gen2Plantillas) < 170 {
		t.Fatalf("faltan plantillas: %d", len(gen2Plantillas))
	}
	if len(vias) < 18 {
		t.Fatalf("faltan vías: %d", len(vias))
	}
}

// (b) ningún valor visible en ninguna vía.
func TestGenerador2NingunSecretoSeVe(t *testing.T) {
	cmds, plats := gen2Casos()
	malos := map[string]int{}
	n := 0
	for i, c := range cmds {
		ms := marcas(c)
		for _, v := range vias {
			if sueltas[v.nombre] {
				continue
			}
			out := v.f(nuevo, plats[i], c)
			for m := range ms {
				if strings.Contains(out, m) {
					malos[v.nombre]++
					if n++; n <= 40 {
						t.Errorf("[%s] (%s)\n  entrada: %q\n  salida:  %q", v.nombre, plats[i], c, strings.TrimSpace(out))
					}
					break
				}
			}
		}
	}
	for k, v := range malos {
		t.Errorf("vía %s: %d fugas", k, v)
	}
}

func platDe(p string) string {
	if p == "ios" {
		return "ios-xe"
	}
	return p
}
