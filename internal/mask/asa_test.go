package mask

import "testing"

// Reglas de ASA (show running-config) y el arreglo de snmp-server host con interfaz.
var asaCases = []struct{ in, want string }{
	{"passwd 2KFQnbNIdI.2KYOU encrypted", "passwd <MASKED:enable-secret> encrypted"},
	{"passwd 2KFQnbNIdI.2KYOU", "passwd <MASKED:enable-secret>"},
	{" ikev1 pre-shared-key Secr3tKey", " ikev1 pre-shared-key <MASKED:psk>"},
	{" ikev2 remote-authentication pre-shared-key Secr3tKey", " ikev2 remote-authentication pre-shared-key <MASKED:psk>"},
	{" ikev2 local-authentication pre-shared-key Secr3tKey", " ikev2 local-authentication pre-shared-key <MASKED:psk>"},
	{" ldap-login-password LdapP4ss", " ldap-login-password <MASKED:ldap-password>"},
	{"failover key FoK3y", "failover key <MASKED:failover-key>"},
	{"failover key hex 0123456789abcdef0123456789abcdef", "failover key hex <MASKED:failover-key>"},
	{"failover ipsec pre-shared-key FoK3y", "failover ipsec pre-shared-key <MASKED:failover-key>"},
	{" ospf message-digest-key 1 md5 OspfK3y", " ospf message-digest-key 1 md5 <MASKED:ospf-key>"},
	{" ospf authentication-key OspfK3y2", " ospf authentication-key <MASKED:ospf-key>"},
	{" eigrp authentication key 1 EigrpK3y key-id 2", " eigrp authentication key 1 <MASKED:eigrp-key> key-id 2"},
	{" authentication key eigrp 1 EigrpK3y key-id 2", " authentication key eigrp 1 <MASKED:eigrp-key> key-id 2"},
	// snmp-server host: la IP se queda y se tapa la comunidad.
	{"snmp-server host inside 10.1.1.1 community Comm1 version 2c", "snmp-server host inside 10.1.1.1 community <MASKED:snmp-community> version 2c"},
	{"snmp-server host inside 10.1.1.1 poll community Comm1", "snmp-server host inside 10.1.1.1 poll community <MASKED:snmp-community>"},
	{"snmp-server host inside 10.1.1.1", "snmp-server host inside 10.1.1.1"},
	{"snmp-server host inside 10.1.1.1 version 3 user1", "snmp-server host inside 10.1.1.1 version 3 user1"},
	{"snmp-server host 10.1.1.1 version 2c Comm1", "snmp-server host 10.1.1.1 version 2c <MASKED:snmp-community>"},
	{"snmp-server host 10.1.1.1 Comm1", "snmp-server host 10.1.1.1 <MASKED:snmp-community>"},
	// aaa-server en una línea: «host IP KEY [timeout N]».
	{"aaa-server RAD (inside) host 10.1.1.5 RadK3y timeout 5", "aaa-server RAD (inside) host 10.1.1.5 <MASKED:aaa-key> timeout 5"},
	{"aaa-server RAD (inside) host 10.1.1.5 RadK3y", "aaa-server RAD (inside) host 10.1.1.5 <MASKED:aaa-key>"},
	{"aaa-server RAD host 10.1.1.5 RadK3y", "aaa-server RAD host 10.1.1.5 <MASKED:aaa-key>"},
	{"aaa-server RAD (inside) host 10.1.1.5 *****", "aaa-server RAD (inside) host 10.1.1.5 *****"},
	{"aaa-server RAD (inside) host 10.1.1.5", "aaa-server RAD (inside) host 10.1.1.5"},
	{"aaa-server RAD (inside) host 10.1.1.5 timeout 5", "aaa-server RAD (inside) host 10.1.1.5 timeout 5"},
	{"aaa-server RAD protocol radius", "aaa-server RAD protocol radius"},
	// Revisión: tipos de cifrado 0/8.
	{"failover key 0 FoSecret", "failover key 0 <MASKED:failover-key>"},
	{"failover key 8 FoEnc", "failover key 8 <MASKED:failover-key>"},
	{"failover ipsec pre-shared-key 0 FoSecret", "failover ipsec pre-shared-key 0 <MASKED:failover-key>"},
	{"failover ipsec pre-shared-key 8 FoEnc", "failover ipsec pre-shared-key 8 <MASKED:failover-key>"},
	{"snmp-server host inside 10.1.1.1 community 0 CommClear version 2c", "snmp-server host inside 10.1.1.1 community 0 <MASKED:snmp-community> version 2c"},
	{"snmp-server host inside 10.1.1.1 community 8 CommEnc version 2c", "snmp-server host inside 10.1.1.1 community 8 <MASKED:snmp-community> version 2c"},
	{"snmp-server community 0 CommClear", "snmp-server community 0 <MASKED:snmp-community>"},
	{"snmp-server community 0 CommClear RO", "snmp-server community 0 <MASKED:snmp-community> RO"},
	{" authentication key eigrp 100 8 EigEnc key-id 1", " authentication key eigrp 100 8 <MASKED:eigrp-key> key-id 1"},
	{" authentication key eigrp 100 0 EigClear key-id 1", " authentication key eigrp 100 0 <MASKED:eigrp-key> key-id 1"},
	// Host por nombre: la palabra community marca el valor.
	{"snmp-server host inside nms01 community CommHost version 2c", "snmp-server host inside nms01 community <MASKED:snmp-community> version 2c"},
	{"snmp-server host inside nms01 poll community CommHost", "snmp-server host inside nms01 poll community <MASKED:snmp-community>"},
	// IOS/NX-OS: comunidad con forma de IP no se confunde con la forma ASA.
	{"snmp-server host 10.1.1.1 1.2.3.4", "snmp-server host 10.1.1.1 <MASKED:snmp-community>"},
	{"snmp-server host 10.1.1.1 ab:cd udp-port 162", "snmp-server host 10.1.1.1 <MASKED:snmp-community> udp-port 162"},
	// Otras claves de ASA.
	{" radius-common-pw CommonPw", " radius-common-pw <MASKED:radius-key>"},
	{"vpdn username u1 password VpdnPw", "vpdn username u1 password <MASKED:user-secret>"},
	{"vpdn username u1 password VpdnPw store-local", "vpdn username u1 password <MASKED:user-secret> store-local"},
	// Mayúsculas al teclear.
	{"FAILOVER KEY FoSecret", "FAILOVER KEY <MASKED:failover-key>"},
	{"ENABLE PASSWORD Secret", "ENABLE PASSWORD <MASKED:enable-secret>"},
	// Solo «*****» exacto queda igual: una clave real de asteriscos se tapa.
	{"failover key ********", "failover key <MASKED:failover-key>"},
	// Claves tipo 0 con espacios: se tapa todo hasta el fin de línea o hasta la palabra propia del comando.
	{"username bob password 0 open version two", "username bob password 0 <MASKED:user-secret>"},
	{"username bob secret 0 my rw pass", "username bob secret 0 <MASKED:user-secret>"},
	{"snmp-server community 0 my ro word RW", "snmp-server community 0 <MASKED:snmp-community> RW"},
	{"snmp-server community 0 my pass RO", "snmp-server community 0 <MASKED:snmp-community> RO"},
	{" ikev1 pre-shared-key 0 go udp-port now", " ikev1 pre-shared-key 0 <MASKED:psk>"},
	{"snmp-server host inside 10.1.1.1 community 0 my version two version 2c udp-port 162", "snmp-server host inside 10.1.1.1 community 0 <MASKED:snmp-community> version 2c udp-port 162"},
	{" authentication key eigrp 100 0 my key-id pass key-id 1", " authentication key eigrp 100 0 <MASKED:eigrp-key> key-id 1"},
	{"vpdn username u1 password 0 a b store-local", "vpdn username u1 password 0 <MASKED:user-secret> store-local"},
	// Host de IOS por nombre con comunidad que parece IP; en ASA «interfaz IP» sigue sin tocarse.
	{"snmp-server host nms01 cafe:01", "snmp-server host nms01 <MASKED:snmp-community>"},
	{"snmp-server host inside nms01 poll", "snmp-server host inside nms01 poll"},
	{"snmp-server host inside nms01 version 3 user1", "snmp-server host inside nms01 version 3 user1"},
	{"snmp-server host nms01 version 2c Comm1", "snmp-server host nms01 version 2c <MASKED:snmp-community>"},
	{"snmp-server host 10.0.0.9 Comm1 udp-port 162", "snmp-server host 10.0.0.9 <MASKED:snmp-community> udp-port 162"},
	// Un espacio al final no anula el sufijo propio del comando.
	{"snmp-server community 0 Comm RO ", "snmp-server community 0 <MASKED:snmp-community> RO "},
	{" authentication key eigrp 100 0 my pass key-id 1 ", " authentication key eigrp 100 0 <MASKED:eigrp-key> key-id 1 "},
	// Sin falsos positivos.
	{" description key server for vpn", " description key server for vpn"},
	{"ssh key-exchange group dh-group14-sha256", "ssh key-exchange group dh-group14-sha256"},
	{"crypto ikev2 policy 10", "crypto ikev2 policy 10"},
	{" password-management password-expire-in-days 14", " password-management password-expire-in-days 14"},
	{"failover lan interface folink GigabitEthernet0/3", "failover lan interface folink GigabitEthernet0/3"},
	{"passwd", "passwd"},
	{"failover key", "failover key"},
	// Lo que ASA ya muestra oculto no se toca.
	{"passwd ***** encrypted", "passwd ***** encrypted"},
	{" ikev1 pre-shared-key *****", " ikev1 pre-shared-key *****"},
	{"failover key *****", "failover key *****"},
	{" ospf message-digest-key 1 md5 *****", " ospf message-digest-key 1 md5 *****"},
	{"snmp-server host inside 10.1.1.1 community ***** version 2c", "snmp-server host inside 10.1.1.1 community ***** version 2c"},
	// Ya funcionaban.
	{"enable password 2KFQnbNIdI encrypted", "enable password <MASKED:enable-secret> encrypted"},
	{"username admin password 2KFQ encrypted privilege 15", "username admin password <MASKED:user-secret> encrypted privilege 15"},
	{"snmp-server community Comm1", "snmp-server community <MASKED:snmp-community>"},
}

func TestASAReglas(t *testing.T) {
	for _, c := range asaCases {
		once, _ := Apply("asa", c.in+"\n")
		if got := once[:len(once)-1]; got != c.want {
			t.Errorf("Apply(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
		twice, n := Apply("asa", once)
		if twice != once || len(n) != 0 {
			t.Errorf("no idempotente %q: %q → %q %v", c.in, once, twice, n)
		}
	}
}

// Reglas por bloque: la línea del valor va en la siguiente.
func TestASABloques(t *testing.T) {
	in := "aaa-server RAD (inside) host 10.1.1.5\n key TacacsK3y\n timeout 5\naaa-server X protocol radius\n key-id 2\nlicense smart\n token 0123456789abcdef\n feature tier standard\ninterface Gi0\n key foo\n token bar\n"
	want := "aaa-server RAD (inside) host 10.1.1.5\n key <MASKED:aaa-key>\n timeout 5\naaa-server X protocol radius\n key-id 2\nlicense smart\n token <MASKED:token>\n feature tier standard\ninterface Gi0\n key foo\n token bar\n"
	got, _ := Apply("asa", in)
	if got != want {
		t.Fatalf("got:\n%s", got)
	}
	if again, n := Apply("asa", got); again != got || len(n) != 0 {
		t.Fatalf("no idempotente: %q %v", again, n)
	}
}

// show failover no lleva secretos: nada cambia.
func TestASAShowFailoverIntacto(t *testing.T) {
	in := `Failover On
Failover unit Primary
Failover LAN Interface: folink GigabitEthernet0/3 (up)
Unit Poll frequency 1 seconds, holdtime 15 seconds
Version: Ours 9.8(1), Mate 9.8(1)
Last Failover at: 10:15:32 UTC Nov 14 2026
        This host: Primary - Active
                Active time: 12345 (sec)
        Other host: Secondary - Standby Ready
                Active time: 0 (sec)

Stateful Failover Logical Update Statistics
        Link : folink GigabitEthernet0/3 (up)
        Stateful Obj    xmit       xerr       rcv        rerr
        General         1234       0          1230       0
`
	got, n := Apply("asa", in)
	if got != in || len(n) != 0 {
		t.Fatalf("cambió: %q %v", got, n)
	}
}

// La forma de una línea de ASA y bloques en mayúsculas.
func TestASABloquesMayusculas(t *testing.T) {
	in := "AAA-SERVER RAD (inside) host 10.1.1.5\n RADIUS-COMMON-PW Common1\n KEY K1\n"
	want := "AAA-SERVER RAD (inside) host 10.1.1.5\n RADIUS-COMMON-PW <MASKED:radius-key>\n KEY <MASKED:aaa-key>\n"
	if got, _ := Apply("asa", in); got != want {
		t.Fatalf("got:\n%s", got)
	}
}

// «host NOMBRE IP» sin comunidad es ASA solo en ASA; en cualquier otra plataforma (o sin ella) la IP es la comunidad.
func TestASAHostSinComunidadDependeDeLaPlataforma(t *testing.T) {
	in := "snmp-server host nms01 1.2.3.4\n"
	for plat, want := range map[string]string{
		"asa":    in,
		"ios-xe": "snmp-server host nms01 <MASKED:snmp-community>\n",
		"":       "snmp-server host nms01 <MASKED:snmp-community>\n",
	} {
		if got, _ := Apply(plat, in); got != want {
			t.Errorf("Apply(%q) = %q, want %q", plat, got, want)
		}
	}
	// La palabra community vale en todas.
	for _, plat := range []string{"asa", "ios-xe", ""} {
		got, _ := Apply(plat, "snmp-server host inside 10.1.1.1 community C1\n")
		if got != "snmp-server host inside 10.1.1.1 community <MASKED:snmp-community>\n" {
			t.Errorf("%q: %q", plat, got)
		}
	}
}

// «license smart» solo abre el bloque con la línea exacta; el register de exec no.
func TestASALicenseSmartRegisterNoAbreBloque(t *testing.T) {
	in := "license smart register idtoken TOK123\n token abc\n"
	want := "license smart register idtoken <MASKED:token>\n token abc\n"
	if got, _ := Apply("asa", in); got != want {
		t.Fatalf("got:\n%s", got)
	}
}
