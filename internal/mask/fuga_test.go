package mask

import (
	"strings"
	"testing"
)

// Secretos de configuración que v0.4.0 dejaba en claro en las evidencias (Patrol, respaldos, grabaciones).
func TestReglasDeLaFugaDeV040(t *testing.T) {
	cases := []struct{ in, want, kind string }{
		// ISE/TrustSec: PAC dentro de «radius server …».
		{"  pac key 7 0822455D0A16", "  pac key 7 <MASKED:radius-key>", "radius-key"},
		{" pac key Cl4ve", " pac key <MASKED:radius-key>", "radius-key"},
		// CoA de ISE: «aaa server radius dynamic-author».
		{" client 10.1.1.10 server-key 7 0822455D0A16", " client 10.1.1.10 server-key 7 <MASKED:radius-key>", "radius-key"},
		{" client 10.1.1.10 vrf MGMT server-key Cl4ve", " client 10.1.1.10 vrf MGMT server-key <MASKED:radius-key>", "radius-key"},
		{" server-key 7 0822455D0A16", " server-key 7 <MASKED:radius-key>", "radius-key"},
		// LISP (fabric SD-Access).
		{"  authentication-key 7 0822455D0A16", "  authentication-key 7 <MASKED:lisp-key>", "lisp-key"},
		{"  etr map-server 10.0.0.1 key 7 0822455D0A16", "  etr map-server 10.0.0.1 key 7 <MASKED:lisp-key>", "lisp-key"},
		{" ipv4 etr map-server 10.0.0.1 key Cl4ve", " ipv4 etr map-server 10.0.0.1 key <MASKED:lisp-key>", "lisp-key"},
		{"  map-server 10.0.0.1 key 6 ABCDEF", "  map-server 10.0.0.1 key 6 <MASKED:lisp-key>", "lisp-key"},
		// 9800: credenciales de gestión de los AP en «ap profile».
		{" mgmtuser username admin password 8 $8$abc secret 8 $8$def", " mgmtuser username admin password 8 <MASKED:user-secret> secret 8 <MASKED:user-secret>", "user-secret"},
		// LDAP, IS-IS, LDP, GLBP, OSPFv3.
		{" bind authenticated dn cn=svc,dc=x password 7 0822455D0A16", " bind authenticated dn cn=svc,dc=x password 7 <MASKED:ldap-password>", "ldap-password"},
		{" area-password Cl4ve", " area-password <MASKED:isis-password>", "isis-password"},
		{" domain-password Cl4ve authenticate snp validate", " domain-password <MASKED:isis-password> authenticate snp validate", "isis-password"},
		{"mpls ldp neighbor 10.0.0.2 password 7 0822455D0A16", "mpls ldp neighbor 10.0.0.2 password 7 <MASKED:ldp-password>", "ldp-password"},
		{" glbp 1 authentication text Cl4ve", " glbp 1 authentication text <MASKED:fhrp-key>", "fhrp-key"},
		{" glbp 1 authentication md5 key-string 7 0822", " glbp 1 authentication md5 key-string 7 <MASKED:fhrp-key>", "fhrp-key"},
		{" ipv6 ospf authentication ipsec spi 256 md5 1234567890ABCDEF1234567890ABCDEF", " ipv6 ospf authentication ipsec spi 256 md5 <MASKED:ospf-key>", "ospf-key"},
		// Salida de show snmp community / show snmp host de IOS (la comunidad v1/v2c es el secreto).
		{"Community name: MARKER-SNMP", "Community name: <MASKED:snmp-community>", "snmp-community"},
		{"Community Index: MARKER-SNMP", "Community Index: <MASKED:snmp-community>", "snmp-community"},
		{"Community SecurityName: MARKER-SNMP", "Community SecurityName: <MASKED:snmp-community>", "snmp-community"},
		{"user: MARKER-SNMP\tsecurity model: v2c", "user: <MASKED:snmp-community>\tsecurity model: v2c", "snmp-community"},
	}
	for _, c := range cases {
		got, counts := Apply("ios-xe", c.in+"\n")
		if got != c.want+"\n" || counts[c.kind] == 0 {
			t.Errorf("Apply(%q) = %q %v, want %q", c.in, got, counts, c.want)
		}
	}
}

// Un usuario SNMPv3 en show snmp host es un nombre, no un secreto: no se toca.
func TestSNMPv3UsuarioNoSeEnmascara(t *testing.T) {
	in := "user: monitor\tsecurity model: v3 priv\n"
	if got, _ := Apply("ios-xe", in); got != in {
		t.Fatalf("got %q", got)
	}
}

// NX-OS da show snmp community y show snmp host como tablas: la comunidad es la primera columna de la primera y la
// SecName (en v1/v2c) la última de la segunda.
func TestTablasSNMPDeNXOS(t *testing.T) {
	in := strings.Join([]string{
		"Community            Group / Access      context    acl_filter",
		"---------            --------------      -------    ----------",
		"MARKER-RO            network-operator",
		"MARKER-RW            network-admin",
		"",
		"-------------------------------------------------------------------",
		"Host                            Port Version  Level  Type   SecName",
		"-------------------------------------------------------------------",
		"10.1.1.1                        162  v2c      noauth trap   MARKER-HOST",
		"10.1.1.2                        162  v3       priv   trap   monitor",
		"-------------------------------------------------------------------",
		"show version",
		"MARKER-FUERA de la tabla",
	}, "\n") + "\n"
	got, counts := Apply("nx-os", in)
	for _, s := range []string{"MARKER-RO", "MARKER-RW", "MARKER-HOST"} {
		if strings.Contains(got, s) {
			t.Errorf("quedó %s en claro:\n%s", s, got)
		}
	}
	if !strings.Contains(got, "monitor") || !strings.Contains(got, "MARKER-FUERA") || counts["snmp-community"] != 3 {
		t.Errorf("enmascaró de más o de menos (%v):\n%s", counts, got)
	}
}

// Forma genérica <palabra de secreto> <tipo> <valor> en cualquier posición: tapa lo que ninguna regla por comando
// conoce, también varias veces en la misma línea.
func TestFormaGenericaDeSecretos(t *testing.T) {
	cases := []struct{ in, want string }{
		{" algo nuevo password 7 0822455D0A16 extra", " algo nuevo password 7 <MASKED:secret> extra"},
		{" otro comando secret 8 $8$abc", " otro comando secret 8 <MASKED:secret>"},
		{" futuro key 6 ABCDEF vrf X", " futuro key 6 <MASKED:secret> vrf X"},
		{" x server-key 0 claro", " x server-key 0 <MASKED:secret>"},
		{" y authentication-key 9 $9$a key 7 0822", " y authentication-key 9 <MASKED:secret> key 7 <MASKED:secret>"},
		{" z key-string 7 0822", " z key-string 7 <MASKED:secret>"},
	}
	for _, c := range cases {
		if got, _ := Apply("ios-xe", c.in+"\n"); got != c.want+"\n" {
			t.Errorf("Apply(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Lo que no es un secreto no se toca: tipos que no son de cifrado y palabras sin tipo.
	for _, in := range []string{
		"spanning-tree vlan 1 priority 4096",
		"key chain EIGRP",
		" key 1",
		"crypto key generate rsa modulus 2048",
		"Encryption key type 4 is deprecated",
		"show key chain",
	} {
		if got, _ := Apply("ios-xe", in+"\n"); got != in+"\n" {
			t.Errorf("enmascaró de más: %q → %q", in, got)
		}
	}
}
