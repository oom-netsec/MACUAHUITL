package mask

import (
	"testing"
)

// M1: JSON compacto en una línea, varios campos y los campos nuevos; XML con prefijo de namespace y CDATA.
func TestJSONYXMLDeNxosEnCualquierParte(t *testing.T) {
	for _, tc := range []struct{ in, leak string }{
		{`{"TABLE_snmp_community": {"ROW_snmp_community": {"community_name": "ZQ2xx", "grouporaccess": "network-operator"}}}`, "ZQ2xx"},
		{`{"a": {"secname": "ZQ3xx"}, "tacacs_key": "ZQ4xx", "radius_key": "ZQ5xx"}`, "ZQ5xx"},
		{`{"auth_password": "ZQ6xx", "priv_password": "ZQ7xx"}`, "ZQ6xx"},
		{`{"auth_password": "ZQ6xx", "priv_password": "ZQ7xx"}`, "ZQ7xx"},
		{`  "community_name": "ZQ8xx",`, "ZQ8xx"},
		{`<nf:community_name>ZQ9xx</nf:community_name>`, "ZQ9xx"},
		{`<ROW><community_name><![CDATA[ZQ10xx]]></community_name></ROW>`, "ZQ10xx"},
		{`<ROW><nf:key>ZQ11xx</nf:key><nf:password> ZQ12xx </nf:password></ROW>`, "ZQ12xx"},
		{`<ROW><nf:key>ZQ11xx</nf:key><nf:password> ZQ12xx </nf:password></ROW>`, "ZQ11xx"},
	} {
		noLeak(t, "nx-os", tc.in, tc.leak)
	}
	// Lo que no es secreto se queda.
	in := `{"hostname": "SW1", "vlan": "10"}` + "\n"
	if out, _ := Apply("nx-os", in); out != in {
		t.Errorf("%q", out)
	}
}

// M3: abreviaturas en CFGLOG y archive log.
func TestLogDeComandoConAbreviaturas(t *testing.T) {
	for _, cmd := range []struct{ c, leak string }{
		{"snmp-s user u g v3 au sha ZQ1xx pr aes 128 ZQ2xx", "ZQ2xx"},
		{"snmp-s user u g v3 au sha ZQ1xx pr aes 128 ZQ2xx", "ZQ1xx"},
		{"ip ospf mess 1 md5 ZQ3xx", "ZQ3xx"},
		{"stan 1 auth md5 key-s ZQ4xx", "ZQ4xx"},
		{"stan 1 auth text ZQ6xx", "ZQ6xx"},
		{"ntp auth 1 md5 ZQ8xx", "ZQ8xx"},
		{"pre-sh ZQ18xx", "ZQ18xx"},
		{"license smart reg idt ZQ24xx", "ZQ24xx"},
		{"username bob secret  ZQ16xx", "ZQ16xx"},
		{"username bob secret\tZQ16yy", "ZQ16yy"},
	} {
		noLeak(t, "ios-xe", `%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:`+cmd.c, cmd.leak)
		noLeak(t, "ios-xe", `    2     1   admin@vty0     | `+cmd.c, cmd.leak)
	}
}

// cliHistory no distingue mayúsculas.
func TestCliHistoryEnMayusculas(t *testing.T) {
	noLeak(t, "nx-os", "  12  09:01:55  SNMP-SERVER COMMUNITY ZQ20xx RO", "ZQ20xx")
}

// ASA 111008 con un apóstrofo en el usuario.
func TestASA111008ConApostrofoEnElUsuario(t *testing.T) {
	noLeak(t, "asa", `%ASA-5-111008: User 'adm'n' executed the 'key ZQ61xx' command.`, "ZQ61xx")
	noLeak(t, "asa", `%ASA-5-111010: User 'adm'n', running 'CLI' from IP 10.0.0.1, executed 'key ZQ62xx'`, "ZQ62xx")
}

// archive log: una tabla markdown no es una línea del log; las formas reales sí.
func TestArchiveLogNoTocaTablasMarkdown(t *testing.T) {
	in := "| Key | Descripción de la clave |\n| password | hunter2 |\n| Token de acceso | key id del token |\n"
	if out, _ := Apply("ios-xe", in); out != in {
		t.Errorf("%q", out)
	}
	noLeak(t, "ios-xe", `    2     1   admin@vty0     | password ARCHPW1`, "ARCHPW1")
	noLeak(t, "ios-xe", `|  key ARCHKEY1`, "ARCHKEY1")
}
