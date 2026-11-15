package mask

import (
	"strings"
	"testing"
)

func noLeak(t *testing.T, platform, in string, leaks ...string) {
	t.Helper()
	out, _ := Apply(platform, in+"\n")
	for _, l := range leaks {
		if strings.Contains(out, l) {
			t.Errorf("%s: fuga de %q en %q → %q", platform, l, in, out)
		}
	}
	if !strings.Contains(out, "<MASKED:") {
		t.Errorf("%s: no tapó nada: %q → %q", platform, in, out)
	}
}

// M1: las líneas de log que citan un subcomando (sin su bloque) también pierden el valor.
func TestLogDeComandoCitadoTapaElSubcomando(t *testing.T) {
	for _, tc := range []struct{ in, leak string }{
		{`%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:password CFGLINE1`, "CFGLINE1"},
		{`%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:key CFGRAD1`, "CFGRAD1"},
		{`%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:token X1TOKEN`, "X1TOKEN"},
		{`%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:usern bob sec SECABR1`, "SECABR1"},
		{`    2     1   admin@vty0     | password ARCHPW1`, "ARCHPW1"},
		{`|  key ARCHKEY1`, "ARCHKEY1"},
	} {
		noLeak(t, "ios-xe", tc.in, tc.leak)
	}
}

// M2: show accounting log de NX-OS con HSRP/VRRP y key-string.
func TestAccountingNxosFhrp(t *testing.T) {
	for _, tc := range []struct{ in, leak string }{
		{`Sun Nov 15 10:00:00 2026:type=update:id=vty0:user=admin:cmd=configure terminal ; interface Vlan10 ; hsrp 10 ; authentication text ACC1 (SUCCESS)`, "ACC1"},
		{`Sun Nov 15 10:00:00 2026:type=update:id=vty0:user=admin:cmd=configure terminal ; interface Vlan10 ; hsrp 10 ; authentication md5 key-string ACC2 (SUCCESS)`, "ACC2"},
		{`Sun Nov 15 10:00:00 2026:type=update:id=vty0:user=admin:cmd=configure terminal ; interface Vlan10 ; vrrp 10 ; authentication text ACC3 (SUCCESS)`, "ACC3"},
	} {
		noLeak(t, "nx-os", tc.in, tc.leak)
	}
	// La regla FHRP sin sangría (línea suelta, p. ej. tras partir por « ; »).
	noLeak(t, "nx-os", `authentication text FHRP9`, "FHRP9")
}

// B3: JSON/XML de NX-OS con campos de secreto.
func TestNxosJSONyXML(t *testing.T) {
	for _, tc := range []struct{ in, leak string }{
		{`            "community_name": "JSONCOMM1",`, "JSONCOMM1"},
		{`<community_name>XMLCOMM1</community_name>`, "XMLCOMM1"},
		{`  "password": "JPASS1"`, "JPASS1"},
		{`    <key>XKEY1</key>`, "XKEY1"},
		{`"secret":"JSEC1",`, "JSEC1"},
		{`<passphrase>XPH1</passphrase>`, "XPH1"},
	} {
		noLeak(t, "nx-os", tc.in, tc.leak)
	}
	if out, _ := Apply("nx-os", `"hostname": "SW1"`+"\n"); out != `"hostname": "SW1"`+"\n" {
		t.Errorf("cambió una línea sin secreto: %q", out)
	}
}

// B4: ASA anterior a 8.4.
func TestASAIsakmpKeySinCrypto(t *testing.T) {
	noLeak(t, "asa", `isakmp key ISAKEY1 address 1.1.1.1 netmask 255.255.255.255`, "ISAKEY1")
}

// B3: líneas numeradas de show cli history de NX-OS.
func TestNxosCliHistory(t *testing.T) {
	noLeak(t, "nx-os", `  12  09:01:55  snmp-server community HISTC1 group network-operator`, "HISTC1")
	noLeak(t, "nx-os", `  13  username bob password 0 HISTP1`, "HISTP1")
}
