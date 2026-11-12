package mask

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRules(t *testing.T) {
	cases := []struct{ in, want, kind string }{
		{"enable secret 9 $9$abc$def", "enable secret 9 <MASKED:enable-secret>", "enable-secret"},
		{"enable password 7 0822455D0A16", "enable password 7 <MASKED:enable-secret>", "enable-secret"},
		{"enable secret s3cr3t", "enable secret <MASKED:enable-secret>", "enable-secret"},
		{"username admin privilege 15 secret 9 $9$x$y", "username admin privilege 15 secret 9 <MASKED:user-secret>", "user-secret"},
		{"username bob password 0 hola", "username bob password 0 <MASKED:user-secret>", "user-secret"},
		{"snmp-server community MARKER-SNMP RO", "snmp-server community <MASKED:snmp-community> RO", "snmp-community"},
		{"snmp-server community publica", "snmp-server community <MASKED:snmp-community>", "snmp-community"},
		{"tacacs-server key 7 0822455D0A16", "tacacs-server key 7 <MASKED:tacacs-key>", "tacacs-key"},
		{"radius-server key clave", "radius-server key <MASKED:radius-key>", "radius-key"},
		{"crypto isakmp key MiPSK address 0.0.0.0", "crypto isakmp key <MASKED:psk> address 0.0.0.0", "psk"},
		{"  pre-shared-key local MiPSK", "  pre-shared-key local <MASKED:psk>", "psk"},
		{"  pre-shared-key MiPSK", "  pre-shared-key <MASKED:psk>", "psk"},
		{"  pre-shared-key remote 0 MiPSK", "  pre-shared-key remote 0 <MASKED:psk>", "psk"},
		{" pre-shared-key address 10.0.0.1 key Cisco123", " pre-shared-key address 10.0.0.1 key <MASKED:psk>", "psk"},
		{" pre-shared-key address 10.0.0.1 255.255.255.255 key 0 Cisco123", " pre-shared-key address 10.0.0.1 255.255.255.255 key 0 <MASKED:psk>", "psk"},
		{" pre-shared-key hostname peer.example key Cisco123", " pre-shared-key hostname peer.example key <MASKED:psk>", "psk"},
		{"ntp authentication-key 1 md5 0822455D0A16 7", "ntp authentication-key 1 md5 <MASKED:ntp-key> 7", "ntp-key"},
		{" ip ospf authentication-key 7 0822", " ip ospf authentication-key 7 <MASKED:ospf-key>", "ospf-key"},
		{" ip ospf message-digest-key 1 md5 7 0822", " ip ospf message-digest-key 1 md5 7 <MASKED:ospf-key>", "ospf-key"},
	}
	for _, c := range cases {
		got, counts := Apply("ios-xe", c.in+"\n")
		if got != c.want+"\n" || counts[c.kind] != 1 {
			t.Errorf("Apply(%q) = %q %v, want %q", c.in, got, counts, c.want)
		}
	}
}

func TestBlockContext(t *testing.T) {
	in := "tacacs server ISE1\n address ipv4 192.0.2.5\n key 7 0822455D0A16\n!\nradius server R1\n key clave\n!\nline vty 0 4\n password 7 045802150C2E\n transport input ssh\n!\ninterface Gi1\n description key 7 is broken\n"
	want := "tacacs server ISE1\n address ipv4 192.0.2.5\n key 7 <MASKED:tacacs-key>\n!\nradius server R1\n key <MASKED:radius-key>\n!\nline vty 0 4\n password 7 <MASKED:line-password>\n transport input ssh\n!\ninterface Gi1\n description key 7 is broken\n"
	if got, _ := Apply("ios-xe", in); got != want {
		t.Fatalf("got:\n%s", got)
	}
}

func TestDot1xCredentials(t *testing.T) {
	in := "dot1x credentials SUP\n username host1\n password 0 Secreta\n!\ninterface Gi1\n description password x\n"
	want := "dot1x credentials SUP\n username host1\n password 0 <MASKED:dot1x-password>\n!\ninterface Gi1\n description password x\n"
	if got, _ := Apply("ios-xe", in); got != want {
		t.Fatalf("got:\n%s", got)
	}
}

func TestDescriptionNotMasked(t *testing.T) {
	for _, in := range []string{" description key 7 is broken\n", "banner motd ^C enable secret is not here ^C\n", "% password incorrect\n"} {
		if got, counts := Apply("ios-xe", in); got != in || len(counts) != 0 {
			t.Errorf("Apply(%q) = %q %v", in, got, counts)
		}
	}
}

func TestPrivateKeyBlock(t *testing.T) {
	in := "x\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\ndef\n-----END RSA PRIVATE KEY-----\ny\ncrypto pki certificate chain TP\n certificate 01\n  3082ABCD\n  \tquit\nz\n"
	got, counts := Apply("ios-xe", in)
	for _, leak := range []string{"MIIabc", "def\n", "3082ABCD"} {
		if strings.Contains(got, leak) {
			t.Errorf("leaked %q:\n%s", leak, got)
		}
	}
	if !strings.Contains(got, "x\n") || !strings.Contains(got, "y\n") || !strings.HasSuffix(got, "z\n") || counts["private-key"] != 2 {
		t.Fatalf("got %v:\n%s", counts, got)
	}
}

func TestRunningConfigFixture(t *testing.T) {
	_, f, _, _ := runtime.Caller(0)
	b, err := os.ReadFile(filepath.Join(filepath.Dir(f), "..", "..", "test", "transcripts", "ios-xe", "show_running-config.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got, counts := Apply("ios-xe", string(b))
	for _, leak := range []string{"MARKER-SNMP", "EXAMPLEhash", "0822455D0A16", "045802150C2E"} {
		if strings.Contains(got, leak) {
			t.Errorf("leaked %q", leak)
		}
	}
	if counts["snmp-community"] != 1 || counts["enable-secret"] != 1 || counts["user-secret"] != 1 || counts["line-password"] != 1 {
		t.Fatalf("counts = %v", counts)
	}
	if !strings.Contains(got, " description key 7 is broken\n") {
		t.Fatal("description was altered")
	}
}

func TestIdempotent(t *testing.T) {
	in := "enable secret 9 $9$x\nsnmp-server community c RO\n"
	once, _ := Apply("ios-xe", in)
	twice, counts := Apply("ios-xe", once)
	if once != twice || len(counts) != 0 {
		t.Fatalf("not idempotent: %q / %q %v", once, twice, counts)
	}
}

func TestCRLFPreserved(t *testing.T) {
	got, _ := Apply("ios-xe", "snmp-server community c RO\r\nhostname X\r\n")
	if got != "snmp-server community <MASKED:snmp-community> RO\r\nhostname X\r\n" {
		t.Fatalf("got %q", got)
	}
}

// En show startup-config la cadena no trae el certificado ni su quit: IOS deja una referencia a nvram.
// La cadena termina en la siguiente línea de primer nivel y el resto de la configuración sigue (hallazgo B1 del QA).
func TestCertificateChainWithoutQuit(t *testing.T) {
	in := "hostname SW1\n!\ncrypto pki certificate chain TP-self-signed-1\n certificate self-signed 01 nvram:IOS-Self-Sig#1.cer\n!\ninterface GigabitEthernet0/1\n switchport access vlan 10\n!\nline vty 0 4\n password 7 0822455D0A16\n!\nntp server 10.0.0.1\nend\n"
	out, _ := Apply("ios-xe", in)
	for _, want := range []string{"crypto pki certificate chain TP-self-signed-1", "interface GigabitEthernet0/1", " switchport access vlan 10", "ntp server 10.0.0.1", "end", " password 7 <MASKED:line-password>"} {
		if !strings.Contains(out, want) {
			t.Errorf("falta %q en:\n%s", want, out)
		}
	}
	if strings.Contains(out, "0822455D0A16") {
		t.Error("la contraseña de la línea salió sin máscara")
	}
}

// Revisión de B1: varios certificados en una cadena (con quit cada uno) quedan todos ocultos; una línea
// que es solo \r dentro de la cadena no la corta; y una llave sin END no se come el resto.
func TestChainAndKeyEdges(t *testing.T) {
	multi := "crypto pki certificate chain TP\n certificate 02\n  3082AAAA\n  \tquit\n certificate ca 01\n  3082BBBB\n  \tquit\nhostname SW1\n"
	if out, _ := Apply("ios-xe", multi); strings.Contains(out, "BBBB") || strings.Contains(out, "AAAA") || !strings.Contains(out, "hostname SW1") {
		t.Errorf("cadena con varios certificados:\n%s", out)
	}
	cr := "crypto pki certificate chain TP\r\n certificate 02\r\n  3082AAAA\r\n\r\r\n  3082CCCC\r\n  \tquit\r\nhostname SW1\r\n"
	if out, _ := Apply("ios-xe", cr); strings.Contains(out, "CCCC") || !strings.Contains(out, "hostname SW1") {
		t.Errorf("línea solo con \\r:\n%q", out)
	}
	key := "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nMIIabcdef+/=\n\nhostname SW1\ninterface Gi0/1\n"
	if out, _ := Apply("ios-xe", key); strings.Contains(out, "MIIabcdef") || !strings.Contains(out, "hostname SW1") || !strings.Contains(out, "interface Gi0/1") {
		t.Errorf("llave sin END:\n%s", out)
	}
}

// Un prompt termina cualquier cadena o llave abierta: la salida del comando siguiente no se pierde.
func TestPromptedEndsSkip(t *testing.T) {
	var s Stream
	s.Line("crypto pki certificate chain TP\n")
	s.Line(" certificate self-signed 01 nvram:IOS-Self-Sig#1.cer\n")
	s.Prompted("SW1#show ip interface brief", "")
	if out, ok := s.Line("  Vlan1  10.0.0.1  YES manual up up\n"); !ok || !strings.Contains(out, "Vlan1") {
		t.Fatalf("se perdió la salida tras el prompt: %q %v", out, ok)
	}
}
