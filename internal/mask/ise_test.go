package mask

import "testing"

// Show running-config de ISE (ADE-OS, CLI Reference 3.1-3.4, sin validar en laboratorio): hash|plain precede al valor.
var iseCases = []struct{ in, want string }{
	{"username admin password hash $1$k5Ze0aXr$Qh1z3G5h0LkP9wYb7mV0A. role admin email admin@example.com", "username admin password hash <MASKED:user-secret> role admin email admin@example.com"},
	{"username jdoe password plain Secreta123 role user", "username jdoe password plain <MASKED:user-secret> role user"},
	{"username jdoe password plain Secreta123", "username jdoe password plain <MASKED:user-secret>"},
	{"username admin password hash 2a3b4c5d6e role admin", "username admin password hash <MASKED:user-secret> role admin"},
	{"snmp-server community Comun1dad ro", "snmp-server community <MASKED:snmp-community> ro"},
	{"snmp-server host 10.1.1.5 version 2c Comun1dad", "snmp-server host 10.1.1.5 version 2c <MASKED:snmp-community>"},
	{"ntp authentication-key 1 md5 hash 0A1B2C3D4E5F", "ntp authentication-key 1 md5 hash <MASKED:ntp-key>"},
	{"ntp authentication-key 2 md5 plain NtpK3y", "ntp authentication-key 2 md5 plain <MASKED:ntp-key>"},
	{"  user backup password hash 1f2e3d4c5b6a", "  user backup password hash <MASKED:client-password>"},
	{"  user backup password plain Rep0Pw", "  user backup password plain <MASKED:client-password>"},
	{"  url sftp://backup.example.com/repo", "  url sftp://backup.example.com/repo"},
	// Falsos positivos: ni usuario, ni rol, ni índice, ni nada sin secreto.
	{"username admin", "username admin"},
	{"ntp server 10.1.1.1 key 1", "ntp server 10.1.1.1 key 1"},
	{"ntp authentication-key 1", "ntp authentication-key 1"},
	{"ntp server 10.1.1.1", "ntp server 10.1.1.1"},
	{"ip host 10.1.1.9 ise-ppan.example.com", "ip host 10.1.1.9 ise-ppan.example.com"},
	{"kron occurrence backup-nightly at 01:00 recurring", "kron occurrence backup-nightly at 01:00 recurring"},
	{"kron policy-list backup-list", "kron policy-list backup-list"},
	{"repository myrepo", "repository myrepo"},
	{"hostname ise-psn1", "hostname ise-psn1"},
}

func TestISEReglas(t *testing.T) {
	for _, c := range iseCases {
		once, _ := Apply("ise", c.in+"\n")
		if got := once[:len(once)-1]; got != c.want {
			t.Errorf("Apply(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
		twice, n := Apply("ise", once)
		if twice != once || len(n) != 0 {
			t.Errorf("no idempotente %q: %q → %q %v", c.in, once, twice, n)
		}
	}
}

// Las líneas de ISE no cambian lo que ya hacían las reglas de IOS/ASA para sus propias formas.
func TestISENoCambiaIOS(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"username admin secret 5 $1$abc$def", "username admin secret 5 <MASKED:user-secret>"},
		{"username bob privilege 15 password 7 0822455D0A16", "username bob privilege 15 password 7 <MASKED:user-secret>"},
		{"username bob password secreto1", "username bob password <MASKED:user-secret>"},
		{"ntp authentication-key 1 md5 0822455D0A16 7", "ntp authentication-key 1 md5 <MASKED:ntp-key> 7"},
	} {
		got, _ := Apply("ios-xe", c.in+"\n")
		if got != c.want+"\n" {
			t.Errorf("%q\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

// SNMPv3 de ISE: dos claves tras hash|plain; el usuario, el engine ID y la IP no se tapan.
func TestISESNMPv3YNtpSha(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"snmp-server user snmpu v3 plain AuthPass123 PrivPass123", "snmp-server user snmpu v3 plain <MASKED:snmp-user-auth> <MASKED:snmp-user-priv>"},
		{"snmp-server user snmpu v3 hash 1a2b3c 4d5e6f", "snmp-server user snmpu v3 hash <MASKED:snmp-user-auth> <MASKED:snmp-user-priv>"},
		{"snmp-server user snmpu v3 plain AuthPass123 PrivPass123 RO", "snmp-server user snmpu v3 plain <MASKED:snmp-user-auth> <MASKED:snmp-user-priv> RO"},
		{"snmp-server host 10.1.1.5 version 3 snmpu 0x80001f88 plain AuthPass123 PrivPass123", "snmp-server host 10.1.1.5 version 3 snmpu 0x80001f88 plain <MASKED:snmp-user-auth> <MASKED:snmp-user-priv>"},
		{"snmp-server host 10.1.1.5 version 3 snmpu 0x80001f88 hash 1a2b 3c4d", "snmp-server host 10.1.1.5 version 3 snmpu 0x80001f88 hash <MASKED:snmp-user-auth> <MASKED:snmp-user-priv>"},
		{"ntp authentication-key 1 sha1 plain K3y", "ntp authentication-key 1 sha1 plain <MASKED:ntp-key>"},
		{"ntp authentication-key 1 sha1 hash 0A1B", "ntp authentication-key 1 sha1 hash <MASKED:ntp-key>"},
		{"snmp-server user snmpu", "snmp-server user snmpu"},
	} {
		once, _ := Apply("ise", c.in+"\n")
		if got := once[:len(once)-1]; got != c.want {
			t.Errorf("Apply(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
		twice, n := Apply("ise", once)
		if twice != once || len(n) != 0 {
			t.Errorf("no idempotente %q: %q → %q %v", c.in, once, twice, n)
		}
	}
}
