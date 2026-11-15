package mask

import (
	"strings"
	"testing"
)

// Auditoría de punta a punta: huecos de ISE, ASA/FTD, AireOS y syslogs de comandos ejecutados.
func TestAuditoriaHuecos(t *testing.T) {
	for _, c := range []struct{ pl, in, want string }{
		// 1. ISE: encryption-key de backup/restore/backup-logs y de la kron policy-list.
		{"ise", "backup b1 repository r1 ise-config encryption-key plain Secr3tK", "backup b1 repository r1 ise-config encryption-key plain <MASKED:backup-key>"},
		{"ise", "backup b1 repository r1 encryption-key hash 1a2b3c", "backup b1 repository r1 encryption-key hash <MASKED:backup-key>"},
		{"ise", "restore b1.tar.gpg repository r1 encryption-key plain Secr3tK include-adeos", "restore b1.tar.gpg repository r1 encryption-key plain <MASKED:backup-key> include-adeos"},
		{"ise", "backup-logs lg1 repository r1 encryption-key plain Secr3tK", "backup-logs lg1 repository r1 encryption-key plain <MASKED:backup-key>"},
		{"ise", "  cli backup b1 repository r1 ise-config encryption-key plain Secr3tK", "  cli backup b1 repository r1 ise-config encryption-key plain <MASKED:backup-key>"},
		{"ise", "backup b1 repository r1 ise-config", "backup b1 repository r1 ise-config"},
		// 4. ASA/FTD: key config-key password-encryption NUEVA [VIEJA].
		{"asa", "key config-key password-encryption NewPassw0rd OldPassw0rd", "key config-key password-encryption <MASKED:config-key> <MASKED:config-key>"},
		{"ftd", "key config-key password-encryption NewPassw0rd", "key config-key password-encryption <MASKED:config-key>"},
		{"ios", "key config-key password-encrypt Abc12345", "key config-key password-encrypt <MASKED:config-key>"},
		// 5. ASA/FTD: snmp-server host-group.
		{"asa", "snmp-server host-group inside GRP1 community Comm1 version 2c", "snmp-server host-group inside GRP1 community <MASKED:snmp-community> version 2c"},
		{"ftd", "snmp-server host-group inside GRP1 poll community 0 Comm1 version 2c", "snmp-server host-group inside GRP1 poll community 0 <MASKED:snmp-community> version 2c"},
		{"asa", "snmp-server host-group inside GRP1 version 3 u1", "snmp-server host-group inside GRP1 version 3 u1"},
		// 7. ntp: cmac y tipo tras el algoritmo.
		{"asa", "ntp authentication-key 5 cmac Ntp5ecret", "ntp authentication-key 5 cmac <MASKED:ntp-key>"},
		{"ftd", "ntp authentication-key 5 cmac-aes-128 Ntp5ecret", "ntp authentication-key 5 cmac-aes-128 <MASKED:ntp-key>"},
		{"ios", "ntp authentication-key 5 cmac Ntp5ecret", "ntp authentication-key 5 cmac <MASKED:ntp-key>"},
		{"ios", "ntp authentication-key 7 md5 8 Ntp5ecret", "ntp authentication-key 7 md5 8 <MASKED:ntp-key>"},
		{"asa", "ntp authentication-key 7 md5 0 Ntp5ecret", "ntp authentication-key 7 md5 0 <MASKED:ntp-key>"},
		{"ios", "ntp authentication-key 7 md5 Ntp5ecret 7", "ntp authentication-key 7 md5 <MASKED:ntp-key> 7"},
		// 3. AireOS: transfer.
		{"aireos", "transfer download password Tr4nsPw", "transfer download password <MASKED:transfer-password>"},
		{"aireos", "transfer upload password Tr4nsPw", "transfer upload password <MASKED:transfer-password>"},
		{"aireos", "transfer download certpassword Cp4ss", "transfer download certpassword <MASKED:transfer-password>"},
		{"aireos", "transfer download path /tftp/", "transfer download path /tftp/"},
		{"aireos", "transfer download start", "transfer download start"},
		// 8. AireOS: comunidad IPv6.
		{"aireos", "config snmp community ipv6addr 2001:db8::1 64 Comun1dadV6", "config snmp community ipv6addr 2001:db8::1 64 <MASKED:snmp-community>"},
		// 9. AireOS: malla.
		{"aireos", "config mesh security psk provisioning key MeshK3y", "config mesh security psk provisioning key <MASKED:psk>"},
		{"aireos", "config mesh security psk provisioning enable", "config mesh security psk provisioning enable"},
		// 12. AireOS: forma encrypt de mgmtuser (la clave, no el usuario).
		{"aireos", "config mgmtuser add encrypt admin2 C1av3Cif read-write", "config mgmtuser add encrypt admin2 <MASKED:user-secret> read-write"},
		{"aireos", "config mgmtuser add encrypt admin2 C1av3Cif", "config mgmtuser add encrypt admin2 <MASKED:user-secret>"},
		{"aireos", "config mgmtuser add encrypt Secreta1 read-only", "config mgmtuser add encrypt <MASKED:user-secret> read-only"}, // usuario llamado «encrypt»
		// 10. FTD CLISH: configure manager add.
		{"ftd", "configure manager add 10.1.1.1 RegK3yAbc NatId123", "configure manager add 10.1.1.1 <MASKED:manager-regkey> <MASKED:manager-natid>"},
		{"ftd", "configure manager add 10.1.1.1 RegK3yAbc", "configure manager add 10.1.1.1 <MASKED:manager-regkey>"},
		{"ftd", "configure manager add DONTRESOLVE RegK3yAbc NatId123", "configure manager add DONTRESOLVE <MASKED:manager-regkey> <MASKED:manager-natid>"},
		{"ftd", "configure manager delete", "configure manager delete"},
		// 11. Syslogs que citan el comando.
		{"asa", "%ASA-5-111008: User 'enable_15' executed the 'username bob password S3cretPw privilege 15' command.", "%ASA-5-111008: User 'enable_15' executed the 'username bob password <MASKED:secret>' command."},
		{"ftd", "%FTD-5-111008: User 'enable_15' executed the 'failover key FoK3y' command.", "%FTD-5-111008: User 'enable_15' executed the 'failover key <MASKED:failover-key>' command."},
		{"asa", "%ASA-5-111010: User 'admin', running 'CLI' from IP 10.1.1.9, executed 'failover key FoK3y'", "%ASA-5-111010: User 'admin', running 'CLI' from IP 10.1.1.9, executed 'failover key <MASKED:failover-key>'"},
		{"ftd", "Nov 14 2026 10:00:00 fw1 : %FTD-5-111010: User 'admin', running 'CLI' from IP 10.1.1.9, executed 'key config-key password-encryption N1 O1'", "Nov 14 2026 10:00:00 fw1 : %FTD-5-111010: User 'admin', running 'CLI' from IP 10.1.1.9, executed 'key config-key password-encryption <MASKED:config-key> <MASKED:config-key>'"},
		{"asa", "%ASA-7-111009: User 'enable_15' executed cmd: enable password Abc12345", "%ASA-7-111009: User 'enable_15' executed cmd: enable password <MASKED:enable-secret>"},
		{"asa", "%ASA-5-111008: User 'enable_15' executed the 'show version' command.", "%ASA-5-111008: User 'enable_15' executed the 'show version' command."},
		{"asa", "%ASA-5-111010: User 'admin', running 'CLI' from IP 10.1.1.9, executed 'show version'", "%ASA-5-111010: User 'admin', running 'CLI' from IP 10.1.1.9, executed 'show version'"},
	} {
		once, _ := Apply(c.pl, c.in+"\n")
		if got := once[:len(once)-1]; got != c.want {
			t.Errorf("%s Apply(%q)\n got %q\nwant %q", c.pl, c.in, got, c.want)
		}
		if twice, n := Apply(c.pl, once); twice != once || len(n) != 0 {
			t.Errorf("%s no idempotente %q: %q → %q %v", c.pl, c.in, once, twice, n)
		}
	}
}

// Bloques que abre una línea: cluster group (ASA/FTD) y crypto ca trustpoint (ASA/FTD).
func TestAuditoriaBloques(t *testing.T) {
	for _, c := range []struct{ pl, in, want string }{
		{"asa", "cluster group C1\n key Cl4sterKey\n local-unit A\n", "cluster group C1\n key <MASKED:cluster-key>\n local-unit A\n"},
		{"ftd", "cluster group C1\n key Cl4sterKey\ninterface g0\n key visible\n", "cluster group C1\n key <MASKED:cluster-key>\ninterface g0\n key visible\n"},
		{"asa", "crypto ca trustpoint TP1\n password TpPassw0rd\n enrollment self\n", "crypto ca trustpoint TP1\n password <MASKED:pki-password>\n enrollment self\n"},
		{"ftd", "crypto ca trustpoint TP1\n password TpPassw0rd\n", "crypto ca trustpoint TP1\n password <MASKED:pki-password>\n"},
		{"asa", "crypto ca trustpoint TP1\n enrollment self\nhostname fw\n password visible\n", "crypto ca trustpoint TP1\n enrollment self\nhostname fw\n password visible\n"},
	} {
		once, _ := Apply(c.pl, c.in)
		if once != c.want {
			t.Errorf("%s Apply(%q)\n got %q\nwant %q", c.pl, c.in, once, c.want)
		}
		if twice, n := Apply(c.pl, once); twice != once || len(n) != 0 {
			t.Errorf("%s no idempotente %q: %q → %q %v", c.pl, c.in, once, twice, n)
		}
	}
}

// AireOS en «(Nombre) config>»: sin el prefijo «config».
func TestAuditoriaAireOSConfigSinPrefijo(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"snmp community ipv6addr 2001:db8::1 64 Comun1dadV6", "snmp community ipv6addr 2001:db8::1 64 <MASKED:snmp-community>"},
		{"mesh security psk provisioning key MeshK3y", "mesh security psk provisioning key <MASKED:psk>"},
		{"mgmtuser add encrypt admin2 C1av3Cif read-write", "mgmtuser add encrypt admin2 <MASKED:user-secret> read-write"},
	} {
		var s Stream
		if got := s.Prompted(c.in, "aireconfig"); got != c.want {
			t.Errorf("config> %q\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

// Segunda ronda: comando citado en 111010 sin contexto de bloque, encrypt de radius/tacacs, sha2 y filas «> …».
func TestAuditoria2(t *testing.T) {
	for _, c := range []struct{ pl, in, want string }{
		{"asa", "%ASA-5-111010: User 'admin', running 'CLI' from IP 10.1.1.9, executed 'key Cl4sterKey'", "%ASA-5-111010: User 'admin', running 'CLI' from IP 10.1.1.9, executed 'key <MASKED:secret>'"},
		{"ftd", "%FTD-5-111010: User 'admin', running 'CLI' from IP 10.1.1.9, executed 'password TpPass1'", "%FTD-5-111010: User 'admin', running 'CLI' from IP 10.1.1.9, executed 'password <MASKED:secret>'"},
		{"asa", "%ASA-5-111008: User 'enable_15' executed the 'secret S3cr3t' command.", "%ASA-5-111008: User 'enable_15' executed the 'secret <MASKED:secret>' command."},
		{"asa", "%ASA-5-111008: User 'enable_15' executed the 'snmp-server community Comm1' command.", "%ASA-5-111008: User 'enable_15' executed the 'snmp-server community <MASKED:snmp-community>' command."},
		{"asa", "%ASA-5-111008: User 'enable_15' executed the 'community Comm2' command.", "%ASA-5-111008: User 'enable_15' executed the 'community <MASKED:secret>' command."},
		{"asa", "%ASA-5-111010: User 'a', running 'CLI' from IP 10.1.1.9, executed 'show key chain'", "%ASA-5-111010: User 'a', running 'CLI' from IP 10.1.1.9, executed 'show key chain'"},
		{"aireos", "config radius auth add encrypt 4 10.1.1.8 1812 ascii R4dK3y", "config radius auth add encrypt 4 10.1.1.8 1812 ascii <MASKED:radius-key>"},
		{"aireos", "config radius acct add encrypt 4 10.1.1.8 1813 hex 0a1b", "config radius acct add encrypt 4 10.1.1.8 1813 hex <MASKED:radius-key>"},
		{"aireos", "config tacacs auth add encrypt 1 10.1.1.6 49 ascii TacK3y", "config tacacs auth add encrypt 1 10.1.1.6 49 ascii <MASKED:tacacs-key>"},
		{"ios", "ntp authentication-key 3 sha2 Ntp5ecret", "ntp authentication-key 3 sha2 <MASKED:ntp-key>"},
		{"ios", "ntp authentication-key 3 sha384 Ntp5ecret", "ntp authentication-key 3 sha384 <MASKED:ntp-key>"},
		{"ios", "ntp authentication-key 3 hmac-sha1 Ntp5ecret", "ntp authentication-key 3 hmac-sha1 <MASKED:ntp-key>"},
	} {
		once, _ := Apply(c.pl, c.in+"\n")
		if got := once[:len(once)-1]; got != c.want {
			t.Errorf("%s Apply(%q)\n got %q\nwant %q", c.pl, c.in, got, c.want)
		}
		if twice, n := Apply(c.pl, once); twice != once || len(n) != 0 {
			t.Errorf("%s no idempotente %q: %q → %q %v", c.pl, c.in, once, twice, n)
		}
	}
	// Una fila «> …» de la tabla de comunidades no la cierra: la comunidad siguiente se tapa.
	in := "Community            Group / Access      context    acl_filter\n---------            --------------      -------    ----------\n> network-operator\nSecretComm           network-admin\n\n"
	out, _ := Apply("nx-os", in)
	if strings.Contains(out, "SecretComm") {
		t.Errorf("tabla cerrada por la fila «>»:\n%s", out)
	}
	// Una línea «> » dentro de una llave PEM no corta el descarte.
	out, _ = Apply("ftd", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n> \nQUJDREVGRw==\n-----END RSA PRIVATE KEY-----\nhostname x\n")
	if strings.Contains(out, "QUJDREVGRw") || !strings.Contains(out, "hostname x") {
		t.Errorf("PEM con «> »:\n%s", out)
	}
}
