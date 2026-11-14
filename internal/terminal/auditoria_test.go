package terminal

import (
	"strings"
	"testing"
)

var auditoriaCasos = []struct{ prompt, cmd string }{
	{"ise/admin# ", "backup b1 repository r1 ise-config encryption-key plain Secr3tKeyAA"},
	{"ise/admin(config-Policy List)# ", "cli backup b1 repository r1 ise-config encryption-key plain Secr3tKeyAA"},
	{"ise/admin# ", "restore b1.tar.gpg repository r1 encryption-key hash 1a2b3c4d5e6f7a"},
	{"ciscoasa(cfg-cluster)# ", "key Cl4sterSecretAA"},
	{"(Cisco Controller) >", "transfer download password Tr4nsferPwAA"},
	{"(Cisco Controller) >", "transfer download certpassword Cert1fPwAA"},
	{"ciscoasa(config)# ", "key config-key password-encryption NewPassw0rdAA OldPassw0rdAA"},
	{"ciscoasa(config)# ", "snmp-server host-group inside GRP1 community Comm1SecretAA version 2c"},
	{"ciscoasa(config-ca-trustpoint)# ", "password TpPassw0rdAA"},
	{"ciscoasa(config)# ", "ntp authentication-key 5 cmac NtpSecretKeyAA"},
	{"ciscoasa(config)# ", "ntp authentication-key 7 md5 8 NtpSecretKeyAA"},
	{"(Cisco Controller) >", "config snmp community ipv6addr 2001:db8::1 64 Comun1dadV6AA"},
	{"(Cisco Controller) config>", "snmp community ipv6addr 2001:db8::1 64 Comun1dadV6AA"},
	{"(Cisco Controller) >", "config mesh security psk provisioning key MeshK3yAAAA"},
	{"> ", "configure manager add 10.1.1.1 RegK3yAbcAA NatId123AA"},
	{"> ", "configure manager add DONTRESOLVE RegK3yAbcAA NatId123AA"},
	{"(Cisco Controller) >", "config mgmtuser add encrypt admin2 C1av3CifAAAA read-write"},
}

// secretos: palabras de la línea que acaban en «AA» o son claves largas conocidas; ninguna puede quedar en la grabación.
func secretos(cmd string) (out []string) {
	for _, w := range strings.Fields(cmd) {
		if strings.HasSuffix(w, "AA") || strings.HasPrefix(w, "1a2b3c") || strings.HasPrefix(w, "Comun1dad") || strings.HasPrefix(w, "MeshK3y") || strings.HasPrefix(w, "C1av3") {
			out = append(out, w)
		}
	}
	return
}

func TestAuditoriaTecleadoYEco(t *testing.T) {
	for _, c := range auditoriaCasos {
		sec := secretos(c.cmd)
		if len(sec) == 0 {
			t.Fatalf("caso sin secreto: %q", c.cmd)
		}
		p := strings.TrimRight(c.prompt, " ")
		if c.prompt == "> " {
			p = "> "
		}
		// Eco completo.
		r, b := newRec()
		r.Output([]byte(p))
		r.Input([]byte(c.cmd + "\r"))
		r.Output([]byte(c.cmd + "\r\n\r\n" + p))
		r.Close()
		for _, s := range sec {
			if strings.Contains(b.String(), s) {
				t.Errorf("eco completo %q: %q en la grabación:\n%s", c.cmd, s, b.String())
			}
		}
		if !strings.Contains(b.String(), ">>> ") || !strings.Contains(b.String(), "<MASKED:") {
			t.Errorf("eco completo %q: sin >>> o sin tapado:\n%s", c.cmd, b.String())
		}
		// Eco partido por un syslog en medio del valor mientras se teclea.
		r, b = newRec()
		r.Output([]byte(p))
		for _, ch := range c.cmd {
			r.Input([]byte(string(ch)))
		}
		cut := len(c.cmd) - 5
		r.Output([]byte(c.cmd[:cut]))
		r.Output([]byte("\r\n%ASA-5-111008: uno\r\n"))
		r.Output([]byte(c.cmd[cut:] + "\r\n"))
		r.Input([]byte("\r"))
		r.Output([]byte(p))
		r.Close()
		for _, s := range sec {
			if strings.Contains(b.String(), s) {
				t.Errorf("eco partido %q: %q en la grabación:\n%s", c.cmd, s, b.String())
			}
		}
	}
}

// El prompt de ISE con espacio y el «> » de FTD abren bloque normal; una salida que empieza con «>» sigue siendo salida.
func TestAuditoriaPrompts(t *testing.T) {
	for _, p := range []string{"ise/admin(config-Policy List)#", "> ", "> show version"} {
		if promptRe.FindString(p) == "" {
			t.Errorf("no reconoce el prompt %q", p)
		}
	}
	for _, p := range []string{">>> x", ">x", "ise/admin(config-Policy List) x"} {
		if strings.HasPrefix(promptRe.FindString(p), "> ") {
			t.Errorf("%q se tomó por prompt de FTD", p)
		}
	}
	if !shellPrompt.MatchString("> ") || !shellPrompt.MatchString("ise/admin(config-Policy List)#") {
		t.Error("shellPrompt no los reconoce")
	}
}

// Syslogs de ASA/FTD que citan el comando: salen enmascarados en la grabación.
func TestAuditoriaSyslogComando(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("ciscoasa(config)# "))
	r.Output([]byte("%ASA-5-111008: User 'enable_15' executed the 'failover key FoK3yAA' command.\r\n"))
	r.Output([]byte("%FTD-5-111010: User 'admin', running 'CLI' from IP 10.1.1.9, executed 'failover key FoK3yBB'\r\n"))
	r.Close()
	if strings.Contains(b.String(), "FoK3y") {
		t.Errorf("%s", b.String())
	}
}

// (a) Una línea «> x» de salida no vacía la red por contenido: el valor tecleado, repetido después, sale tapado.
func TestAuditoriaFTDLineaMayorNoVaciaLaRed(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("> "))
	r.Input([]byte("configure manager add 10.1.1.1 RegK3yAbcAA NatId123AA\r"))
	r.Output([]byte("> configure manager add 10.1.1.1 RegK3yAbcAA NatId123AA\r\n> x\r\nregistrado con RegK3yAbcAA\r\n> "))
	r.Close()
	if strings.Contains(b.String(), "RegK3yAbcAA") {
		t.Errorf("%s", b.String())
	}
}

// (b) Una línea «> » en medio de un PEM no corta el descarte del resto de la llave.
func TestAuditoriaFTDLineaMayorEnPEM(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("-----BEGIN RSA PRIVATE KEY-----\r\nMIIEowIBAAKCAQEA\r\n> \r\nQUJDREVGRwAAAAAA\r\n-----END RSA PRIVATE KEY-----\r\n> "))
	r.Close()
	if strings.Contains(b.String(), "QUJDREVGRw") {
		t.Errorf("%s", b.String())
	}
}

// (c) Teclear mientras la última línea va a medias («*> 10.0…», «> 10…») no vacía el bloque del prompt.
func TestAuditoriaLineaAMediasNoReiniciaElBloque(t *testing.T) {
	for _, partial := range []string{"*> 10.0.0.0/8 ", "> 10.0.0.0/8 ", "10.0.0.0/8#10 "} {
		r, b := newRec()
		r.Output([]byte("SW1(config-server-tacacs)#"))
		r.Input([]byte("\r"))
		r.Output([]byte("\r\nSW1(config-server-tacacs)#"))
		r.Output([]byte("\r\n" + partial))
		r.Input([]byte("key TacK3yAAAA\r"))
		r.Output([]byte("\r\nSW1(config-server-tacacs)#"))
		r.Close()
		if strings.Contains(b.String(), "TacK3yAAAA") {
			t.Errorf("%q:\n%s", partial, b.String())
		}
	}
}

// (d) Una fila «> …» de show snmp community no cierra la tabla.
func TestAuditoriaFilaMayorNoCierraLaTabla(t *testing.T) {
	r, b := newRec()
	r.Output([]byte("nx1# "))
	r.Input([]byte("show snmp community\r"))
	r.Output([]byte("show snmp community\r\nCommunity            Group / Access      context    acl_filter\r\n---------            --------------      -------    ----------\r\n> network-operator\r\nSecretComm           network-admin\r\n\r\nnx1# "))
	r.Close()
	if strings.Contains(b.String(), "SecretComm") {
		t.Errorf("%s", b.String())
	}
}
