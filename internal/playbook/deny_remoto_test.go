package playbook

import (
	"errors"
	"testing"
)

// Un playbook de terceros no puede hacer que el equipo salga a la red (more ftp://…) ni saltarse la revisión con un
// pipe al inicio, ni hacer ping a la difusión desde toda la flota.
func TestCheckDeniedRechazaRutasRemotasYPipeInicial(t *testing.T) {
	for _, cmd := range []string{
		"more ftp://203.0.113.9/x", "more http://203.0.113.9/x", "mo https://h/x", "dir tftp://203.0.113.9/",
		"verify /md5 ftp://h/x", "show file information ftp://x/y", "more scp://u@h/x", "more rcp:x", "dir sftp:",
		"MORE FTP://H/X", "more tftp:x",
		"| redirect flash:x", "  |redirect flash:x", "|",
		"ping 255.255.255.255", "ping 255.255.255.255 repeat 10",
	} {
		if err := CheckDenied("ios-xe", cmd); !errors.Is(err, ErrDenied) {
			t.Errorf("%q: se aceptó (err=%v)", cmd, err)
		}
	}
	for _, cmd := range []string{
		"more flash:config.txt", "dir bootflash:", "verify /md5 flash:c8000v.bin", "show file information flash:x",
		"show ip http server status", "show running-config | include http:", "show logging | i tftp:", "dir nvram:",
		"ping 10.0.0.1 repeat 5", "",
	} {
		if err := CheckDenied("ios-xe", cmd); err != nil {
			t.Errorf("%q: rechazado: %v", cmd, err)
		}
	}
}
