package fileserve

import (
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Con el puerto estándar (TFTP 69, FTP 21, SCP/SFTP 22) no hay nada que redirigir: ni regla nft ni cómo quitarla.
func TestRedirectConPuertoEstandarNoHayRegla(t *testing.T) {
	for proto, port := range map[string]int{"tftp": 69, "ftp": 21, "scp": 22, "sftp": 22} {
		if c := RedirectCommandIn(i18n.Es, proto, "192.0.2.10", port); c != "" {
			t.Errorf("%s:%d dio una regla: %q", proto, port, c)
		}
		if h := RedirectHintIn(i18n.Es, proto, "192.0.2.10", port); h != "" {
			t.Errorf("%s:%d dio una pista: %q", proto, port, h)
		}
	}
	if RedirectCommandIn(i18n.Es, "tftp", "192.0.2.10", 6969) == "" {
		t.Fatal("un puerto no estándar debe seguir teniendo su regla")
	}
}
