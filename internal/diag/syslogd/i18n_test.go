package syslogd

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestValidacionDeDireccionYProtocolo(t *testing.T) {
	privilegedPorts = true
	t.Cleanup(func() { privilegedPorts = runtime.GOOS != "windows" })
	// En Windows i18n elige la variante .windows del mismo código (ADR 0012 h).
	privEs, privEn := "syslogd: el puerto 80 es privilegiado; usa uno alto (p. ej. 5514) y redirige si hace falta", "syslogd: port 80 is privileged; use a high one (e.g. 5514) and redirect if needed"
	if runtime.GOOS == "windows" {
		privEs, privEn = "syslogd: el puerto 80 no se puede abrir; elige otro", "syslogd: port 80 cannot be opened; choose another"
	}
	for _, tc := range []struct {
		err           error
		es, en, field string
	}{
		{ValidateAddr("1.2.3.4:abc", false), `syslogd: puerto inválido "abc"`, `syslogd: invalid port "abc"`, "addr"},
		{ValidateAddr("1.2.3.4:80", false), privEs, privEn, "addr"},
		{ValidateAddr("0.0.0.0:5514", false), "syslogd: escuchar en todas las interfaces requiere pedirlo explícitamente", "syslogd: listening on all interfaces must be requested explicitly", "addr"},
		{Listen(context.Background(), Config{Addr: "127.0.0.1:5514", Proto: "sctp"}), `syslogd: protocolo "sctp" no soportado (udp o tcp)`, `syslogd: protocol "sctp" is not supported (udp or tcp)`, "protocol"},
	} {
		var c i18n.Coded
		if tc.err == nil || !errors.As(tc.err, &c) {
			t.Fatalf("%q: sin código (%v)", tc.es, tc.err)
		}
		if tc.err.Error() != tc.es || c.Localize(i18n.En) != tc.en || c.Metadata()["field"] != tc.field {
			t.Errorf("es=%q en=%q meta=%v", tc.err.Error(), c.Localize(i18n.En), c.Metadata())
		}
	}
}
