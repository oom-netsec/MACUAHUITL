package syslogd

import (
	"context"
	"errors"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestValidacionDeDireccionYProtocolo(t *testing.T) {
	for _, tc := range []struct {
		err           error
		es, en, field string
	}{
		{ValidateAddr("1.2.3.4:abc", false), `syslogd: puerto inválido "abc"`, `syslogd: invalid port "abc"`, "addr"},
		{ValidateAddr("1.2.3.4:80", false), "syslogd: el puerto 80 es privilegiado; usa uno alto (p. ej. 5514) y redirige si hace falta", "syslogd: port 80 is privileged; use a high one (e.g. 5514) and redirect if needed", "addr"},
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
