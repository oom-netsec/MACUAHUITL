package fileserve

import (
	"errors"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Los motivos que antes eran errors.New/fmt.Errorf sueltos: el es es el de siempre y con en sale en inglés.
func TestMotivosSueltosEsEn(t *testing.T) {
	for _, c := range []struct {
		code   string
		args   i18n.Args
		es, en string
	}{
		{"fileserve.reason.stopped", nil, "servidor detenido", "server stopped"},
		{"fileserve.reason.no_reply", i18n.A("tries", 5), "sin respuesta tras 5 intentos", "no reply after 5 attempts"},
		{"fileserve.reason.client_abort_msg", i18n.A("msg", "disk full"), "el cliente abortó: disk full", "the client aborted: disk full"},
		{"fileserve.reason.file_closed", nil, "archivo ya cerrado", "file already closed"},
		{"fileserve.reason.no_pasv", nil, "sin PASV", "no PASV"},
	} {
		var tr Transfer
		tr.setErr(i18n.New(c.code, c.args))
		if tr.Error != c.es || ReasonIn("en", tr) != c.en || ReasonIn("es", tr) != c.es {
			t.Errorf("%s: es=%q en=%q", c.code, tr.Error, ReasonIn("en", tr))
		}
	}
	w := &recvFile{done: true}
	if _, _, err := w.commit(); err == nil || err.Error() != "archivo ya cerrado" || i18n.English(err) != "file already closed" {
		t.Errorf("commit: %v", err)
	}
	var ie *i18n.Error
	if _, err := (&ftpSession{}).dataConn(); !errors.As(err, &ie) || err.Error() != "sin PASV" {
		t.Errorf("dataConn: %v", err)
	}
}
