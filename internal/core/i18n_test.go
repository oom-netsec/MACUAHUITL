package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

// con devuelve un contexto que pide el idioma (vacío = sin el metadato).
func con(t *testing.T, lang string) context.Context {
	c := ctx(t)
	if lang != "" {
		c = metadata.AppendToOutgoingContext(c, "accept-language", lang)
	}
	return c
}

func reasonOf(err error) (string, map[string]string) {
	for _, d := range status.Convert(err).Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			return ei.Reason, ei.Metadata
		}
	}
	return "", nil
}

// Regresión: con es explícito, el mensaje de cada error migrado es el de siempre; con en sale en inglés.
// El reason y la metadata viajan siempre.
func TestIdiomaDeLosErroresMigrados(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	tc := v1.NewToolsServiceClient(h.conn)
	syslog := func(c context.Context) error {
		st, err := tc.Syslog(c, &v1.SyslogRequest{Addr: "127.0.0.1:0", RatePerSource: 20000})
		if err == nil {
			_, err = st.Recv()
		}
		return err
	}
	const esIngest = "la tasa por origen debe estar entre 1 y 10000 (0 = default), no 20000"
	for lang, want := range map[string]string{"es": esIngest, "es-MX": esIngest,
		"en": "the per-source rate must be between 1 and 10000 (0 = default), not 20000", "en-US,en;q=0.9": "the per-source rate must be between 1 and 10000 (0 = default), not 20000"} {
		err := syslog(con(t, lang))
		if status.Code(err) != codes.InvalidArgument || err.Error() != "rpc error: code = InvalidArgument desc = "+want {
			t.Errorf("syslog %q: %v", lang, err)
		}
		if r, m := reasonOf(err); r != "ingest.invalid" || m["field"] != "rate_per_source" || m["min"] != "1" || m["max"] != "10000" {
			t.Errorf("syslog %q: reason %q metadata %v", lang, r, m)
		}
	}

	// Un export sobre un archivo que existe: file.exists con la ruta.
	dst := filepath.Join(t.TempDir(), "hosts.json")
	os.WriteFile(dst, []byte("x"), 0o600)
	inv := v1.NewInventoryServiceClient(h.conn)
	if _, err := inv.PutDevice(ctx(t), &v1.PutDeviceRequest{Device: &v1.Device{Hostname: "sw-i18n", Name: "sw-i18n", Target: &v1.Target{Address: "192.0.2.10"}, Platform: "ios-xe"}}); err != nil {
		t.Fatal(err)
	}
	for lang, want := range map[string]string{"es": "el archivo ya existe", "en": "the file already exists"} {
		_, err := inv.ExportHosts(con(t, lang), &v1.ExportHostsRequest{Path: dst})
		if status.Code(err) != codes.AlreadyExists || status.Convert(err).Message() != want {
			t.Errorf("hosts %q: %v", lang, err)
		}
		if r, m := reasonOf(err); r != "file.exists" || m["path"] != dst {
			t.Errorf("hosts %q: reason %q metadata %v", lang, r, m)
		}
	}
	if b, _ := os.ReadFile(dst); string(b) != "x" {
		t.Fatal("no debe pisar el archivo")
	}

	// El respaldo de la bóveda.
	bk := filepath.Join(t.TempDir(), "r.mcvault")
	os.WriteFile(bk, []byte("x"), 0o600)
	for lang, want := range map[string]string{"": "vault: el archivo de respaldo ya existe", "en": "vault: the backup file already exists"} {
		_, err := h.vault.ExportBackup(con(t, lang), &v1.ExportBackupRequest{Path: bk, Passphrase: []byte(fraseResp), Confirm: true})
		if status.Code(err) != codes.AlreadyExists || status.Convert(err).Message() != want {
			t.Errorf("respaldo %q: %v", lang, err)
		}
		if r, m := reasonOf(err); r != "file.exists" || m["path"] != bk || strings.Contains(err.Error(), fraseResp) {
			t.Errorf("respaldo %q: reason %q metadata %v", lang, r, m)
		}
	}
}

// El idioma canónico es el inglés: sin accept-language (o con uno desconocido) el núcleo responde en inglés, no en es.
func TestSinIdiomaRespondeIngles(t *testing.T) {
	i18ntest.Default(t, i18n.En) // el resto de las pruebas del paquete fija es por omisión
	h := newHarness(t, nil)
	h.ready(t)
	tc := v1.NewToolsServiceClient(h.conn)
	const want = "the per-source rate must be between 1 and 10000 (0 = default), not 20000"
	for _, lang := range []string{"", "fr", "xx"} {
		st, err := tc.Syslog(con(t, lang), &v1.SyslogRequest{Addr: "127.0.0.1:0", RatePerSource: 20000})
		if err == nil {
			_, err = st.Recv()
		}
		if status.Code(err) != codes.InvalidArgument || status.Convert(err).Message() != want {
			t.Errorf("syslog con %q: %v", lang, err)
		}
	}
}
