package scripts

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
	dom "github.com/oom-netsec/MACUAHUITL/internal/scripts"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

var hexID = regexp.MustCompile(`[0-9a-f]{32}`)

// avisosCasos recorre los avisos de la vista previa y de la aplicación de un import; ctx fija el idioma.
func avisosCasos(t *testing.T, ctx context.Context) map[string]string {
	t.Helper()
	out := map[string]string{}
	j := func(ws []string) string { return hexID.ReplaceAllString(strings.Join(ws, " | "), "<ID>") }
	b, _ := nuevoSvc(t)
	guardar(t, b, "Mio", "show version")
	s1 := dom.Script{ID: dom.NewID(), Name: "mio", Tech: "l2", Platform: "ios-xe", Commands: []string{"show clock"}, Tags: []string{}, Origin: "usuario"}
	s2 := dom.Script{ID: dom.NewID(), Name: "Otro", Tech: "l2", Platform: "ios-xe", Commands: []string{"show users"}, Tags: []string{}, Origin: "usuario"}
	s3 := dom.Script{ID: dom.NewID(), Name: "Omitido", Tech: "l2", Platform: "ios-xe", Commands: []string{"show arp"}, Tags: []string{}, Origin: "usuario"}
	c := dom.Coleccion{ID: dom.NewID(), Name: "Kit", ScriptIDs: []string{s1.ID, "lib-no-existe", s2.ID, "lib-l2-stp", s3.ID}}
	raw, err := dom.MarshalColecciones([]dom.Coleccion{c}, []dom.Script{s1, s2, s3}, b.clock())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "k.json")
	if err := service.WriteExport(context.Background(), path, raw, false); err != nil {
		t.Fatal(err)
	}
	p, err := b.PreviewImportCollections(ctx, &v1.PreviewImportCollectionsRequest{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	out["col-preview"] = j(p.Warnings)
	ap, err := b.ApplyImportCollections(ctx, &v1.ApplyImportCollectionsRequest{Token: p.Token, ScriptDecisions: decs(s1.ID, "renombrar", s3.ID, "omitir")})
	if err != nil {
		t.Fatal(err)
	}
	out["col-apply"] = j(ap.Warnings)
	// sin suma
	s, _ := nuevoSvc(t)
	sc := dom.Script{ID: dom.NewID(), Name: "Sin suma", Tech: "l2", Platform: "ios-xe", Commands: []string{"show clock"}, Tags: []string{}, Origin: "usuario"}
	rawS, _ := dom.Marshal([]dom.Script{sc}, s.clock())
	ps, err := s.PreviewImport(ctx, &v1.PreviewImportRequest{Path: escribe(t, sinSuma(rawS))})
	if err != nil {
		t.Fatal(err)
	}
	out["script-sin-suma"] = j(ps.Warnings)
	return out
}

func TestAvisosImportEspanolRegresion(t *testing.T) {
	i18ntest.Golden(t, "testdata/avisos_es.golden.json", avisosCasos(t, i18n.WithLocale(context.Background(), "es")))
}

func TestAvisosImportEn(t *testing.T) {
	en := avisosCasos(t, i18n.WithLocale(context.Background(), "en"))
	want := map[string]string{
		"col-preview":     `collection "Kit": the script lib-no-existe is not in the local library; it will be skipped`,
		"script-sin-suma": "file without a checksum",
	}
	for k, w := range want {
		if en[k] != w {
			t.Errorf("%s: %q, quería %q", k, en[k], w)
		}
	}
	if !strings.Contains(en["col-apply"], "was not imported; it was removed from the collection") || !strings.Contains(en["col-apply"], `is not in the local library; it was skipped`) || strings.Contains(en["col-apply"], "colección") {
		t.Errorf("col-apply: %q", en["col-apply"])
	}
}
