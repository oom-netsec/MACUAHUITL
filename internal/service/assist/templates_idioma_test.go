package assist

import (
	"context"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/assist"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// Fase 30e: las plantillas salen en el idioma pedido; con es, el texto de las plantillas del núcleo (y el catálogo en es
// no se desvía de él); con en, ningún nombre, etiqueta o ayuda queda en español.
func TestPlantillasEsYEn(t *testing.T) {
	r := newRig(t, simulator.Config{})
	es, err := r.svc.ListSnippetTemplates(i18n.WithLocale(context.Background(), "es"), &v1.ListSnippetTemplatesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	en, _ := r.svc.ListSnippetTemplates(i18n.WithLocale(context.Background(), "en"), &v1.ListSnippetTemplatesRequest{})
	src := assist.Templates()
	if len(es.Templates) != len(src) || len(en.Templates) != len(src) {
		t.Fatalf("%d %d %d", len(es.Templates), len(en.Templates), len(src))
	}
	same := 0
	for i, tp := range src {
		check := func(key, want, gotEs, gotEn string) {
			if gotEs != want || !i18n.Has(key) || i18n.Msg("es", key, nil) != want {
				t.Errorf("%s: es %q / catálogo %q, quería %q", key, gotEs, i18n.Msg("es", key, nil), want)
			}
			if gotEn == "" || (gotEn == want && want != "") {
				same++
				t.Logf("%s: el inglés es igual al español: %q", key, want)
			}
		}
		check("snippet."+tp.ID+".name", tp.Name, es.Templates[i].Name, en.Templates[i].Name)
		for j, f := range tp.Fields {
			k := "snippet." + tp.ID + ".field." + f.Name
			check(k, f.Label, es.Templates[i].Fields[j].Label, en.Templates[i].Fields[j].Label)
			if f.Help != "" {
				check(k+".help", f.Help, es.Templates[i].Fields[j].Help, en.Templates[i].Fields[j].Help)
			}
		}
	}
	t.Logf("textos iguales en los dos idiomas: %d", same)
}
