package scripts

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
	dom "github.com/oom-netsec/MACUAHUITL/internal/scripts"
)

// guionesCasos recorre la biblioteca de fábrica y los errores de validación y de los RPC de scripts y colecciones;
// ctx fija el idioma.
func guionesCasos(t *testing.T, ctx context.Context) map[string]string {
	t.Helper()
	out := map[string]string{}
	put := func(n string, err error) {
		out[n] = "ok"
		if err != nil {
			out[n] = "ERROR: " + err.Error()
		}
	}
	s, _ := nuevoSvc(t)
	lib, err := s.ListScripts(ctx, &v1.ListScriptsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	cfg := ""
	for _, x := range lib.Scripts {
		if x.Origin == dom.OrigenBiblioteca {
			if cfg == "" && strings.HasPrefix(x.Name, "Config · ") {
				cfg = x.Id
			}
			names = append(names, x.Id+" | "+x.Name+" | "+x.Description)
		}
	}
	sort.Strings(names)
	b, _ := json.Marshal(names)
	out["biblioteca"] = string(b)
	g, err := s.GetScript(ctx, &v1.GetScriptRequest{Id: cfg})
	if err != nil {
		put("lib_get", err)
	} else {
		out["lib_get"] = g.Script.Name + " | " + g.Script.Description
	}
	_, err = s.GetScript(ctx, &v1.GetScriptRequest{Id: "lib-no-existe"})
	put("get_lib_no_existe", err)
	_, err = s.GetScript(ctx, &v1.GetScriptRequest{Id: "0123456789abcdef0123456789abcdef"})
	put("get_no_existe", err)

	ok := func() *v1.Script {
		return &v1.Script{Name: "Mi script", Tech: "gestion", Platform: "ios-xe", Commands: []string{"show version"}}
	}
	long := strings.Repeat("x", 600)
	mut := map[string]func(x *v1.Script){
		"nombre_vacio":  func(x *v1.Script) { x.Name = "" },
		"tecnologia":    func(x *v1.Script) { x.Tech = "nada" },
		"plataforma":    func(x *v1.Script) { x.Platform = "nada" },
		"descripcion":   func(x *v1.Script) { x.Description = long },
		"sin_comandos":  func(x *v1.Script) { x.Commands = nil },
		"comando_vacio": func(x *v1.Script) { x.Commands = []string{" "} },
		"comando_ascii": func(x *v1.Script) { x.Commands = []string{"show vérsion"} },
		"muchas_etiquetas": func(x *v1.Script) {
			for i := 0; i < 30; i++ {
				x.Tags = append(x.Tags, "t"+string(rune('a'+i%26))+string(rune('a'+i/26)))
			}
		},
		"etiqueta_mala": func(x *v1.Script) { x.Tags = []string{"MAL"} },
		"etiqueta_dup":  func(x *v1.Script) { x.Tags = []string{"a", "a"} },
		"id_malo":       func(x *v1.Script) { x.Id = "zzz" },
		"id_biblioteca": func(x *v1.Script) { x.Id = cfg },
		"nombre_de_lib": func(x *v1.Script) { x.Name = lib.Scripts[0].Name },
	}
	for n, f := range mut {
		x := ok()
		f(x)
		_, err := s.SaveScript(ctx, &v1.SaveScriptRequest{Script: x})
		put("guardar_"+n, err)
	}
	_, err = s.SaveScript(ctx, &v1.SaveScriptRequest{})
	put("guardar_sin_script", err)
	_, err = s.DeleteScript(ctx, &v1.DeleteScriptRequest{Id: cfg})
	put("borrar_lib", err)
	_, err = s.DeleteScript(ctx, &v1.DeleteScriptRequest{Id: "0123456789abcdef0123456789abcdef"})
	put("borrar_no_existe", err)
	_, err = s.DuplicateScript(ctx, &v1.DuplicateScriptRequest{Id: "0123456789abcdef0123456789abcdef"})
	put("duplicar_no_existe", err)
	_, err = s.SetFavorite(ctx, &v1.SetFavoriteRequest{Id: "lib-no-existe", Favorite: true})
	put("favorito_no_existe", err)
	_, err = s.ExportScripts(ctx, &v1.ExportScriptsRequest{})
	put("exportar_vacio", err)
	_, err = s.ExportScripts(ctx, &v1.ExportScriptsRequest{Ids: make([]string, 2000), Path: "/tmp/x"})
	put("exportar_muchos", err)
	_, err = s.ApplyImport(ctx, &v1.ApplyImportRequest{Token: "no-existe"})
	put("importar_token", err)
	_, err = s.PreviewImport(ctx, &v1.PreviewImportRequest{Path: "relativa"})
	put("importar_ruta", err)

	_, err = s.GetCollection(ctx, &v1.GetCollectionRequest{Id: "0123456789abcdef0123456789abcdef"})
	put("col_get_no_existe", err)
	_, err = s.SaveCollection(ctx, &v1.SaveCollectionRequest{})
	put("col_guardar_vacia", err)
	for n, c := range map[string]*v1.Collection{"nombre": {Name: ""}, "descripcion": {Name: "x", Description: long}, "id": {Id: "zz", Name: "x"}, "favoritos": {Id: "favoritos", Name: "otro"}} {
		_, err = s.SaveCollection(ctx, &v1.SaveCollectionRequest{Collection: c})
		put("col_guardar_"+n, err)
	}
	_, err = s.DeleteCollection(ctx, &v1.DeleteCollectionRequest{Id: "favoritos"})
	put("col_borrar_favoritos", err)
	_, err = s.DeleteCollection(ctx, &v1.DeleteCollectionRequest{Id: "0123456789abcdef0123456789abcdef"})
	put("col_borrar_no_existe", err)
	_, err = s.ReorderCollections(ctx, &v1.ReorderCollectionsRequest{Ids: []string{"x"}})
	put("col_orden", err)
	_, err = s.SetCollectionScripts(ctx, &v1.SetCollectionScriptsRequest{Id: "favoritos", ScriptIds: []string{cfg, cfg}})
	put("col_scripts_repetido", err)
	_, err = s.SetCollectionScripts(ctx, &v1.SetCollectionScriptsRequest{Id: "0123456789abcdef0123456789abcdef"})
	put("col_scripts_no_existe", err)
	_, err = s.SetPinned(ctx, &v1.SetPinnedRequest{Id: "lib-no-existe", Pinned: true})
	put("fijar_no_existe", err)
	_, err = s.ReorderPinned(ctx, &v1.ReorderPinnedRequest{Ids: []string{"x"}})
	put("fijar_orden", err)
	_, err = s.ExportCollections(ctx, &v1.ExportCollectionsRequest{})
	put("col_exportar_vacio", err)
	_, err = s.ExportCollections(ctx, &v1.ExportCollectionsRequest{Ids: []string{"0123456789abcdef0123456789abcdef"}, Path: "/tmp/x"})
	put("col_exportar_no_existe", err)
	_, err = s.ApplyImportCollections(ctx, &v1.ApplyImportCollectionsRequest{Token: "no-existe"})
	put("col_importar_token", err)
	_, err = s.ImportTemplate(ctx, &v1.ImportTemplateRequest{Kind: "raro"})
	put("plantilla_tipo", err)
	_, err = s.ImportFormat(ctx, &v1.ImportFormatRequest{Kind: "raro"})
	put("formato_tipo", err)
	return out
}

func TestGuionesRegresionEs(t *testing.T) {
	base := guionesCasos(t, context.Background())
	i18ntest.Golden(t, "testdata/guiones_es.golden.json", base)
	for _, loc := range []string{"es", "es-MX", "fr"} {
		for k, v := range guionesCasos(t, i18n.WithLocale(context.Background(), loc)) {
			if base[k] != v {
				t.Errorf("%s con %q difiere de sin idioma", k, loc)
			}
		}
	}
}

// Con en, los scripts de fábrica salen con nombre y descripción en inglés y los errores de validación sin español;
// los scripts del usuario no se traducen.
func TestGuionesEnIngles(t *testing.T) {
	es := regexp.MustCompile(`[áéíóúñ¿]|\b(el|la|los|las|de|del|con|sin|para|solo|hay|ya|falta|una|un)\b`)
	ids := regexp.MustCompile(`lib-[a-z0-9-]+|ios-xe/[a-z0-9-]+`)
	en := i18n.WithLocale(context.Background(), "en")
	base := guionesCasos(t, context.Background())
	for k, v := range guionesCasos(t, en) {
		if k == "biblioteca" {
			var got, was []string
			json.Unmarshal([]byte(v), &got)
			json.Unmarshal([]byte(base[k]), &was)
			for i := range got {
				if got[i] == was[i] || es.MatchString(ids.ReplaceAllString(got[i], "")) {
					t.Errorf("biblioteca sin traducir: %q (es %q)", got[i], was[i])
				}
			}
			continue
		}
		if k == "col_exportar_vacio" || k == "exportar_vacio" || k == "importar_ruta" || k == "guardar_nombre_de_lib" { // texto de service o dato de la biblioteca
			continue
		}
		if m := es.FindString(ids.ReplaceAllString(v, "")); m != "" {
			t.Errorf("%s: queda español (%q): %s", k, m, v)
		}
	}
	s, _ := nuevoSvc(t)
	mio := guardar(t, s, "Mi guion útil")
	r, err := s.GetScript(en, &v1.GetScriptRequest{Id: mio.Id})
	if err != nil || r.Script.Name != "Mi guion útil" {
		t.Fatalf("un script del usuario no se traduce: %v %v", r, err)
	}
	g, err := s.GetScript(en, &v1.GetScriptRequest{Id: "lib-cfg-ntp"})
	if err != nil || g.Script.Name != "Config · NTP" || !strings.HasPrefix(g.Script.Description, "Synchronizes") {
		t.Fatalf("%v %v", g, err)
	}
}
