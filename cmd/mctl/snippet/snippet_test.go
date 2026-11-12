package snippet

import (
	"bufio"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func TestParseSets(t *testing.T) {
	got, err := parseSets(cli.List{"interfaces=Gi1/0/1,Gi1/0/2", "descripcion=a=b", "vacio="})
	if err != nil || got["interfaces"] != "Gi1/0/1,Gi1/0/2" || got["descripcion"] != "a=b" || got["vacio"] != "" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []cli.List{{"sin-igual"}, {"=x"}, {"a=1", "a=2"}} {
		if _, err := parseSets(bad); err == nil {
			t.Errorf("%v aceptado", bad)
		}
	}
}

// Los secretos que no vienen en --set se piden sin eco (aquí, por stdin) y nunca se imprimen.
func TestFillSecretsPromptsOnlyForMissingRequiredSecrets(t *testing.T) {
	tpl := &v1.SnippetTemplate{Id: "x", Fields: []*v1.SnippetField{
		{Name: "clave", Label: "Clave", Type: "secret", Required: true},
		{Name: "otra", Label: "Otra", Type: "secret", Required: true},
		{Name: "opc", Label: "Opcional", Type: "secret"},
		{Name: "texto", Label: "Texto", Type: "text", Required: true},
	}}
	var out strings.Builder
	c := &cli.Env{In: bufio.NewReader(strings.NewReader("S3cr3to-1\n")), Out: &out}
	vals := map[string]string{"otra": "ya-dada"}
	if err := fillSecrets(c, tpl, vals); err != nil {
		t.Fatal(err)
	}
	if vals["clave"] != "S3cr3to-1" || vals["otra"] != "ya-dada" || vals["opc"] != "" || vals["texto"] != "" {
		t.Fatalf("%v", vals)
	}
	if strings.Contains(out.String(), "S3cr3to") {
		t.Fatalf("el secreto salió por la salida: %q", out.String())
	}
	// Sin nada que leer el comando falla, no sigue con un secreto vacío.
	for _, in := range []string{"", "\n"} {
		c = &cli.Env{In: bufio.NewReader(strings.NewReader(in)), Out: &out}
		if err := fillSecrets(c, tpl, map[string]string{"otra": "x"}); err == nil {
			t.Errorf("secreto vacío aceptado (entrada %q)", in)
		}
	}
}
