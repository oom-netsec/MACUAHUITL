package pack

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/scripts"
)

func userScript(name, plat string, cmds ...string) scripts.Script {
	return scripts.Script{ID: scripts.NewID(), Name: name, Tech: "l2", Platform: plat, Description: "desc " + name,
		Commands: cmds, Tags: []string{"uno", "dos"}, Origin: scripts.OrigenUsuario}
}

func userPB(plat, id string, cmds ...string) playbook.Playbook {
	pb := playbook.Playbook{ID: plat + "/" + id, Platform: plat, Name: "PB " + id, NameEn: "PB en " + id}
	for _, c := range cmds {
		pb.Commands = append(pb.Commands, playbook.Command{Text: c, Timeout: 60 * time.Second})
	}
	return pb
}

func exportIn(sc []scripts.Script, pbs []playbook.Playbook) ExportInput {
	return ExportInput{ID: "acme/mio", Core: "v0.3.0", Now: time.Date(2026, 11, 13, 14, 5, 0, 0, time.Local), Scripts: sc, Playbooks: pbs}
}

// El .mpack exportado pasa Verify como NO oficial y trae lo que se pidió con las reglas del ADR.
func TestExportPasaVerifyComoNoOficial(t *testing.T) {
	sc := []scripts.Script{userScript("Uno", "ios", "show version"), userScript("Dos", "cualquiera", "show clock")}
	pbs := []playbook.Playbook{userPB("ios-xe", "mio", "show clock"), userPB("nx-os", "nx", "show clock"), userPB("ios", "acme-ya", "show version")}
	r, err := Export(exportIn(sc, pbs))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Verify(r.Data, "v0.3.0", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Official || p.ID != "acme/mio" || p.Version != "2026.1113.140500" || p.MinCore != "0.3.0" || p.License != "NOASSERTION" ||
		p.NameEn != p.Name || p.DescriptionEn != p.Description || len(p.Scripts) != 2 || len(p.Playbooks) != 2 {
		t.Fatalf("%+v", p.Manifest)
	}
	for _, s := range p.Scripts {
		if !strings.HasPrefix(s.ID, "lib-acme-") || len(s.ID) != len("lib-acme-")+12 {
			t.Fatal(s.ID)
		}
	}
	if p.Playbooks[0].ID != "ios-xe/acme-mio" || p.Playbooks[1].ID != "ios/acme-ya" {
		t.Fatalf("%v %v", p.Playbooks[0].ID, p.Playbooks[1].ID)
	}
	if len(r.Omitted) != 1 || r.Omitted[0] != "nx-os/nx" {
		t.Fatal(r.Omitted)
	}
	if !strings.Contains(p.Readme, "Uno") || !strings.Contains(p.Readme, "ios-xe/acme-mio") {
		t.Fatal(p.Readme)
	}
	// Se instala con allow_unsigned y no sin él.
	s, _ := openStore(t, t.TempDir(), nil, Base{})
	if _, err := s.Install(r.Data, false); Reason(err) != "unsigned" {
		t.Fatal(err)
	}
	if _, err := s.Install(r.Data, true); err != nil {
		t.Fatal(err)
	}
}

func TestExportMinCoreDev(t *testing.T) {
	in := exportIn([]scripts.Script{userScript("Uno", "ios", "show version")}, nil)
	in.Core = "dev"
	r, err := Export(in)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Verify(r.Data, "v0.0.1", nil)
	if err != nil || p.MinCore != "0.0.0" {
		t.Fatal(err, p)
	}
}

func TestExportRechazos(t *testing.T) {
	ok := []scripts.Script{userScript("Uno", "ios", "show version")}
	cases := []struct {
		name   string
		mod    func(*ExportInput)
		reason string
	}{
		{"editor oom", func(in *ExportInput) { in.ID = "oom/x" }, "editor.reserved"},
		{"editor segmento reservado", func(in *ExportInput) { in.ID = "l2/x" }, "editor.reserved"},
		{"editor con guion", func(in *ExportInput) { in.ID = "a-b/x" }, "manifest.invalid"},
		{"id sin barra", func(in *ExportInput) { in.ID = "acme" }, "manifest.invalid"},
		{"vacío", func(in *ExportInput) { in.Scripts = nil }, "export.empty"},
		{"solo playbooks no exportables", func(in *ExportInput) {
			in.Scripts = nil
			in.Playbooks = []playbook.Playbook{userPB("nx-os", "a", "show clock")}
		}, "export.empty"},
		{"nombres repetidos", func(in *ExportInput) { in.Scripts = append(in.Scripts, userScript("UNO", "ios", "show clock")) }, "export.name_dup"},
		{"licencia mala", func(in *ExportInput) { in.License = "no es spdx!" }, "manifest.invalid"},
	}
	for _, c := range cases {
		in := exportIn(ok, nil)
		c.mod(&in)
		if _, err := Export(in); Reason(err) != c.reason {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// Un playbook con ID que no sirve como script derivado se omite con aviso; no tumba el export.
func TestExportOmiteIDInvalido(t *testing.T) {
	pbs := []playbook.Playbook{userPB("ios", "con_guion_bajo", "show clock"), userPB("ios", "bueno", "show clock"), userPB("ios-xe", "bueno", "show clock")}
	pbs[2].Name = "Otro nombre"
	r, err := Export(exportIn(nil, pbs))
	if err != nil {
		t.Fatal(err)
	}
	// ios/bueno y ios-xe/bueno quedarían en el mismo archivo playbooks/acme-bueno.yaml: el segundo se omite.
	if fmt.Sprint(r.Omitted) != "[ios/con_guion_bajo ios-xe/bueno]" || r.Playbooks != 1 {
		t.Fatal(r.Omitted, r.Playbooks)
	}
}

func TestExportREADMEConTopeDeLista(t *testing.T) {
	var sc []scripts.Script
	for i := range 1000 {
		sc = append(sc, userScript(fmt.Sprintf("%03d ", i)+strings.Repeat("x", 60), "ios", "show clock"))
	}
	r, err := Export(exportIn(sc, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(r.Data, "v0.3.0", nil); err != nil {
		t.Fatal(err)
	}
}

// Un playbook propio cuyo script derivado se llama como uno de la base o de un instalado se omite: Install lo rechazaría por colisión.
func TestExportOmiteNombreOcupado(t *testing.T) {
	in := exportIn(nil, []playbook.Playbook{userPB("ios", "uno", "show clock"), userPB("ios", "dos", "show version")})
	in.TakenNames = []string{"pb UNO"}
	r, err := Export(in)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(r.Omitted) != "[ios/uno]" || r.Playbooks != 1 {
		t.Fatal(r.Omitted, r.Playbooks)
	}
}
