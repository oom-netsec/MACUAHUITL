package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// Un archivo de hosts es dato ajeno: una fila Telnet no ata una credencial de la bóveda por su etiqueta (Telnet va en
// claro y no hay huella que confirmar). El host queda con credencial tecleada, como al elegir Telnet en la libreta, y
// la vista previa lo dice (protocolo, telnet_typed y un aviso). Una fila SSH con la misma etiqueta sí la ata.
func TestImportTelnetNoAtaCredencial(t *testing.T) {
	s, d := nuevoSvc(t)
	cid := cred(t, d, "admin lab")
	csv := "name,address,port,platform,folder,tags,credential_label,notes,startup_command,protocol\n" +
		"SW-CORE,203.0.113.66,,ios-xe,,,admin lab,,,telnet\n" +
		"SW-SSH,203.0.113.67,,ios-xe,,,admin lab,,,ssh\n" +
		"SW-TEL,203.0.113.68,,ios-xe,,,,,,telnet\n"
	ruta := filepath.Join(t.TempDir(), "h.csv")
	os.WriteFile(ruta, []byte(csv), 0o600)
	p, err := s.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: ruta})
	if err != nil || len(p.Items) != 3 {
		t.Fatalf("preview: %v %v", p, err)
	}
	por := map[string]*v1.ImportHostItem{}
	for _, it := range p.Items {
		por[it.Host.Name] = it
	}
	if it := por["SW-CORE"]; it.Host.Protocol != "telnet" || !it.TelnetTyped || it.CredentialMissing {
		t.Fatalf("SW-CORE = %v", it)
	}
	if it := por["SW-SSH"]; it.Host.Protocol != "ssh" || it.TelnetTyped || it.CredentialMissing {
		t.Fatalf("SW-SSH = %v", it)
	}
	if it := por["SW-TEL"]; it.Host.Protocol != "telnet" || it.TelnetTyped {
		t.Fatalf("SW-TEL (sin etiqueta) = %v", it)
	}
	if w := strings.Join(p.Warnings, "|"); !strings.Contains(w, "Telnet") {
		t.Fatalf("avisos = %q", w)
	}
	a, err := s.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token})
	if err != nil || a.Created != 3 {
		t.Fatalf("apply: %v %v", a, err)
	}
	for _, x := range lista(t, s, &v1.ListDevicesRequest{}) {
		switch x.Name {
		case "SW-CORE", "SW-TEL":
			if x.CredentialId != "" || x.Protocol != "telnet" {
				t.Fatalf("%s importado = %v", x.Name, x)
			}
		case "SW-SSH":
			if x.CredentialId != cid {
				t.Fatalf("SW-SSH importado = %v", x)
			}
		}
	}
	if au := d.AuditText(); !strings.Contains(au, "with_credential=1") || !strings.Contains(au, "telnet=2") {
		t.Fatalf("auditoría: %s", au)
	}
}

// «Reemplazar» un host guardado con credencial por una fila «TELNET » del archivo: no hereda la credencial vieja ni ata
// la de la etiqueta.
func TestImportTelnetReemplazoNoHeredaCredencial(t *testing.T) {
	s, d := nuevoSvc(t)
	cid := cred(t, d, "admin lab")
	poner(t, s, &v1.Device{Name: "SW-CORE", Target: &v1.Target{Address: "10.0.0.1"}, Platform: "ios-xe", CredentialId: cid})
	csv := "name,address,port,platform,folder,tags,credential_label,notes,startup_command,protocol\n" +
		"SW-CORE,203.0.113.66,,ios-xe,,,admin lab,,, TELNET \n"
	ruta := filepath.Join(t.TempDir(), "h.csv")
	if err := os.WriteFile(ruta, []byte(csv), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := s.PreviewImportHosts(bg, &v1.PreviewImportHostsRequest{Path: ruta})
	if err != nil || len(p.Items) != 1 || !p.Items[0].TelnetTyped || p.Items[0].State != "conflicto" {
		t.Fatalf("preview: %v %v", p, err)
	}
	if _, err := s.ApplyImportHosts(bg, &v1.ApplyImportHostsRequest{Token: p.Token, Decisions: []*v1.ImportHostDecision{{Key: p.Items[0].Key, Action: "replace"}}}); err != nil {
		t.Fatal(err)
	}
	for _, x := range lista(t, s, &v1.ListDevicesRequest{}) {
		if x.CredentialId != "" {
			t.Fatalf("quedó con credencial: %v", x)
		}
	}
}
