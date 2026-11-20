package devices

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Fase 48-4: el host guardado lleva protocolo (ssh por omisión, telnet) y el puerto por omisión es el del protocolo.
func TestProtocoloDelHost(t *testing.T) {
	base := Host{Name: "sw1", Address: "10.0.0.1"}
	for _, c := range []struct {
		nombre, proto, plataforma, orden string
		port                             int
		wantProto                        string
		wantPort                         int
		campo                            string // vacío = válido
	}{
		{"sin protocolo es ssh", "", "ios-xe", "", 0, "ssh", 22, ""},
		{"ssh explícito", "ssh", "ios-xe", "", 0, "ssh", 22, ""},
		{"telnet al 23", "telnet", "ios-xe", "", 0, "telnet", 23, ""},
		{"telnet con puerto propio", "telnet", "", "", 2001, "telnet", 2001, ""},
		{"ssh con puerto propio", "ssh", "", "", 2222, "ssh", 2222, ""},
		{"protocolo desconocido", "rlogin", "", "", 0, "", 0, "protocol"},
		{"mayúsculas y espacios de un CSV", " Telnet ", "", "", 0, "telnet", 23, ""},
		{"telnet sin orden de inicio", "telnet", "linux", "tmux", 0, "", 0, "startup_command"},
	} {
		h := base
		h.Protocol, h.Platform, h.StartupCommand, h.Port = c.proto, c.plataforma, c.orden, c.port
		got, err := Clean(h)
		var fe *FieldError
		switch {
		case c.campo == "" && err != nil:
			t.Errorf("%s: %v", c.nombre, err)
		case c.campo != "" && (!errors.As(err, &fe) || fe.Field != c.campo):
			t.Errorf("%s: err = %v, quería el campo %s", c.nombre, err, c.campo)
		case c.campo == "" && (got.Protocol != c.wantProto || got.Port != c.wantPort):
			t.Errorf("%s: %s:%d, quería %s:%d", c.nombre, got.Protocol, got.Port, c.wantProto, c.wantPort)
		}
	}
}

// El protocolo viaja en el archivo de export (solo telnet: un host ssh queda igual que antes, con su misma suma) y
// cuenta para «igual» al importar.
func TestProtocoloEnElArchivo(t *testing.T) {
	ssh := Host{Name: "a", Address: "10.0.0.1", Port: 22, Protocol: "ssh"}
	tel := Host{Name: "b", Address: "10.0.0.2", Port: 23, Protocol: "telnet"}
	if f := ToFile(ssh, ""); f.Protocol != "" {
		t.Errorf("un host ssh lleva protocolo en el archivo: %q", f.Protocol)
	}
	if f := ToFile(tel, ""); f.Protocol != "telnet" || f.Host().Protocol != "telnet" {
		t.Errorf("telnet no viaja: %+v", f)
	}
	otro := tel
	otro.Protocol = "ssh"
	if Same(tel, otro) {
		t.Error("Same ignora el protocolo")
	}
	// CSV: el encabezado nuevo lleva protocol al final y los de antes (sin protocol, y sin startup_command) se aceptan.
	h := HostsHeader()
	if h[len(h)-1] != "protocol" {
		t.Fatalf("encabezado = %v", h)
	}
	for _, hdr := range [][]string{h, h[:len(h)-1], h[:len(h)-2]} {
		if err := checkHeader(hdr); err != nil {
			t.Errorf("encabezado %s: %v", strings.Join(hdr, ","), err)
		}
	}
}

// Un host ssh exportado sale con los mismos bytes que antes de la fase 48 (sin el campo protocol), así que su suma no
// cambia; un CSV telnet sin puerto entra en el 23.
func TestProtocoloExportSshIgualYCSVTelnet(t *testing.T) {
	b, err := json.Marshal(ToFile(Host{Name: "a", Address: "10.0.0.1", Port: 22, Protocol: "ssh", Tags: []string{}}, ""))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"name":"a","address":"10.0.0.1","port":22,"platform":"","folder":"","tags":[],"credential_label":"","notes":""}`; string(b) != want {
		t.Fatalf("export ssh = %s\nquería      %s", b, want)
	}
	got, err := ParseHostsCSV([]byte(strings.Join(HostsHeader(), ",") + "\nviejo,10.0.0.7,,ios,,,,,,telnet\n"))
	if err != nil || len(got.Errors) != 0 || len(got.Hosts) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	h, err := Clean(got.Hosts[0].Host())
	if err != nil || h.Protocol != "telnet" || h.Port != 23 || Key(h) != "10.0.0.7:23" {
		t.Fatalf("csv telnet = %+v %v", h, err)
	}
}
