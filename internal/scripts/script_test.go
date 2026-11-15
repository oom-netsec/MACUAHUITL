package scripts

import (
	"strings"
	"testing"
)

func valido() Script {
	return Script{ID: strings.Repeat("a1", 16), Name: "Mi script", Tech: "l2", Platform: "ios-xe",
		Commands: []string{"show vlan brief"}, Tags: []string{"vlan"}, Origin: OrigenUsuario}
}

func TestValidate(t *testing.T) {
	if err := valido().Validate(); err != nil {
		t.Fatalf("válido rechazado: %v", err)
	}
	casos := map[string]func(*Script){
		"nombre vacío":           func(s *Script) { s.Name = "" },
		"nombre de 65":           func(s *Script) { s.Name = strings.Repeat("n", 65) },
		"nombre con control":     func(s *Script) { s.Name = "a\tb" },
		"tech fuera de lista":    func(s *Script) { s.Tech = "voip" },
		"plataforma desconocida": func(s *Script) { s.Platform = "junos" },
		"descripción de 513":     func(s *Script) { s.Description = strings.Repeat("d", 513) },
		"sin comandos":           func(s *Script) { s.Commands = nil },
		"201 comandos": func(s *Script) {
			s.Commands = make([]string, 201)
			for i := range s.Commands {
				s.Commands[i] = "show clock"
			}
		},
		"comando de 513":     func(s *Script) { s.Commands = []string{strings.Repeat("x", 513)} },
		"comando vacío":      func(s *Script) { s.Commands = []string{"show clock", "  "} },
		"comando con tab":    func(s *Script) { s.Commands = []string{"show\tclock"} },
		"comando con CR":     func(s *Script) { s.Commands = []string{"show clock\r"} },
		"comando no ASCII":   func(s *Script) { s.Commands = []string{"show clóck"} },
		"11 etiquetas":       func(s *Script) { s.Tags = strings.Split("a b c d e f g h i j k", " ") },
		"etiqueta mayúscula": func(s *Script) { s.Tags = []string{"Vlan"} },
		"etiqueta de 25":     func(s *Script) { s.Tags = []string{strings.Repeat("a", 25)} },
		"etiqueta repetida":  func(s *Script) { s.Tags = []string{"a", "a"} },
		"origen desconocido": func(s *Script) { s.Origin = "otro" },
		"id mal formado":     func(s *Script) { s.ID = "xyz" },
	}
	for nombre, mut := range casos {
		s := valido()
		mut(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: debió rechazarse", nombre)
		}
	}
	// los límites exactos pasan
	s := valido()
	s.Name = strings.Repeat("n", 64)
	s.Description = strings.Repeat("d", 512)
	s.Commands = []string{strings.Repeat("x", 512)}
	s.Tags = []string{strings.Repeat("a", 24), "b-1"}
	if err := s.Validate(); err != nil {
		t.Fatalf("límites: %v", err)
	}
	// un ID de biblioteca solo vale con origen biblioteca
	s = valido()
	s.ID, s.Origin = "lib-l2-stp", OrigenBiblioteca
	if err := s.Validate(); err != nil {
		t.Fatalf("biblioteca: %v", err)
	}
	s.Origin = OrigenUsuario
	if err := s.Validate(); err == nil {
		t.Fatal("lib-* con origen usuario debió rechazarse")
	}
}

func TestReadOnly(t *testing.T) {
	s := valido()
	s.Commands = []string{"! revisión", "show vlan brief", "show run | include vlan"}
	if !s.ReadOnly() {
		t.Fatal("solo show debe ser read_only")
	}
	for _, cmd := range []string{"interface Gi1/0/1", "conf t", "write memory", "show clock | redirect flash:x"} {
		s.Commands = []string{"show clock", cmd}
		if s.ReadOnly() {
			t.Errorf("%q no debe ser read_only", cmd)
		}
	}
	s.Commands = []string{"! solo comentario"}
	if s.ReadOnly() {
		t.Fatal("sin comandos reales no es read_only")
	}
	// ASA tiene sus reglas: solo show es de lectura; «more system:running-config» muestra las claves.
	s.Platform, s.Commands = "asa", []string{"show version", "show conn count", "packet-tracer input inside tcp 10.0.0.1 1025 192.0.2.5 80"}
	if !s.ReadOnly() {
		t.Error("asa con solo show es read_only")
	}
	for _, c := range []string{"more system:running-config", "copy running-config disk0:x", "show tech-support file disk0:x", "changeto context admin"} {
		s.Commands = []string{"show version", c}
		if s.ReadOnly() {
			t.Errorf("asa %q no debe ser read_only", c)
		}
	}
	// «Enviar a la terminal» no mira la plataforma de la sesión: de solo lectura es lo inofensivo en IOS-XE y en ASA a la vez.
	for _, c := range []struct{ plat, cmd string }{{"asa", "show logging process ios to-file bootflash:x"}, {"ios-xe", "show tech-support file disk0:x"}} {
		s.Platform, s.Commands = c.plat, []string{c.cmd}
		if s.ReadOnly() {
			t.Errorf("%s %q no debe ser read_only", c.plat, c.cmd)
		}
	}
	for _, c := range []struct{ plat, cmd string }{{"ios-xe", "show ip interface brief | section x"}, {"asa", "show conn count"}} {
		s.Platform, s.Commands = c.plat, []string{c.cmd}
		if !s.ReadOnly() {
			t.Errorf("%s %q debe ser read_only", c.plat, c.cmd)
		}
	}
	// las demás plataformas no son read_only hasta que tengan sus reglas
	for _, p := range []string{"nx-os", "ftd", "wlc-aireos", "cualquiera"} {
		s.Platform, s.Commands = p, []string{"show version"}
		if s.ReadOnly() {
			t.Errorf("%s no debe ser read_only", p)
		}
	}
	s.Platform = "ios"
	s.Commands = []string{"show version"}
	if !s.ReadOnly() {
		t.Fatal("ios con show es read_only")
	}
	// «;» separa comandos en algunos shells: se rechaza en cualquier comando
	s.Commands = []string{"show version ; configure terminal"}
	if s.ReadOnly() {
		t.Fatal("un «;» no es read_only")
	}
	// solo una línea que empieza con «!» en la columna 0 es comentario
	for _, c := range []string{" !x", "!conf t"} {
		s.Commands = []string{"show clock", c}
		if got, want := s.ReadOnly(), c == "!conf t"; got != want {
			t.Errorf("%q: ReadOnly = %v", c, got)
		}
	}
}

func TestRunnableSaltaComentarios(t *testing.T) {
	got := Runnable([]string{"! nota", "show clock", "!conf t", " !x", "show version"})
	if len(got) != 3 || got[0] != "show clock" || got[1] != " !x" || got[2] != "show version" {
		t.Fatalf("Runnable = %q", got)
	}
}

func TestNameKeyUnicaParaTodoElPaquete(t *testing.T) {
	if NameKey("aς") != NameKey("aσ") || NameKey("Hola") != NameKey("hOLA") || NameKey("a") == NameKey("b") {
		t.Fatalf("claves: %q %q", NameKey("aς"), NameKey("aσ"))
	}
}

func TestNewIDUnicoYValido(t *testing.T) {
	a, b := NewID(), NewID()
	if a == b || len(a) != 32 {
		t.Fatalf("ids: %q %q", a, b)
	}
	s := valido()
	s.ID = a
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}

// Nombre y descripción con controles bidi (U+202E, U+2066…) se rechazan: engañan a la vista (trojan source).
func TestValidateRechazaBidi(t *testing.T) {
	for _, mod := range []func(*Script){
		func(s *Script) { s.Name = "Mi \u202escript" },
		func(s *Script) { s.Name = "Mi \u2066script\u2069" },
		func(s *Script) { s.Description = "linea\n\u200fotra" },
	} {
		s := valido()
		mod(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("aceptado: %q / %q", s.Name, s.Description)
		}
	}
}

// Emoji con ZWJ o guion suave en nombre y descripción siguen valiendo (datos ya guardados se pueden editar e
// importar); solo los controles de dirección (bidi) se rechazan.
func TestValidateAceptaFormatoLegitimo(t *testing.T) {
	s := valido()
	s.Name = "Mi \U0001F468\u200d\U0001F4BB script"
	s.Description = "re\u00advisión\nde VLAN"
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.Name = "Mi \u061cscript"
	if err := s.Validate(); err == nil {
		t.Fatal("U+061C aceptado")
	}
}

// El error de tecnología o plataforma fuera de la lista nombra también el nombre canónico en inglés de cada valor.
func TestErrorDeTecnologiaListaTambienElIngles(t *testing.T) {
	s := Script{ID: "lib-x", Origin: OrigenBiblioteca, Name: "X", Tech: "managment", Platform: "ios", Commands: []string{"show clock"}}
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "gestion/management") || !strings.Contains(err.Error(), "diagnostico/diagnostics") {
		t.Fatalf("err = %v", err)
	}
	s.Tech, s.Platform = "l2", "cualquier"
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "cualquiera/any") {
		t.Fatalf("err = %v", err)
	}
}
