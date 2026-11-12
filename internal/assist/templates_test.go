package assist

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// campos cubre un campo de cada tipo; ninguno es obligatorio salvo req.
func typed(typ FieldType, mod ...func(*Field)) Template {
	f := Field{Name: "x", Label: "X", Type: typ}
	for _, m := range mod {
		if m != nil {
			m(&f)
		}
	}
	return Template{ID: "t", Tech: "l2", Fields: []Field{f}}
}

func TestValidateValuesEachType(t *testing.T) {
	choices := func(f *Field) { f.Choices = []string{"add", "remove"} }
	rng := func(f *Field) { f.Min, f.Max = 30, 100 }
	cases := []struct {
		typ       FieldType
		mod       func(*Field)
		ok, wrong []string
	}{
		{TypeText, func(f *Field) { f.Pattern = `^[A-Z]+$`; f.Max = 5 }, []string{"ABC"}, []string{"abc", "ABCDEF", "A?B", "Ñ", "A\tB"}},
		{TypeInt, rng, []string{"30", "100", "55"}, []string{"29", "101", "abc", "5.5", "+40", "040", "-40"}},
		{TypeDecimal, func(f *Field) { f.Min, f.Max = 0, 100 }, []string{"0", "0.5", "99.99", "100.00", "100"}, []string{"100.01", "1.234", "-1", "1,5", ".5", "abc"}},
		{TypeBool, nil, []string{"true", "false"}, []string{"si", "1", "TRUE"}},
		{TypeChoice, choices, []string{"add", "remove"}, []string{"set", "ADD", "add,remove"}},
		{TypeIPv4, nil, []string{"10.1.2.3", "192.168.0.1"}, []string{"10.1.2", "10.1.2.256", "::1", "10.1.2.3/24", "10.1.2.3 ", "010.1.2.3", "10.1.2.3%eth0"}},
		{TypeIPv4Mask, nil, []string{"255.255.255.0", "255.255.255.252", "255.255.255.255", "255.0.0.0"}, []string{"255.0.255.0", "0.0.0.0", "24", "255.255.255", "255.255.255.256"}},
		{TypeInterface, nil, []string{"Gi1/0/1", "GigabitEthernet1/0/48", "Port-channel1", "Po2"}, []string{"Vlan10", "Loopback0", "Gi1/0/1.10", "Gi1/0/1,Gi1/0/2", ""}},
		{TypeInterfaces, nil, []string{"Gi1/0/1", "Gi1/0/1, Gi1/0/2", "Gi1/0/1-4", "gi1/0/1 gi1/0/2"}, []string{"Po1", "Vlan10", "Gi1/0/4-1", "Gi1/0/1-99", "range Gi1/0/1"}},
		{TypeVlanID, nil, []string{"1", "10", "4094"}, []string{"0", "4095", "-1", "ten", "010"}},
		{TypeSecret, func(f *Field) { f.Min, f.Max = 8, 20 }, []string{"abcdefgh", "Zx9.-_~@:,"}, []string{"corta", "tiene espacio xx", "con?interroga", strings.Repeat("a", 21)}},
	}
	for _, c := range cases {
		tpl := typed(c.typ, c.mod)
		for _, v := range c.ok {
			if err := ValidateValues(tpl, Values{"x": v}); err != nil {
				t.Errorf("%s: %q rechazado: %v", c.typ, v, err)
			}
		}
		for _, v := range c.wrong {
			if v == "" { // vacío equivale a ausente, y solo falla si es obligatorio
				continue
			}
			if err := ValidateValues(tpl, Values{"x": v}); err == nil || !errors.Is(err, ErrInvalidValues) {
				t.Errorf("%s: %q aceptado (%v)", c.typ, v, err)
			}
		}
	}
}

func TestValidateValuesUnknownMissingAndEmpty(t *testing.T) {
	tpl := Template{ID: "t", Tech: "l2", Fields: []Field{{Name: "a", Label: "A", Type: TypeText, Required: true}, {Name: "b", Label: "B", Type: TypeInt}}}
	if err := ValidateValues(tpl, Values{"a": "hola"}); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]Values{"falta": {}, "vacío": {"a": ""}, "en blanco": {"a": "   "}, "desconocida": {"a": "x", "c": "1"}, "nil": nil} {
		if err := ValidateValues(tpl, v); err == nil {
			t.Errorf("%s aceptado", name)
		}
	}
	// Un opcional vacío es lo mismo que ausente (la UI manda todo el formulario).
	if err := ValidateValues(tpl, Values{"a": "x", "b": ""}); err != nil {
		t.Fatal(err)
	}
	// Todos los problemas en un solo error, y el texto fuera de ASCII no se cuela.
	err := ValidateValues(tpl, Values{"b": "z", "c": "1"})
	if err == nil || !strings.Contains(err.Error(), "falta") || !strings.Contains(err.Error(), "desconocido") || !strings.Contains(err.Error(), "B") {
		t.Fatalf("error = %v", err)
	}
	if err := ValidateValues(tpl, Values{"a": "café"}); err == nil {
		t.Error("no ASCII aceptado")
	}
	if err := ValidateValues(tpl, Values{"a": "x\r\nreload"}); err == nil {
		t.Error("salto de línea aceptado")
	}
}

func TestValidateValuesNeverEchoesSecrets(t *testing.T) {
	tpl := Template{ID: "t", Tech: "l2", Fields: []Field{{Name: "clave", Label: "Clave", Type: TypeSecret, Required: true, Min: 8, Max: 12}, {Name: "n", Label: "N", Type: TypeInt}}}
	for _, bad := range []string{"S3cr3to corto?", "S3cr3toño", "x", strings.Repeat("S3cr3to", 4), "con espacio S3cr3to"} {
		err := ValidateValues(tpl, Values{"clave": bad, "n": "zz"})
		if err == nil {
			t.Fatalf("%q aceptado", bad)
		}
		for _, leak := range []string{bad, "S3cr3to"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("el error cita el secreto %q: %v", leak, err)
			}
		}
	}
	// Una clave de campo desconocida tampoco arrastra su valor.
	err := ValidateValues(tpl, Values{"clave": "S3cr3to123", "contrasena": "Otro-Secreto"})
	if err == nil || strings.Contains(err.Error(), "Otro-Secreto") || strings.Contains(err.Error(), "S3cr3to123") {
		t.Fatalf("%v", err)
	}
}

func TestInterfaceList(t *testing.T) {
	got, err := ParseInterfaceList("Gi1/0/1-3, Gi1/0/7 gigabitethernet1/0/7 Gi1/0/2")
	if err != nil || !slices.Equal(got, []string{"Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/7"}) {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := ParseInterfaceList(""); err == nil {
		t.Error("lista vacía aceptada")
	}
	if _, err := ParseInterfaceList("Gi1/0/1-60"); err == nil {
		t.Error("rango de más de 48 puertos aceptado")
	}
}

func TestTemplatesCatalog(t *testing.T) {
	all := Templates()
	if len(all) == 0 {
		t.Fatal("catálogo vacío")
	}
	ids, last := map[string]bool{}, -1
	known := map[FieldType]bool{}
	for _, ft := range FieldTypes {
		known[ft] = true
	}
	for _, tp := range all {
		if ids[tp.ID] || tp.ID == "" {
			t.Errorf("ID repetido o vacío: %q", tp.ID)
		}
		ids[tp.ID] = true
		ti := slices.Index(TechOrder, tp.Tech)
		if ti < 0 || ti < last {
			t.Errorf("%s: tecnología %q inválida o fuera del orden del catálogo", tp.ID, tp.Tech)
		}
		last = max(last, ti)
		if tp.Name == "" || tp.Fn.Name == "" || tp.Pre == nil || tp.Plan == nil || len(tp.Platforms) == 0 {
			t.Errorf("%s: plantilla incompleta", tp.ID)
		}
		for _, p := range tp.Platforms {
			if p != "ios" && p != "ios-xe" {
				t.Errorf("%s: plataforma %q", tp.ID, p)
			}
		}
		names := map[string]bool{}
		for _, f := range tp.Fields {
			if !known[f.Type] || f.Name == "" || f.Label == "" || names[f.Name] {
				t.Errorf("%s: campo %+v inválido o repetido", tp.ID, f)
			}
			names[f.Name] = true
			if f.Type == TypeChoice && len(f.Choices) == 0 {
				t.Errorf("%s.%s: choice sin opciones", tp.ID, f.Name)
			}
			if f.Pattern != "" {
				if _, err := compilePattern(f.Pattern); err != nil {
					t.Errorf("%s.%s: patrón: %v", tp.ID, f.Name, err)
				}
			}
			if f.Type == TypeSecret && !tp.Fn.Scrub {
				t.Errorf("%s: tiene un secreto y su Function no lleva Scrub", tp.ID)
			}
		}
	}
	for _, id := range []string{"vlan", "trunk", "svi", "descripcion", "speed-duplex", "storm-control", "portfast-bpduguard", "port-security", "errdisable-recovery"} {
		if _, ok := TemplateByID(id); !ok {
			t.Errorf("falta la plantilla %s", id)
		}
	}
	if _, ok := TemplateByID("no-existe"); ok {
		t.Error("TemplateByID inventó una plantilla")
	}
}

// Los campos vlan_id declaran su rango completo: la CLI y la UI lo muestran sin que Max=0 diga «2-0».
func TestVlanIDFieldsCarryTheirRange(t *testing.T) {
	n := 0
	for _, tpl := range Templates() {
		for _, f := range tpl.Fields {
			if f.Type != TypeVlanID {
				continue
			}
			n++
			if f.Max != 4094 || f.Min < 1 {
				t.Errorf("%s.%s: Min %g Max %g, esperaba 1-4094", tpl.ID, f.Name, f.Min, f.Max)
			}
		}
	}
	if n == 0 {
		t.Fatal("el catálogo no tiene campos vlan_id")
	}
}
