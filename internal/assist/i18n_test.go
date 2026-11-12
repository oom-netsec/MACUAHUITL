package assist

import (
	"errors"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func plantillaDePrueba() Template {
	return Template{ID: "prueba", Fields: []Field{
		{Name: "txt", Label: "Texto", Type: TypeText, Min: 2, Max: 5, Pattern: `^[a-z]+$`},
		{Name: "num", Label: "Número", Type: TypeInt, Min: 1, Max: 10},
		{Name: "dec", Label: "Decimal", Type: TypeDecimal, Min: 0, Max: 5},
		{Name: "flag", Label: "Bandera", Type: TypeBool},
		{Name: "opc", Label: "Opción", Type: TypeChoice, Choices: []string{"a", "b"}},
		{Name: "ip", Label: "IP", Type: TypeIPv4},
		{Name: "mask", Label: "Máscara", Type: TypeIPv4Mask},
		{Name: "if", Label: "Puerto", Type: TypeInterface},
		{Name: "ifs", Label: "Puertos", Type: TypeInterfaces},
		{Name: "vl", Label: "VLAN", Type: TypeVlanID},
		{Name: "sec", Label: "Secreto", Type: TypeSecret, Min: 4, Max: 8},
		{Name: "obl", Label: "Obligatorio", Type: TypeText, Required: true},
	}}
}

// Regresión: el texto en es de cada problema es el de siempre (byte por byte); en en sale traducido; la metadata
// trae plantilla, campo y motivo del primero y nunca un valor.
func TestValidateValuesTextoEsYEn(t *testing.T) {
	for _, tc := range []struct {
		vals  Values
		es    string
		en    string
		field string
		why   string
	}{
		{Values{"obl": "x", "txt": "AB"}, `Texto (txt): "AB" no cumple el formato esperado`, "", "txt", "pattern"},
		{Values{"obl": "x", "txt": "abcdefg"}, `Texto (txt): mide 7 caracteres y debe medir entre 2 y 5`, "txt: is 7 characters long and must be between 2 and 5", "txt", "range"},
		{Values{"obl": "x", "num": "11"}, `Número (num): 11 fuera de 1-10`, "num: 11 is outside 1-10", "num", "range"},
		{Values{"obl": "x", "num": "0x"}, `Número (num): "0x" no es un entero (sin signo ni ceros a la izquierda)`, "", "num", "type"},
		{Values{"obl": "x", "dec": "9.5"}, `Decimal (dec): 9.5 fuera de 0-5`, "", "dec", "range"},
		{Values{"obl": "x", "flag": "si"}, `Bandera (flag): "si": solo true o false`, "", "flag", "choice"},
		{Values{"obl": "x", "opc": "z"}, `Opción (opc): "z": elige una de a, b`, `opc: "z": choose one of a, b`, "opc", "choice"},
		{Values{"obl": "x", "ip": "1.2.3"}, `IP (ip): dirección IPv4 inválida "1.2.3"`, `ip: invalid IPv4 address "1.2.3"`, "ip", "type"},
		{Values{"obl": "x", "mask": "255.0.255.0"}, `Máscara (mask): máscara "255.0.255.0" no contigua`, "", "mask", "type"},
		{Values{"obl": "x", "mask": "x"}, `Máscara (mask): máscara inválida "x" (usa la forma 255.255.255.0)`, "", "mask", "type"},
		{Values{"obl": "x", "if": "Vlan10"}, `Puerto (if): "Vlan10" no es un puerto físico ni un Port-channel`, "", "if", "type"},
		{Values{"obl": "x", "ifs": "Gi1/0/1-60"}, `Puertos (ifs): rango "Gi1/0/1-60" inválido (de menor a mayor y hasta 48 puertos)`, "", "ifs", "range"},
		{Values{"obl": "x", "vl": "5000"}, `VLAN (vl): 5000 fuera de 1-4094`, "", "vl", "range"},
		{Values{"obl": "x", "sec": "ab"}, `Secreto (sec): el secreto debe medir entre 4 y 8 caracteres`, "sec: the secret must be between 4 and 8 characters long", "sec", "range"},
		{Values{"obl": "x", "sec": "ab cd"}, `Secreto (sec): el secreto lleva caracteres no permitidos (solo ASCII visible, sin espacios ni '?')`, "", "sec", "pattern"},
		{Values{"obl": "x", "raro": "1"}, `campo desconocido "raro"`, `unknown field "raro"`, "raro", "unknown_field"},
		{Values{}, `falta Obligatorio (obl)`, `obl is required`, "obl", "required"},
		{Values{"obl": "x", "txt": "a?"}, `Texto (txt): "a?": '?' y el tabulador no se admiten`, "", "txt", "pattern"},
		{Values{"obl": "x", "txt": "áa"}, `Texto (txt): "áa": tiene caracteres fuera de ASCII imprimible (0x20-0x7e)`, "", "txt", "pattern"},
		{Values{"obl": "x", "num": " 3"}, `Número (num): " 3": sin espacios al inicio ni al final`, "", "num", "pattern"},
	} {
		err := ValidateValues(plantillaDePrueba(), tc.vals)
		var c i18n.Coded
		if err == nil || !errors.As(err, &c) || !errors.Is(err, ErrInvalidValues) {
			t.Fatalf("%v: %v", tc.vals, err)
		}
		if want := "assist: valores del snippet inválidos: " + tc.es; err.Error() != want {
			t.Errorf("es = %q\nquiero %q", err.Error(), want)
		}
		if tc.en != "" {
			if want := "assist: invalid snippet values: " + tc.en; c.Localize(i18n.En) != want {
				t.Errorf("en = %q\nquiero %q", c.Localize(i18n.En), want)
			}
		}
		m := c.Metadata()
		if c.Reason() != "assist.invalid_value" || m["template"] != "prueba" || m["field"] != tc.field || m["why"] != tc.why || len(m) != 3 {
			t.Errorf("%s: reason %q metadata %v", tc.es, c.Reason(), m)
		}
	}
}

// El valor de un secreto no aparece ni en el texto ni en la metadata, en ningún idioma.
func TestSecretoNuncaEnLaMetadata(t *testing.T) {
	err := ValidateValues(plantillaDePrueba(), Values{"obl": "x", "sec": "HUNTER2 con espacio"})
	var c i18n.Coded
	if !errors.As(err, &c) {
		t.Fatal(err)
	}
	for _, s := range []string{err.Error(), c.Localize(i18n.En), strings.Join(valuesOf(c.Metadata()), " ")} {
		if strings.Contains(s, "HUNTER2") {
			t.Fatalf("el secreto se filtró: %q", s)
		}
	}
}

func valuesOf(m map[string]string) (out []string) {
	for _, v := range m {
		out = append(out, v)
	}
	return
}
