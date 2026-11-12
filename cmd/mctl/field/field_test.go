package field

import "testing"

func TestEscaper(t *testing.T) {
	var e escaper
	cases := []struct {
		in   string
		data string
		acts string
	}{
		{"show ver\r", "show ver\r", ""},
		{"a\x1d", "a", ""}, // escape pendiente entre lecturas
		{"b", "", "b"},
		{"\x1d\x1dz", "\x1dz", ""}, // doble escape = carácter literal
		{"x\x1dqy", "x", "q"},      // tras salir se descarta el resto
		{"\x1d?", "", "?"},
		{"\x1dk", "", "?"}, // desconocido: muestra la ayuda
	}
	for _, c := range cases {
		data, acts := e.feed([]byte(c.in))
		if string(data) != c.data || string(acts) != c.acts {
			t.Errorf("%q → %q %q; se esperaba %q %q", c.in, data, acts, c.data, c.acts)
		}
	}
}
