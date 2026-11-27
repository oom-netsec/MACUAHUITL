package mask

import (
	"strings"
	"testing"
)

var fuzzPlatforms = []string{"ios", "ios-xe", "nx-os", "asa", "ftd", "aireos", "ise", ""}

const fuzzSeed = "SEMILLA7"

func FuzzApply(f *testing.F) {
	f.Add(byte(1), "username bob password 0 hola\n")
	f.Add(byte(3), "username bob password 0 open version two\n")
	f.Add(byte(0), "line vty 0 4\n password 0 my pw\n")
	f.Add(byte(1), "dot1x credentials SUP\n username host1\n password 0 Secreta\n!\ninterface Gi1\n description password x\n")
	f.Add(byte(2), "snmp-server community public group network-admin\n")
	f.Add(byte(1), "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n")
	f.Add(byte(4), "")
	f.Fuzz(func(t *testing.T, p byte, text string) {
		plat := fuzzPlatforms[int(p)%len(fuzzPlatforms)]
		out, _ := Apply(plat, text)
		// La 2.ª pasada nunca muestra más que la 1.ª. Puede tapar de más: sus marcadores y una cita cuya comilla quedó dentro
		// de un tramo (escapes, espacios Unicode, bytes inválidos) le dan otro contexto, y perseguir cada caso de esa clase
		// rompía la nocturna sin que nada se filtrara. Lo que sí se exige es que no destape nada.
		if again, _ := Apply(plat, out); !neverShowsMore(out, again) {
			t.Fatalf("la 2.ª pasada muestra más (%q)\n1: %q\n2: %q", plat, out, again)
		}
		// Un secreto sembrado en forma de regla no sale en claro, sea cual sea el texto previo.
		if strings.Contains(text, fuzzSeed) {
			return
		}
		// También con espacios Unicode y una comilla de cola: sin bytes altos la copia normalizada (twinSpans) no corre.
		for _, l := range []string{"username u password 0 " + fuzzSeed, "username u password\u00a00 " + fuzzSeed + `".`, "username u password 0\u2003" + fuzzSeed + `",`, `tacacs-server key "` + fuzzSeed + `\".x"` + "\u00a0x"} {
			sec, _ := Apply(plat, text+"\n"+l+"\n")
			if strings.Contains(sec, fuzzSeed) {
				t.Fatalf("SEGURIDAD: el secreto sembrado se filtró (%q): %q", plat, sec)
			}
		}
	})
}

// FuzzStream: Line en secuencia con trozos arbitrarios; ni pánico ni filtración del secreto sembrado.
func FuzzStream(f *testing.F) {
	f.Add(byte(1), "username bob password 0 hola\nline vty 0 4\n password 0 x\n")
	f.Add(byte(3), "a\r\nb\n\n")
	f.Fuzz(func(t *testing.T, p byte, text string) {
		if strings.Contains(text, fuzzSeed) {
			return
		}
		st := Stream{Platform: fuzzPlatforms[int(p)%len(fuzzPlatforms)], MaxSkip: 50}
		var out strings.Builder
		for _, raw := range strings.SplitAfter(text+"\nusername u password 0 "+fuzzSeed+"\n", "\n") {
			if l, ok := st.Line(raw); ok {
				out.WriteString(l)
			}
		}
		if strings.Contains(out.String(), fuzzSeed) {
			t.Fatalf("SEGURIDAD: secreto sembrado filtrado por Stream: %q", out.String())
		}
	})
}

// Corpus del fuzz (nocturna del 2026-11-26): con un tabulador y un byte no ASCII antes de una cita, el tramo de la copia
// normalizada (twinSpans) se extendía hasta el espacio y tapaba también la comilla que cierra la cita; la 2.ª pasada veía
// la cita abierta hasta el fin de la línea y tapaba lo de fuera. La comilla que cierra (o abre) una cita no es del valor.
func TestTwinSpansNoTapaLaComillaDeLaCita(t *testing.T) {
	for _, in := range []string{"\t\xec\"pA x\" pA A0", "\t\xec\"password Zq7secret\" y z", "\t\xe9\"password x\", y", "\t\xec \"password Zq1\"Zq2\" y"} {
		out, _ := Apply("ios-xe", in)
		if again, _ := Apply("ios-xe", out); again != out {
			t.Errorf("%q no idempotente:\n1: %q\n2: %q", in, out, again)
		}
		if strings.Count(out, `"`) != strings.Count(in, `"`) && !strings.Contains(in, `Zq1"Zq2`) {
			t.Errorf("%q: se tapó una comilla de la cita: %q", in, out)
		}
		if strings.Contains(out, "Zq") || strings.Contains(out, " x") && strings.Contains(in, "password x") {
			t.Errorf("%q: el valor quedó en claro: %q", in, out)
		}
	}
}

// neverShowsMore: second es first con algunos tramos visibles cambiados por marcadores: cada tramo visible de second está, en
// orden, en lo visible de first, sus marcadores siguen, y second no muestra más texto.
func neverShowsMore(first, second string) bool {
	if first == second {
		return true
	}
	if len(maskedMarker.FindAllString(second, -1)) < len(maskedMarker.FindAllString(first, -1)) {
		return false
	}
	// Cada tramo visible de second cae, en orden, dentro de un solo tramo visible de first: nunca dentro del texto de un
	// marcador («<MASKED:x>secret<MASKED:y>» no vale como «secret» visible).
	vis, k, pos := maskedMarker.Split(first, -1), 0, 0
	for _, piece := range maskedMarker.Split(second, -1) {
		for ; k < len(vis); k, pos = k+1, 0 {
			if i := strings.Index(vis[k][pos:], piece); i >= 0 {
				pos += i + len(piece)
				break
			}
		}
		if k == len(vis) {
			return false
		}
	}
	return len(maskedMarker.ReplaceAllString(second, "")) <= len(maskedMarker.ReplaceAllString(first, ""))
}

// La propiedad del fuzz: tapar de más en la 2.ª pasada se acepta; destapar o cambiar lo visible, no.
func TestSegundaPasadaNuncaMuestraMas(t *testing.T) {
	for _, c := range []struct {
		first, second string
		ok            bool
	}{
		{"a <MASKED:secret> b c", "a <MASKED:secret> b c", true},
		{"\t\xec\"pA <MASKED:secret> pA A0", "\t\xec\"pA <MASKED:secret> pA <MASKED:secret>", true},
		{"<MASKED:secret> \"pA \f\xd10", "<MASKED:secret> \"pA \f<MASKED:secret>", true},
		{"a <MASKED:secret> b", "a Zq7secret b", false},                                                          // destapó
		{"a <MASKED:secret> b", "a b", false},                                                                    // perdió el marcador
		{"a <MASKED:secret> b", "a <MASKED:secret> b x", false},                                                  // muestra texto nuevo
		{"a b", "x <MASKED:secret> b", false},                                                                    // cambió lo visible
		{"u password <MASKED:secret> padding-long-text", "u password <MASKED:x>secret<MASKED:y> padding", false}, // texto sacado de un marcador
	} {
		if g := neverShowsMore(c.first, c.second); g != c.ok {
			t.Errorf("neverShowsMore(%q, %q) = %v, quiero %v", c.first, c.second, g, c.ok)
		}
	}
	// Las dos entradas del corpus que tapan de más en la 2.ª pasada: lo aceptado es eso, no más.
	for _, in := range []struct{ plat, text string }{{"ios-xe", "\t\xec\"pA x\" pA A0"}, {"ios", "\\\" \"pA \f\xd10"}} {
		out, _ := Apply(in.plat, in.text)
		again, _ := Apply(in.plat, out)
		if !neverShowsMore(out, again) {
			t.Errorf("%q: 1: %q 2: %q", in.text, out, again)
		}
	}
}

// Revisión 2: una comilla escapada («\"») no es borde de cita: lo que sigue sigue siendo del valor.
func TestTwinSpansComillaEscapadaNoEsBorde(t *testing.T) {
	in := "! snmp-server user u\u3000auth md5 \"Zq18\\\"\u200b y\"\tpriv \"Zq18\\\" y\"'"
	out, _ := Apply("nx-os", in)
	if strings.Contains(out, "<MASKED:secret>y") || strings.Contains(out, "Zq18") {
		t.Errorf("quedó a la vista parte del secreto: %q", out)
	}
}

// Revisión 1: con un espacio Unicode en la línea, una cita con «\"» seguido de puntuación no deja ver la cola del secreto.
func TestTwinSpansEscapeConPuntuacion(t *testing.T) {
	for _, c := range []struct{ plat, in string }{
		{"ios", "  tacacs-server key \"Zq1\\\" Zq2\\\".Zq3\"\u00a0x"},
		{"ios", "tacacs-server\u00a0key \"Zq1\\\" Zq2\\\".Zq3\""},
		{"ios", "username u password 0 \"Zq1\\\" Zq2\\\",Zq3\"\u2003x"},
		{"ios", "snmp-server community \"Zq1\\\" Zq2\\\":Zq3\" ro\u00a0"},
		{"ios", "\t\xecsnmp-server community \"Zq1\\\".Zq2\""},
		{"nx-os", "  tacacs-server key \"Zq1\\\" Zq2\\\".Zq3\"\u00a0x"},
	} {
		if out, _ := Apply(c.plat, c.in); strings.Contains(out, "Zq3") || strings.Contains(out, ".Zq2") {
			t.Errorf("%s %q: %q", c.plat, c.in, out)
		}
	}
}
