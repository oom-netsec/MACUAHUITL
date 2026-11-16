package terminal

import (
	"regexp"
	"strings"
	"testing"
)

var tapaRe = regexp.MustCompile(`<MASKED:[^>]*>`)

// fuga4: devuelve el primer 4-grama de v que sigue visible en out una vez quitados los <MASKED:…>.
func fuga4(out, v string) string {
	vis := tapaRe.ReplaceAllString(out, "\x00")
	for i := 0; i+4 <= len(v); i++ {
		if strings.Contains(vis, v[i:i+4]) {
			return v[i : i+4]
		}
	}
	return ""
}

const syslogAsync = "\r\n*Mar  1 00:01:02.345: %SYS-5-CONFIG_I: Configured from console by vty0\r\n"

// Un «#» o «>» dentro del secreto con el eco partido por un syslog: el resto del eco no es un prompt.
func TestEcoPartidoConAlmohadillaEnElSecreto(t *testing.T) {
	valores := []string{"Pa55w0rd#Xq7z9", "Cisco>Admin123", "Ab12(x)#Zk98qW", "Ab12)>Zk98qW", "Qw3rty>>Zx9v8", "a#b#Xq7z9Lm"}
	const prompt = "R1(config)#"
	for _, v := range valores {
		cmd := "enable secret " + v
		for k := 0; k <= len(cmd); k++ {
			for _, modo := range []string{"pegado", "caracter"} {
				r, b := newRec()
				r.Output([]byte(prompt))
				echo := cmd[:k] + syslogAsync + cmd[k:]
				if modo == "pegado" {
					r.Input([]byte(cmd + "\r"))
					r.Output([]byte(echo + "\r\n" + prompt))
				} else {
					for _, c := range cmd {
						r.Input([]byte(string(c)))
					}
					r.Output([]byte(echo))
					r.Input([]byte("\r"))
					r.Output([]byte("\r\n" + prompt))
				}
				r.Output([]byte("\r\nsalida normal posterior\r\n" + prompt))
				r.Close()
				out := b.String()
				if f := fuga4(out, v); f != "" {
					t.Fatalf("%s k=%d %q: fuga %q:\n%s", modo, k, v, f, out)
				}
				if !strings.Contains(out, "Z salida normal posterior\n") {
					t.Fatalf("%s k=%d %q: tapó de más lo posterior:\n%s", modo, k, v, out)
				}
			}
		}
	}
}

// Un prompt real que vuelve con el eco a medias (error, Ctrl-C, end) no deja tapada la salida posterior.
func TestPromptRealTrasEcoPartidoNoTapaLoPosterior(t *testing.T) {
	for _, corte := range []string{"% Invalid input detected at '^' marker.", "^C", "% Incomplete command."} {
		r, b := newRec()
		r.Output([]byte("R1(config)#"))
		r.Input([]byte("enable secret Pa55w0rd#Xq7z9\r"))
		r.Output([]byte("enable secret Pa55" + syslogAsync + "w0rd#X\r\n" + corte + "\r\nR1(config)#\r\nlinea posterior\r\nR1(config)#"))
		r.Close()
		out := b.String()
		if f := fuga4(out, "Pa55w0rd#Xq7z9"); f != "" {
			t.Errorf("%q: fuga %q:\n%s", corte, f, out)
		}
		if !strings.Contains(out, "Z linea posterior\n") {
			t.Errorf("%q: tapó de más:\n%s", corte, out)
		}
	}
}
