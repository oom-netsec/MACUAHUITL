package mask_test

import (
	"strings"
	"testing"
)

// Las 5 formas que la pasada de Release encontró con el valor visible: en Cmd, CFGLOG, ASA 111008 y la sesión de
// terminal con eco no debe verse ningún valor. «k» de una sola letra se cubre en estos contextos.
func TestCincoFormasDeRelease(t *testing.T) {
	formas := []string{
		"enable secret lev 15 ZqVALOR1",
		"ena sec lev 15 0 ZqVALOR1",
		"snmp-s ho 10.1.1.1 ver 2c ZqVALOR1",
		"snmp-s ho 10.1.1.1 ZqVALOR1",
		"tacacs-ser k ZqVALOR1",
	}
	vias := map[string]func(c string) string{
		"Cmd": func(c string) string { return nuevo.cmd("ios-xe", c) },
		"CFGLOG": func(c string) string {
			return nuevo.apply("ios-xe", "%PARSER-5-CFGLOG_LOGGEDCMD: User:bob  logged command:"+c+"\n")
		},
		"ASA 111008": func(c string) string {
			return nuevo.apply("asa", "%ASA-5-111008: User 'enable_15' executed the '"+c+"' command.\n")
		},
		"terminal": func(c string) string { return sesion(nuevo, guion("R1(config)#", []string{c}, false, false, false), 1) },
	}
	for _, f := range formas {
		for n, via := range vias {
			if out := via(f); strings.Contains(out, "ZqVALOR1") {
				t.Errorf("[%s] %q deja ver el valor:\n%s", n, f, out)
			}
		}
	}
}
