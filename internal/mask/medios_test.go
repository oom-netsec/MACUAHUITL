package mask_test

import (
	"fmt"
	"strings"
	"testing"
)

// Prueba de aceptación del punto h: un secreto de varias palabras que el equipo repite más tarde en una línea «Note "…"».
// Ningún 4-grama de ninguna palabra del valor puede verse en la grabación.
func TestSecretoDeVariasPalabrasRepetidoDespues(t *testing.T) {
	const v1, v2 = "Pa55w0rd", "Xq7z9mK"
	casos := []struct{ prompt, tpl string }{
		{"R1(config)#", "enable secret %s"},
		{"R1(config)#", "enable password %s"},
		{"R1(config-if)#", "standby 1 authentication %s"},
		{"R1(config)#", "snmp-server community %s RO"},
		{"R1(config-isakmp-group)#", "key %s"},
		{"R1(config)#", "username u password %s"},
	}
	forma := []string{"pegado", "caracter", "partido"}
	malos := 0
	for _, c := range casos {
		cmd := fmt.Sprintf(c.tpl, v1+" "+v2)
		for _, f := range forma {
			for _, desp := range []bool{false, true} {
				if desp && f == "caracter" {
					continue
				}
				out := grabar(nuevo, func(r sesionRec) {
					r.Output([]byte(c.prompt))
					echo := cmd
					if desp {
						echo = "$" + echo[len(echo)/3:]
					}
					switch f {
					case "pegado":
						r.Input([]byte(cmd + "\r"))
						r.Output([]byte(echo + "\r\n" + c.prompt))
					case "caracter":
						for i := 0; i < len(cmd); i++ {
							r.Input([]byte{cmd[i]})
							r.Output([]byte{cmd[i]})
						}
						r.Input([]byte("\r"))
						r.Output([]byte("\r\n" + c.prompt))
					case "partido":
						r.Input([]byte(cmd + "\r"))
						k := len(echo) - len(v2) - 3
						r.Output([]byte(echo[:k] + syslogPost + echo[k:] + "\r\n" + c.prompt))
					}
					r.Output([]byte("\r\nNote \"" + v1 + " " + v2 + "\"\r\n"))
					r.Output([]byte("Note \"" + v2 + " " + v1 + " again\"\r\n" + c.prompt))
					r.Close()
				})
				for _, v := range []string{v1, v2} {
					for g, n := range visibles4(out, v) {
						if n > 0 {
							if malos++; malos <= 12 {
								t.Errorf("%q %s desp=%v: %q visible\n%s", cmd, f, desp, g, out)
							}
							break
						}
					}
				}
			}
		}
	}
	if malos > 12 {
		t.Errorf("%d casos en total", malos)
	}
	_ = strings.Join
}

// Punto e: un secreto tipo 0 de varias palabras con el eco partido en cada posición posible: ningún 4-grama de ninguna
// de las palabras se ve, ni en el eco ni en la salida posterior.
func TestEcoPartidoSecretoDeVariasPalabrasEnCadaCorte(t *testing.T) {
	const v1, v2 = "Pa55w0rd", "Xq7z9"
	malos, total := 0, 0
	for _, tp := range []string{"enable secret %s", "enable password %s", "username u secret 0 %s", "snmp-server community %s RO"} {
		cmd := fmt.Sprintf(tp, v1+" "+v2)
		for k := 1; k < len(cmd); k++ {
			for _, desp := range []bool{false, true} {
				for _, dos := range []bool{false, true} {
					cortes := []int{k}
					if dos {
						if k+3 >= len(cmd) {
							continue
						}
						cortes = []int{k, k + 3}
					}
					out := grabar(nuevo, func(r sesionRec) { sesionPosterior(r, cmd, v1+" "+v2, cortes, desp) })
					total++
					out = sinLineaInterior(out)
					for _, v := range []string{v1, v2} {
						for g, n := range visibles4(out, v) {
							if n > 0 {
								if malos++; malos <= 8 {
									t.Errorf("%q cortes=%v desp=%v: %q visible\n%s", cmd, cortes, desp, g, out)
								}
								goto sig
							}
						}
					}
				sig:
				}
			}
		}
	}
	if malos > 0 {
		t.Errorf("%d de %d posiciones con fuga", malos, total)
	}
}

// sinLineaInterior quita las líneas «x <valor sin sus extremos> y» y «head <mitad del valor>» de sesionPosterior: un trozo del interior del valor, sin
// límites de palabra, no es algo que la red por contenido pueda perseguir (ni la de la v0.6.5).
func sinLineaInterior(out string) string {
	var b strings.Builder
	for _, l := range strings.SplitAfter(out, "\n") {
		if !strings.Contains(l, "Z x ") && !strings.Contains(l, "Z head ") {
			b.WriteString(l)
		}
	}
	return b.String()
}

// fugasEnVias corre cada comando por todas las vías de comando (no las sueltas, que son configuración impresa) y devuelve
// las que dejan ver algún marcador Zq#####.
func fugasEnVias(plat string, cmds []string, salvo map[string]bool) []string {
	var malos []string
	for _, c := range cmds {
		for _, v := range vias {
			if sueltas[v.nombre] || salvo[v.nombre] {
				continue
			}
			if n := v.f(nuevo, plat, c); len(marcas(n)) > 0 {
				malos = append(malos, fmt.Sprintf("[%s] (%s) %q\n  salida: %q", v.nombre, plat, c, n))
			}
		}
	}
	return malos
}

func informar(t *testing.T, malos []string) {
	t.Helper()
	for i, m := range malos {
		if i < 12 {
			t.Error(m)
		}
	}
	if len(malos) > 12 {
		t.Errorf("%d fugas en total", len(malos))
	}
}

// Punto a: « | » y « ; » dentro de un secreto. Donde la plataforma no separa comandos con « ; » (IOS, o no se sabe) el
// tramo llega hasta el fin de la línea; y en un comando con secreto no hay filtro tras «|».
func TestBarraYPuntoYComaDentroDelSecreto(t *testing.T) {
	cmds := []string{
		"username u secret 0 Zq00001 | Zq00002", "username u secret 0 Zq00001|Zq00002;Zq00003", "username u secret 0 Zq00001 ; Zq00002",
		"enable secret Zq00001 | Zq00002", "enable secret Zq00001 ; Zq00002", "snmp-server community Zq00001 | Zq00002",
		"snmp-server community Zq00001 ; Zq00002 RO", "tacacs-server key Zq00001 | Zq00002 ; Zq00003", "enable password Zq00001 | Zq00002",
	}
	for _, p := range []string{"ios-xe", "", "asa", "ftd"} {
		informar(t, fugasEnVias(p, cmds, nil))
	}
	// NX-OS e ISE separan comandos con « ; »: lo que sigue es otro comando, también en el accounting (que lo trae por definición).
	informar(t, fugasEnVias("nx-os", []string{"enable secret Zq00001 | Zq00002", "snmp-server community Zq00001 | Zq00002"}, nil))
}

// Punto e, sin la red por contenido: un valor solo de dígitos y de menos de 8 no se recuerda (spValue), así que el resto
// de un eco partido solo se tapa por posición: lo que cae dentro del secreto de lo tecleado.
func TestEcoPartidoTapaPorPosicionElRestoDelSecreto(t *testing.T) {
	cmd := "enable secret 1234 5678"
	for k := 1; k < len(cmd); k++ {
		for _, desp := range []bool{false, true} {
			out := grabar(nuevo, func(r sesionRec) {
				r.Output([]byte("R1(config)#"))
				r.Input([]byte(cmd + "\r"))
				echo := cmd[:k] + syslogPost + cmd[k:]
				if desp {
					echo = "$" + echo
				}
				r.Output([]byte(echo + "\r\nR1(config)#"))
				r.Close()
			})
			for _, w := range []string{"1234", "5678"} {
				if strings.Contains(strings.Join(strings.Split(marcado.ReplaceAllString(out, "\x00"), "\n")[1:], "\n"), w) {
					t.Errorf("k=%d desp=%v: %s visible\n%s", k, desp, w, out)
				}
			}
		}
	}
}
