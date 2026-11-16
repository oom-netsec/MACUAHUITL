package mask_test

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/mask"
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

// Punto a: « | » y « ; » dentro de un secreto. En todas las plataformas el tramo llega hasta el fin de la línea; y en un comando con secreto no hay filtro tras «|».
func TestBarraYPuntoYComaDentroDelSecreto(t *testing.T) {
	cmds := []string{
		"username u secret 0 Zq00001 | Zq00002", "username u secret 0 Zq00001|Zq00002;Zq00003", "username u secret 0 Zq00001 ; Zq00002",
		"enable secret Zq00001 | Zq00002", "enable secret Zq00001 ; Zq00002", "snmp-server community Zq00001 | Zq00002",
		"snmp-server community Zq00001 ; Zq00002 RO", "tacacs-server key Zq00001 | Zq00002 ; Zq00003", "enable password Zq00001 | Zq00002",
	}
	for _, p := range []string{"ios-xe", "", "asa", "ftd"} {
		informar(t, fugasEnVias(p, cmds, nil))
	}
	// NX-OS e ISE también: un « ; » dentro del valor es el resto del secreto (ver nxos_punto_y_coma_test.go).
	for _, p := range []string{"nx-os", "ise"} {
		informar(t, fugasEnVias(p, cmds, nil))
	}
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

// Punto b: una «"» dentro del valor en una línea que cita un comando entre comillas: la cita termina en la última comilla.
func TestComillaDentroDelValorEnLineaCitada(t *testing.T) {
	cmds := []string{
		`crypto pki export TP pem terminal 3des Zq04206"Zq04207`, `crypto pki export TP pem terminal Zq04206"Zq04207`,
		`crypto key export rsa K pem terminal aes Zq04206"Zq04207`, `crypto pki export TP pem url ftp://u:Zq04206"Zq04207@h/f 3des password Zq04208"Zq04209`,
		`crypto ca export TP pkcs12 flash:tp.p12 Zq04206"Zq04207`, `crypto pki import TP pem terminal Zq04206"Zq04207`,
		`enable secret 5 Zq04206"Zq04207`,
	}
	solo := map[string]bool{}
	for _, v := range vias {
		if v.nombre != "show tech ASA" && v.nombre != "ERROR comillas" && v.nombre != "ERROR comilla impar" {
			solo[v.nombre] = true
		}
	}
	for _, p := range []string{"ios-xe", "asa"} {
		informar(t, fugasEnVias(p, cmds, solo))
	}
}

// Punto c: ASA 111008/111010 sin el cierre «' command.» (truncado o mal formado): el comando citado llega al fin de la línea.
func TestSyslogASASinCierreDelComando(t *testing.T) {
	cmds := []string{"enable password Zq04206 Zq04207", "snmp-server community Zq04206 RO", "username u secret 0 Zq04206 Zq04207", "crypto ca export TP pkcs12 Zq04206"}
	pre := []string{"%ASA-5-111008: User 'enable_15' executed the '", "%ASA-5-111010: User 'bob', running 'CLI' from IP 10.1.1.1, executed '"}
	var malos []string
	for _, c := range cmds {
		for _, p := range pre {
			for _, cola := range []string{"", " comm", " command"} {
				l := p + c + cola
				for nom, n := range map[string]string{"Apply": nuevo.apply("asa", l+"\n"), "syslog": nuevo.raw(l), "Stream": nuevo.stream("asa", l+"\n")} {
					if len(marcas(n)) > 0 {
						malos = append(malos, fmt.Sprintf("[%s] %q\n  salida: %q", nom, l, n))
					}
				}
			}
		}
	}
	informar(t, malos)
}

// Punto d: «+NO …», «+ENABLE …» y un BOM delante en una línea de diff.
func TestDiffConMayusculasYBOM(t *testing.T) {
	var malos []string
	for _, c := range []string{"+NO snmp-server community Zq04206 RO", "+No enable secret Zq04206", "-ENABLE SECRET 0 Zq04206 Zq04207", "+SNMP-SERVER COMMUNITY Zq04206 RO",
		"\xef\xbb\xbf+snmp-server community Zq04206 RO", "\xef\xbb\xbf+NO tacacs-server key Zq04206", "\xef\xbb\xbf-ENABLE PASSWORD Zq04206", " +USERNAME U SECRET 0 Zq04206 Zq04207"} {
		for _, p := range []string{"ios-xe", ""} {
			for nom, n := range map[string]string{"Apply": nuevo.apply(p, c+"\n"), "Stream": nuevo.stream(p, c+"\n"), "syslog": nuevo.raw(c)} {
				if len(marcas(n)) > 0 {
					malos = append(malos, fmt.Sprintf("[%s] %q\n  salida: %q", nom, c, n))
				}
			}
		}
	}
	informar(t, malos)
}

// Punto f: abreviaturas mínimas de IOS («tac k X», «rad k X») y las citas de los avisos del equipo («% Ambiguous command:
// "…"», «Error:» en minúsculas, comillas simples).
func TestAbreviaturasMinimasYCitasDeAvisos(t *testing.T) {
	cmds := []string{"tac k Zq04206", "rad k Zq04206", "tac k 7 Zq04206", "tacacs-s k Zq04206", "rad key 0 Zq04206 Zq04207", "snmp-s comm Zq04206", "cry isa key Zq04206 add 1.1.1.1",
		"usern u sec 0 Zq04206 Zq04207", "ena sec Zq04206", "ena pass 7 Zq04206"}
	informar(t, fugasEnVias("ios-xe", cmds, nil))
	envolturas := []string{"% Ambiguous command:  \"@\"", "% Invalid input detected at '^' marker: \"@\"", "Error: \"@\"", "error: '@'",
		"warning: \"@\"", "% Ambiguous command: '@' (try again)", "Info: \"@\""}
	var malos []string
	for _, c := range cmds {
		for _, w := range envolturas {
			l := strings.Replace(w, "@", c, 1)
			for nom, n := range map[string]string{"Apply": nuevo.apply("ios-xe", l+"\n"), "Stream": nuevo.stream("ios-xe", l+"\n"), "syslog": nuevo.raw(l),
				"terminal": sesion(nuevo, []ev{{false, "R1(config)#"}, {false, "\r\n" + l + "\r\nR1(config)#"}}, 1)} {
				if len(marcas(n)) > 0 {
					malos = append(malos, fmt.Sprintf("[%s] %q\n  salida: %q", nom, l, n))
				}
			}
		}
	}
	informar(t, malos)
}

// Punto g: espacios Unicode en la configuración impresa («api-key X», «ip pim hello-authentication ah-md5 X»…): las
// reglas de la v0.6.5 solo ven el espacio ASCII; la pasada M₂ las corre sobre la copia normalizada.
func TestEspaciosUnicodeEnConfiguracionImpresa(t *testing.T) {
	cmds := []string{"api-key Zq04206", "crypto pki export TP pem terminal 3des Zq04206", "crypto pki export TP pem terminal 3des Zq04206",
		"set session-key 7 cipher Zq04206", "ip pim hello-authentication ah-md5 Zq04206", "ip pim hello-authentication ah-md5 Zq04206",
		"api-key Zq04206", "api-key Zq04206", "api-key　Zq04206"}
	for _, p := range []string{"ios-xe", "asa", ""} {
		informar(t, fugasEnVias(p, cmds, nil))
		var malos []string
		for _, c := range cmds { // configuración impresa: sin pasar por Command
			for nom, n := range map[string]string{"Apply": nuevo.apply(p, c+"\n"), "Stream": nuevo.stream(p, c+"\n"), "syslog": nuevo.raw(c)} {
				if len(marcas(n)) > 0 {
					malos = append(malos, fmt.Sprintf("[%s] (%s) %q\n  salida: %q", nom, p, c, n))
				}
			}
		}
		informar(t, malos)
	}
}

// Hallazgo 3: un apóstrofo entre letras («Don't», «user's») no es una comilla, y el diff exige minúscula, la palabra clave
// entera en mayúsculas o un BOM: la prosa y las líneas con mayúscula inicial quedan como en la v0.6.5.
func TestApostrofosYDiffConMayusculaInicialIgualAV065(t *testing.T) {
	lineas := []string{
		"Warning: Don't use the password reset feature", "info: user's password expires soon", `ERROR: "description it's the key holder's box"`,
		"error: can't read key file", "Info: the admin's secret rotation is due",
		"+Password aging enabled for local users", "-Server key status: ok", "+Key rotation done", "-Community strings audited", "+Secret store ready",
	}
	for _, l := range lineas {
		for _, p := range []string{"ios-xe", "asa"} {
			for nom, f := range map[string]func(impl) string{
				"Apply":  func(im impl) string { return im.apply(p, l+"\n") },
				"Stream": func(im impl) string { return im.stream(p, l+"\n") },
				"syslog": func(im impl) string { return im.raw(l) },
			} {
				if n, o := f(nuevo), f(viejo); n != o {
					t.Errorf("[%s] (%s) %q\n  nueva:  %q\n  v0.6.5: %q", nom, p, l, n, o)
				}
			}
		}
	}
}

// Hallazgo 4: con varias citas en una línea la extensión de quoteTail no se come la prosa que sigue a la cita que cierra.
func TestQuoteTailConVariasCitasConservaLaProsa(t *testing.T) {
	casos := map[string]string{
		`ERROR: "enable secret abc" is invalid, see "help" for details`:       `ERROR: "enable secret <MASKED:secret>" is invalid, see "help" for details`,
		`ERROR: "enable secret abc", see "help" for details`:                  `ERROR: "enable secret <MASKED:secret>", see "help" for details`,
		`ERROR: "snmp-server community Zq1 RO" rejected; use "snmp-server x"`: `ERROR: "snmp-server community <MASKED:snmp-community> RO" rejected; use "snmp-server x"`,
	}
	for in, want := range casos {
		got := nuevo.apply("ios-xe", in+"\n")
		if strings.Contains(got, "Zq1") || !strings.Contains(got, `see "help" for details`) && strings.Contains(in, "see") || !strings.Contains(got, "rejected") && strings.Contains(in, "rejected") {
			t.Errorf("%q\n  salida: %q\n  espero: %q", in, got, want)
		}
		if strings.Contains(in, "enable secret abc") && strings.Contains(got, "abc") {
			t.Errorf("%q: abc visible: %q", in, got)
		}
	}
	// una comilla del valor pegada a texto sigue extendiendo hasta la que cierra
	if got := nuevo.apply("ios-xe", `ERROR: "crypto pki export TP pem terminal 3des Zq04206"Zq04207" see "x"`+"\n"); strings.Contains(got, "Zq0420") {
		t.Errorf("fuga: %q", got)
	}
}

// sesionPegada: se pegan todos los comandos; llega la línea nota y después los ecos (los pendientes mantienen viva la red por
// contenido).
func sesionPegada(im impl, cmds []string, nota string) string {
	const p = "R1(config)#"
	return grabar(im, func(r sesionRec) {
		r.Output([]byte(p))
		r.Input([]byte(strings.Join(cmds, "\r") + "\r"))
		r.Output([]byte("\r\n" + nota + "\r\n")) // la línea llega antes de que vuelvan los ecos
		for _, c := range cmds {
			r.Output([]byte(c + "\r\n" + p))
		}
		r.Close()
	})
}

// Hallazgo 1: un comando con muchas palabras no desaloja de la lista M₂ el valor de un comando anterior.
func TestComandoLargoNoDesalojaElValorAnterior(t *testing.T) {
	const val = "ZqVal1x"
	largos := []string{
		"snmp-server host 10.1.1.1 version 2c Zcomm00 config syslog snmp envmon entity memory ospf eigrp hsrp vrrp isis flash license cluster stpx ipsla bridge fru-ctrl",
		"key-string 0 " + strings.Join(strings.Fields(strings.Repeat("Aa1x ", 70)), " "),
		"enable password " + func() string {
			var p []string
			for i := 0; i < 80; i++ {
				p = append(p, fmt.Sprintf("Wd%03dxy", i))
			}
			return strings.Join(p, " ")
		}(),
	}
	for _, l := range largos {
		out := sesionPegada(nuevo, []string{"tacacs-server k " + val, l}, "Note: value "+val+" applied")
		for g, n := range visibles4(out, val) {
			if n > 0 {
				t.Errorf("%.40q: %q visible\n%s", l, g, out)
				break
			}
		}
	}
	// fuzz: el valor de un comando y, en medio, comandos largos al azar; el valor repetido después sigue tapado
	r := rand.New(rand.NewSource(11))
	pool := append([]string{"snmp-server community Cm%05d RO", "enable secret Es%05d", "username u secret 0 Pa%05d Xy%05d", "tacacs-server host 10.1.1.2 key 0 Tk%05d"}, largos...)
	malos := 0
	for n := 0; n < 200; n++ {
		v := fmt.Sprintf("ZqF%05dx", n)
		cmds := []string{"tacacs-server k " + v}
		for k := r.Intn(5) + 1; k > 0; k-- {
			c := pool[r.Intn(len(pool))]
			if strings.Contains(c, "%05d") {
				c = strings.NewReplacer("%05d", fmt.Sprintf("%05d", r.Intn(99999))).Replace(c)
			}
			cmds = append(cmds, c)
		}
		out := sesionPegada(nuevo, cmds, "Note: value "+v+" applied")
		if strings.Contains(marcado.ReplaceAllString(out, "\x00"), v) {
			if malos++; malos <= 3 {
				t.Errorf("%q: %s visible\n%s", cmds, v, out)
			}
		}
	}
}

// Hallazgo 2: lo que sigue al valor (opciones, vistas, ACL, nombres) no se recuerda: la salida normal tras el prompt queda
// igual que en la v0.6.5. Y la frase completa de un secreto de varias palabras sí se tapa si se repite.
func TestPalabrasQueNoSonElSecretoNoSeTapanDespues(t *testing.T) {
	cmds := []string{
		"snmp-server host 10.1.1.1 version 2c Zcomm123 config syslog snmp envmon",
		"snmp-server community Zcomm124 view VIEWALL RO ACL_SNMP",
		"key-string 0 this is my long phrase with many words", "key-string 0 this is my long passphrase with many words",
		"crypto isakmp key Zk125x hostname peer.example.com",
		"tacacs-server host 10.1.1.2 key 0 Zk126x timeout 5 single-connection",
	}
	show := []string{"Building configuration...", "snmp-server enable traps config", "snmp-server enable traps syslog envmon", "logging host 10.1.1.1",
		"logging buffered 8192 level 5", "ip access-list standard ACL_SNMP", "snmp-server view VIEWALL iso included", "ip name-server peer.example.com",
		"tacacs-server host 10.1.1.2 single-connection", "these are here with many words and a long list", "this is fine", "show running-config", "end"}
	ses := func(im impl) string {
		return grabar(im, func(r sesionRec) {
			r.Output([]byte("R1(config)#"))
			for _, c := range cmds {
				r.Input([]byte(c + "\r"))
				r.Output([]byte(c + "\r\nR1(config)#"))
			}
			r.Input([]byte("\r")) // un Enter vacío: el prompt sin pendientes cierra la ventana corta de la v0.6.5
			r.Output([]byte("\r\nR1(config)#\r\n"))
			r.Input([]byte("end\r"))
			r.Output([]byte("end\r\nR1#"))
			r.Input([]byte("show running-config\r"))
			r.Output([]byte("show running-config\r\n"))
			for _, l := range show {
				r.Output([]byte(l + "\r\n"))
			}
			r.Output([]byte("R1#"))
			r.Close()
		})
	}
	desde := func(s string) string { return s[strings.Index(s, "R1#show running-config"):] }
	n, o := desde(ses(nuevo)), desde(ses(viejo))
	if n != o {
		t.Errorf("la salida tras el prompt difiere de la v0.6.5:\n nueva:\n%s\n v0.6.5:\n%s", n, o)
	}
	// la frase repetida más tarde se tapa entera; las palabras sueltas de una frase en minúsculas, no
	frase := grabar(nuevo, func(r sesionRec) {
		r.Output([]byte("R1(config)#"))
		r.Input([]byte("key-string 0 this is my long phrase with many words\r"))
		r.Output([]byte("key-string 0 this is my long phrase with many words\r\nR1(config)#"))
		r.Output([]byte("\r\nNote \"this is my long phrase with many words\"\r\nthese words are with many things\r\nR1(config)#"))
		r.Close()
	})
	if strings.Contains(frase, "phrase") && strings.Contains(frase, "Note \"this") || !strings.Contains(frase, "these words are with many things") {
		t.Errorf("la frase debía taparse y la prosa no:\n%s", frase)
	}
}

// Hallazgo 2, cobertura de (e): un valor de varias palabras todo en minúsculas se cubre por posición en cada corte del eco.
func TestEcoPartidoValorEnMinusculasSeCubrePorPosicion(t *testing.T) {
	for _, cmd := range []string{"enable secret my long passphrase", "key-string 0 this is my long passphrase"} {
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
				eco := strings.Join(strings.Split(marcado.ReplaceAllString(out, "\x00"), "\n")[1:], "\n")
				for _, w := range []string{"long", "phrase"} {
					if strings.Contains(eco, w) {
						t.Errorf("%q k=%d desp=%v: %s visible\n%s", cmd, k, desp, w, out)
					}
				}
			}
		}
	}
}

// Hallazgo 2, los valores que se recuerdan: solo el secreto, no las opciones, vistas, ACL ni nombres que le siguen.
func TestValoresRecordadosSonSoloElSecreto(t *testing.T) {
	casos := []struct {
		cmd     string
		textos  []string // en orden
		persist []string
	}{
		{"snmp-server host 10.1.1.1 version 2c Zcomm123 config syslog snmp envmon", []string{"Zcomm123"}, nil},
		{"snmp-server community Zcomm124 view VIEWALL RO ACL_SNMP", []string{"Zcomm124"}, nil},
		{"crypto isakmp key Zk125x hostname peer.example.com", []string{"Zk125x"}, nil},
		{"tacacs-server host 10.1.1.2 key 0 Zk126x timeout 5 single-connection", []string{"Zk126x"}, nil},
		{"key-string 0 this is my long phrase with many words", []string{"this is my long phrase with many words", "this", "long", "phrase", "with", "many", "words"}, []string{"this is my long phrase with many words"}},
		{"enable secret Pa55w0rd Xq7z9mK", []string{"Pa55w0rd Xq7z9mK", "Pa55w0rd", "Xq7z9mK"}, []string{"Pa55w0rd Xq7z9mK", "Pa55w0rd", "Xq7z9mK"}},
		{"snmp-server user u g v3 auth sha Xa1b2c3d priv aes 128 Yb2c3d4e access 10", []string{"Xa1b2c3d", "Yb2c3d4e"}, nil},
	}
	for _, c := range casos {
		_, vs := mask.CutCommandV("", c.cmd, c.cmd)
		var textos, persist []string
		for _, v := range vs {
			textos = append(textos, v.Text)
			if v.Persist {
				persist = append(persist, v.Text)
			}
		}
		if strings.Join(textos, "|") != strings.Join(c.textos, "|") || strings.Join(persist, "|") != strings.Join(c.persist, "|") {
			t.Errorf("%q\n  valores:  %q (esperaba %q)\n  persisten: %q (esperaba %q)", c.cmd, textos, c.textos, persist, c.persist)
		}
	}
}

// Las partes de un valor con forma de URL («Abcd1:Efgh2», «scp://usr:CLAVE@srv/f») las recordaba main: no se desalojan antes
// que las palabras extra de frases posteriores.
func TestPartesDeURLNoSeDesalojanAntesQueLasPalabrasExtra(t *testing.T) {
	for _, primero := range []string{"enable secret Abcd1:Efgh2", "enable secret scp://usr:Efgh2@srv/f", "enable secret Abcd1/Efgh2"} {
		cmds := []string{primero}
		for i := 0; i < 14; i++ {
			cmds = append(cmds, fmt.Sprintf("username u%d password 0 Pa%dsw Xq%dz9 Mn%dp4 Rt%dk2", i, i, i, i, i))
		}
		out := sesionPegada(nuevo, cmds, "Note: Efgh2 is weak")
		if strings.Contains(marcado.ReplaceAllString(out, "\x00"), "Efgh2") {
			t.Errorf("%q: Efgh2 visible\n%s", primero, out)
		}
	}
}
