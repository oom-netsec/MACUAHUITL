package mask_test

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

)

var marcado = regexp.MustCompile(`<MASKED:[^>]*>`)

// visibles4: cuántas veces se ve cada 4-grama de v en out, quitados los <MASKED:…>.
func visibles4(out, v string) map[string]int {
	vis := marcado.ReplaceAllString(out, "\x00")
	m := map[string]int{}
	for i := 0; i+4 <= len(v); i++ {
		g := v[i : i+4]
		m[g] = strings.Count(vis, g)
	}
	return m
}

const syslogPost = "\r\n*Mar  1 00:01:02.345: %SYS-5-CONFIG_I: Configured from console by vty0\r\n"

// sesionPosterior: pega cmd, el eco llega partido por syslogs (cortes), un Enter vacío y varias líneas de salida con el
// valor entero y sus trozos.
func sesionPosterior(rec sesionRec, cmd, v string, cortes []int, desplazado bool) {
	rec.Output([]byte("R1(config)#"))
	rec.Input([]byte(cmd + "\r"))
	echo, prev := "", 0
	for _, k := range cortes {
		echo += cmd[prev:k] + syslogPost
		prev = k
	}
	echo += cmd[prev:]
	if desplazado {
		echo = "$" + echo
	}
	rec.Output([]byte(echo + "\r\nR1(config)#"))
	rec.Input([]byte("\r"))
	rec.Output([]byte("\r\nR1(config)#\r\n"))
	h := len(v) / 2
	for _, l := range []string{"linea " + v + " fin", v[h:] + " tail", "head " + v[:h], "x " + v[1:len(v)-1] + " y"} {
		rec.Output([]byte(l + "\r\n"))
	}
	rec.Output([]byte("R1(config)#"))
	rec.Close()
}

func grabar(im impl, f func(sesionRec)) string {
	var b bytes.Buffer
	t0 := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	f(im.rec(&b, func() time.Time { return t0 }))
	return b.String()
}

// Diferencial de la terminal con salida posterior: ningún 4-grama del valor se ve más veces que en la v0.6.5.
func TestTerminalConSalidaPosteriorNoVeMasQueV065(t *testing.T) {
	valores := []string{"f&3Z7c-c8_fd7#1!4", "Pa55w0rd#Xq7z9", "Cisco>Admin123", "Ab12(x)#Zk98qW", "Ab12)>Zk98qW"}
	plantillas := []string{"tacacs-server key %s", "enable secret %s", "username u secret 0 %s", "snmp-server community %s RO"}
	malos := 0
	for _, v := range valores {
		for _, tp := range plantillas {
			cmd := fmt.Sprintf(tp, v)
			for k := 1; k < len(cmd); k++ {
				for _, desp := range []bool{false, true} {
					f := func(r sesionRec) { sesionPosterior(r, cmd, v, []int{k}, desp) }
					n, o := visibles4(grabar(nuevo, f), v), visibles4(grabar(viejo, f), v)
					for g, c := range n {
						if c > o[g] {
							if malos++; malos <= 10 {
								t.Errorf("%q k=%d desp=%v: %q se ve %d veces (v0.6.5: %d)\n%s", cmd, k, desp, g, c, o[g], grabar(nuevo, f))
							}
							break
						}
					}
				}
			}
		}
	}
	if malos > 10 {
		t.Errorf("%d casos en total", malos)
	}
}

// Huecos que la v0.6.5 también tenía: se cierran con el estado aparte del eco pendiente.
func TestEcoPartidoHuecosDeLaV065(t *testing.T) {
	const v = "Pa55w0rd#Xq7z9"
	casos := map[string]func(r sesionRec){
		"3a línea vieja con el mismo comienzo": func(r sesionRec) {
			r.Output([]byte("R1(config)#"))
			r.Input([]byte("enable secret Old#Value1\r"))
			r.Output([]byte("enable secret Old" + syslogPost + "#Value1\r\n% Invalid input detected at '^' marker.\r\nR1(config)#"))
			r.Input([]byte("enable secret " + v + "\r"))
			r.Output([]byte("enable secret " + syslogPost + v + "\r\nR1(config)#"))
			r.Close()
		},
		"3b partido dos veces": func(r sesionRec) {
			r.Output([]byte("R1(config)#"))
			r.Input([]byte("enable secret " + v + "\r"))
			r.Output([]byte("enable secr" + syslogPost + "et Pa55" + syslogPost + "w0rd#Xq7z9\r\nR1(config)#"))
			r.Close()
		},
		"3c eco desplazado y partido": func(r sesionRec) {
			r.Output([]byte("R1(config)#"))
			r.Input([]byte("enable secret " + v + "\r"))
			r.Output([]byte("$ble secret Pa55" + syslogPost + "w0rd#Xq7z9\r\nR1(config)#"))
			r.Close()
		},
	}
	for nom, f := range casos {
		out := grabar(nuevo, f)
		for g, c := range visibles4(out, v) {
			if c > 0 {
				t.Errorf("%s: %q visible:\n%s", nom, g, out)
				break
			}
		}
	}
}
