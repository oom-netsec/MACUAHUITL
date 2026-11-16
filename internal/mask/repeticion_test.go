package mask_test

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// Regresión de la terminal: la línea de salida que repite lo tecleado pasa por la red por contenido (M₁) sobre S1, y
// solo después por el corte (M₂). Si el corte va antes, parte la frase secreta y deja tokens que la v0.6.5 tapaba.
// Criterio diferencial: todo token del valor visible en la salida nueva se ve también en la v0.6.5.

var (
	rpPalabras = []string{"Alpha", "Gamma", "beta", "Tango", "Delta", "Echo", "Foxtrot", "Kilo"}
	rpClaves   = []string{"key", "password", "secret", "community", "text", "pass", "sec", "comm", "tex", "pre-shared-key", "k", "auth"}
)

// rpValor: n palabras, con palabras clave mezcladas adentro (nunca solo la primera, para que el valor sea una frase).
func rpValor(r *rand.Rand, n, id int) []string {
	var v []string
	for i := 0; i < n; i++ {
		if i > 0 && r.Intn(2) == 0 {
			v = append(v, rpClaves[r.Intn(len(rpClaves))])
		} else {
			v = append(v, fmt.Sprintf("%s%d", rpPalabras[r.Intn(len(rpPalabras))], id*10+i))
		}
	}
	return v
}

type rpForma struct{ prompt, fmt string }

var rpFormas = []rpForma{
	{"R1(config)#", "username U password 0 %s"},
	{"R1(config)#", "enable secret 0 %s"},
	{"R1(config)#", "snmp-server community %s RO"},
	{"R1(config-keychain-key)#", "key-string 0 %s"},
	{"R1(config)#", "username U secret 0 %s"},
}

var rpRepite = []string{`Note RPT "%s"`, `%% RPT "%s" is invalid`, `*Nov 15 10:00:00: %%SYS-5-CONFIG_I: RPT "%s"`}

// rpVisibles: tokens del valor que se ven en las líneas RPT de la grabación (sin contar los marcadores).
func rpVisibles(out string, val []string) map[string]bool {
	vis := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		if !strings.Contains(l, "RPT") {
			continue
		}
		l = markerOK.ReplaceAllString(l, " ")
		for _, w := range strings.Fields(strings.NewReplacer(`"`, " ").Replace(l)) {
			for _, t := range val {
				if w == t {
					vis[t] = true
				}
			}
		}
	}
	return vis
}

func TestRepeticionDeFraseSecretaEnLaTerminal(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	casos, hallados := 0, 0
	rondas := 60
	if raceOn { // ver raceOn
		rondas = 10
	}
	for id := 1; id <= rondas; id++ {
		for _, f := range rpFormas {
			for _, n := range []int{1, 2, 4} {
				val := rpValor(r, n, id)
				cmd := fmt.Sprintf(f.fmt, strings.Join(val, " "))
				for _, rep := range rpRepite {
					evs := guion(f.prompt, []string{cmd}, false, false, false)
					evs = append(evs[:len(evs)-1:len(evs)-1], ev{false, cmd + "\r\n" + fmt.Sprintf(rep, strings.Join(val, " ")) + "\r\n" + f.prompt})
					seed := int64(id*100 + n)
					nv, vj := sesion(nuevo, evs, seed), sesion(viejo, evs, seed)
					ref, got := rpVisibles(vj, val), rpVisibles(nv, val)
					casos++
					for tk := range got {
						if !ref[tk] {
							if hallados++; hallados <= 20 {
								t.Errorf("token %q visible solo en la nueva\n  cmd: %q  repite: %q\n  nueva:  %q\n  v0.6.5: %q", tk, cmd, rep, nv, vj)
							}
						}
					}
				}
			}
		}
	}
	if hallados > 20 {
		t.Errorf("%d tokens visibles de más en total (de %d casos)", hallados, casos)
	}
}

// El caso de la revisión, exacto.
func TestRepeticionCasosDeLaRevision(t *testing.T) {
	for _, c := range []struct{ cmd, rep string }{
		{"username U password 0 Alpha Gamma key beta", `Note "Alpha Gamma key beta"`},
		{"enable secret 0 Tango Delta pass Echo", `Note "Tango Delta pass Echo"`},
	} {
		evs := []ev{{false, "R1(config)#"}, {true, c.cmd + "\r"}, {false, c.cmd + "\r\n" + c.rep + "\r\nR1(config)#"}}
		n, o := sesion(nuevo, evs, 1), sesion(viejo, evs, 1)
		if !strings.Contains(n, `Note "<MASKED:secret>"`) || !strings.Contains(o, `Note "<MASKED:secret>"`) {
			t.Errorf("%q\n  nueva:  %q\n  v0.6.5: %q", c.cmd, n, o)
		}
	}
}
