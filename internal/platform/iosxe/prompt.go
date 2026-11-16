package iosxe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/platform"
)

// errBadPrompt: la línea no tiene la forma de un prompt de ASA.
var errBadPrompt = errors.New("iosxe: no es un prompt de ASA")

// Cada segmento del prompt es una palabra sin espacios: el ejemplo de Cisco «data node» (con espacio) no se acepta.
var (
	segRe     = regexp.MustCompile(`^[\w.\-@:]+$`)
	unitRe    = regexp.MustCompile(`^unit-\d+-\d+$`)
	ctxNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)
	// anyCfgPrompt: prompt de configuración con segmentos (asa/ctx(config)#); en Open es ErrConfigPrompt.
	anyCfgPrompt = regexp.MustCompile(`(?:^|\n)(?:[\w.\-@/:]{1,63}|[\w.\-@:]{1,63}(?:/[\w.\-@:]{1,63}){1,8})\(config[\w\-]*\)# ?$`)
)

// ParsePrompt separa un prompt de ASA en segmentos por «/»: el primero es el hostname; pri/sec, act/stby/actNoFailover/
// stbyNoFailover y control/data/master/slave son el rol, en cualquier orden; un segmento con puntos es el dominio; lo
// demás es la unidad de cluster (unit-N-M, o el último si hay cluster) o el contexto. Una forma (config…)# da
// platform.ErrConfigPrompt. Límite: un contexto llamado act, pri o control es ambiguo y se toma por rol.
func ParsePrompt(s string) (platform.Prompt, error) {
	var p platform.Prompt
	s = strings.TrimSuffix(s, " ")
	if i := strings.IndexByte(s, '('); i >= 0 {
		if cfgPrompt.MatchString(s[i:]) && segRe.MatchString(strings.ReplaceAll(s[:i], "/", "")) && !strings.Contains(s[:i], "//") {
			return p, platform.ErrConfigPrompt
		}
		return p, errBadPrompt
	}
	if len(s) < 2 || (s[len(s)-1] != '#' && s[len(s)-1] != '>') {
		return p, errBadPrompt
	}
	segs := strings.Split(s[:len(s)-1], "/")
	var rest []string
	for i, g := range segs {
		if !segRe.MatchString(g) {
			return p, errBadPrompt
		}
		if i == 0 {
			p.Host = g
			continue
		}
		set := func(dst *string) bool {
			if *dst != "" {
				return false
			}
			*dst = g
			return true
		}
		ok := false
		switch g {
		case "pri", "sec":
			ok = set(&p.Priority)
		case "act", "stby", "actNoFailover", "stbyNoFailover":
			ok = set(&p.State)
		case "control", "data", "master", "slave":
			ok = set(&p.Cluster)
		default:
			if strings.Contains(g, ".") {
				if !set(&p.Domain) {
					return p, errBadPrompt
				}
				ok = true
			}
		}
		if !ok {
			rest = append(rest, g)
		}
	}
	switch {
	case len(rest) == 0:
	case p.Cluster == "" && len(rest) == 1:
		p.Context = rest[0]
	case p.Cluster == "" || len(rest) > 2:
		return p, errBadPrompt
	case len(rest) == 1 && unitRe.MatchString(rest[0]):
		p.Unit = rest[0]
	case len(rest) == 1:
		p.Unit = rest[0] // con cluster y un solo segmento sin forma de unidad, es la unidad (el sistema)
	default:
		p.Context, p.Unit = rest[0], rest[1]
		if unitRe.MatchString(rest[0]) && !unitRe.MatchString(rest[1]) {
			p.Context, p.Unit = rest[1], rest[0]
		}
	}
	return p, nil
}

// stableName es el nombre que identifica la sesión mientras el rol cambia: host o host/contexto.
func stableName(p platform.Prompt) string {
	if p.Context != "" {
		return p.Host + "/" + p.Context
	}
	return p.Host
}

// lastLine es la última línea sin el espacio final.
func lastLine(s string) string {
	return strings.TrimSuffix(s[strings.LastIndexByte(s, '\n')+1:], " ")
}

// sameSession: mismo hostname, contexto, dominio y unidad; el rol puede ser otro (failover).
func sameSession(a, b platform.Prompt) bool {
	return a.Host == b.Host && a.Context == b.Context && a.Domain == b.Domain && a.Unit == b.Unit
}

// Prompt es el último prompt de ASA visto; vacío antes de Detect o en otras plataformas.
func (d *driver) Prompt() platform.Prompt { return d.pr }

// enterASA pasa a comparar el prompt por segmentos (estables) en lugar de exacto. Se llama desde Detect.
func (d *driver) enterASA() {
	p, err := ParsePrompt(d.hostname + "#")
	if err != nil {
		return // un nombre raro: se sigue con la comparación exacta
	}
	d.asa, d.pr, d.hostname = true, p, stableName(p)
}

// atASAPrompt acepta cualquier rol: compara solo la parte estable y anota el rol visto.
func (d *driver) atASAPrompt(last string) bool {
	p, err := ParsePrompt(last)
	if err != nil || !sameSession(p, d.pr) {
		return false
	}
	d.pr = p
	return true
}

// ChangeTo implementa platform.ContextSwitcher. El nombre se valida aquí también: el comando se arma solo con
// "system" o un nombre de contexto válido, nunca con texto libre.
func (d *driver) ChangeTo(ctx context.Context, target string, timeout time.Duration) error {
	if d.err != nil {
		return d.err
	}
	if !d.asa {
		return platform.ErrChangetoUnsupported
	}
	cmd, want := "changeto system", ""
	if target != "system" {
		// un contexto con nombre de rol («act», «control»…) se leería como el rol en el prompt: no se manda
		if !ctxNameRe.MatchString(target) || roleWord(target) {
			return i18n.New("platform.err.changeto_name", i18n.A("name", target))
		}
		cmd, want = "changeto context "+target, target
	}
	ctx, cancel := context.WithTimeout(ctx, maxRun)
	defer cancel()
	if _, err := io.WriteString(d.w, cmd+"\n"); err != nil {
		return d.fail(fmt.Errorf("%w: %v", platform.ErrClosed, err))
	}
	text, err := d.untilIdle(ctx, timeout, func(s string) bool {
		_, err := ParsePrompt(lastLine(s))
		return err == nil || errors.Is(err, platform.ErrConfigPrompt)
	})
	if err != nil {
		return d.fail(err)
	}
	lines := strings.Split(strings.TrimRight(text, "\n "), "\n")
	got, perr := ParsePrompt(lastLine(text))
	// Lo único que cabe entre el eco y el prompt es un syslog intercalado: cualquier otra cosa es un error del equipo.
	clean := perr == nil
	for _, l := range lines[:len(lines)-1] {
		if l = strings.TrimSpace(l); l != "" && l != cmd && !syslogLine.MatchString(l) {
			clean = false
		}
	}
	if !clean || got.Host != d.pr.Host || got.Context != want || got.Domain != d.pr.Domain || got.Unit != d.pr.Unit {
		return d.fail(i18n.New("platform.err.changeto_prompt", i18n.A("got", lastLine(text), "want", want)))
	}
	d.pr, d.hostname = got, stableName(got)
	return nil
}

// roleWord: un segmento del prompt que es rol de failover o de cluster, no un contexto.
func roleWord(g string) bool {
	switch g {
	case "pri", "sec", "act", "stby", "actNoFailover", "stbyNoFailover", "control", "data", "master", "slave":
		return true
	}
	return false
}
